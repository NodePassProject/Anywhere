//
//  MITMSession.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMSession")

nonisolated struct MITMDialResult {
    let connection: ProxyConnection
    let proxyClient: ProxyClient?
}

nonisolated protocol MITMSessionHost: AnyObject, Sendable {
    func mitmDialUpstream(host: String, port: UInt16) async throws -> MITMDialResult
    func mitmSessionSendToClient(_ data: Data)
    func mitmSessionWriteToClient(_ data: Data) async throws
    func mitmSessionDidTearDown(error: Error?)
    func mitmSessionDidConsumeClientBytes(_ count: Int)
}

actor MITMSession: MITMHTTP1StreamDelegate {

    nonisolated var unownedExecutor: UnownedSerialExecutor {
        sessionContext.executor.asUnownedSerialExecutor()
    }

    // MARK: - Inner Transport

    final class InnerTransport: ByteTransport, Sendable {
        private let inbox = AsyncInbox<Data>()
        private enum Phase: PhaseTransitionable {
            case open, closed

            static func canTransition(from old: Phase, to new: Phase) -> Bool {
                switch (old, new) {
                case (.open, .closed):
                    return true
                default:
                    return false
                }
            }
        }
        private struct State: PhaseHolding {
            var phase: Phase = .open
            weak var host: MITMSessionHost?
            var unconsumedBytes = 0
        }
        private let state = Mutex(State())

        var isReady: Bool { state.withLock { $0.phase == .open } }

        func setHost(_ host: MITMSessionHost?) {
            state.withLock { $0.host = host }
        }

        // MARK: ByteTransport

        func send(_ data: Data) async throws {
            guard !state.withLock({ $0.phase == .closed }) else { throw AnywhereError.transport(.notConnected) }
            guard let host = state.withLock({ $0.phase == .closed ? nil : $0.host }) else {
                throw AnywhereError.transport(.terminated)
            }
            try await host.mitmSessionWriteToClient(data)
        }

        func receive() async throws -> TransportChunk {
            guard let batch = try await inbox.nextBatch(), let first = batch.first else { return .end }
            var next = first
            if batch.count > 1 {
                next = Data(capacity: batch.reduce(0) { $0 + $1.count })
                for chunk in batch { next.append(chunk) }
            }
            let received = next.count
            acknowledge(
                state.withLock { state -> Int in
                    let consumed = min(received, state.unconsumedBytes)
                    state.unconsumedBytes -= consumed
                    return consumed
                }
            )
            return .bytes(next)
        }

        func cancel() {
            let unconsumed = state.withLock { state -> Int in
                state.transition(to: .closed)
                let rest = state.unconsumedBytes
                state.unconsumedBytes = 0
                return rest
            }
            inbox.finish()
            acknowledge(unconsumed)
        }

        // MARK: External Inputs

        func feedFromClient(_ data: Data) {
            let accepted = state.withLock { state -> Bool in
                guard state.phase != .closed else { return false }
                state.unconsumedBytes += data.count
                return true
            }
            guard accepted else {
                acknowledge(data.count)
                return
            }
            inbox.yield(data)
        }

        private func acknowledge(_ count: Int) {
            guard count > 0, let host = state.withLock({ $0.host }) else { return }
            host.mitmSessionDidConsumeClientBytes(count)
        }
    }

    // MARK: - Properties

    private let dstHost: String
    private let dstPort: UInt16

    private let sessionContext: SessionExecutionContext

    private let isPlaintext: Bool

    private let leafCache: MITMLeafCertificateCache?
    private let upstreamALPNCache: MITMUpstreamALPNCache
    private let policy: MITMRewritePolicy

    private var proxyClient: ProxyClient?

    private var outerConnection: ProxyConnection?

    private var pendingUpstreamBytes = Data()

    private var isDialing = false

    private var isInboundReadPaused = false

    private var dialedHost: String?
    private var dialedPort: UInt16?

    private var clientSupportsTLS13 = false

    private var pendingClientBytes: Data

    private static let maxPendingClientBytes: Int = 256 * 1024

    private static let maxPendingUpstreamBytes: Int = 8 * 1024 * 1024

    private var tlsServer: TLSServer?
    private var tlsClient: TLSClient?

    private let innerTransport: InnerTransport

    private var innerRecord: (any MITMByteLeg)?
    private var outerRecord: (any MITMByteLeg)?

    private let requestStream: MITMHTTP1Stream
    private let responseStream: MITMHTTP1Stream

    // MARK: - Decoupled HTTP/2 client leg

    private var bridgeClient: MITMBridgeClientLeg?

    private var h2Upstream: MITMHTTP2UpstreamLeg?

    private enum UpstreamProtocol { case undetermined, h2, h1 }
    private var upstreamProtocol: UpstreamProtocol = .undetermined
    private var firstUpstreamDialStarted = false

    private var firstUpstreamDialTarget: UpstreamKey?

    private var boundH2Target: UpstreamKey?

    private struct UpstreamKey: Equatable {
        let host: String
        let port: UInt16
        init(host: String, port: UInt16) {
            self.host = host.lowercased()
            self.port = port
        }
    }

    private struct DeadUpstream {
        let key: UpstreamKey
        let expiresAt: TimeInterval
    }

    private var deadUpstreams: [DeadUpstream] = []
    private static let maxDeadUpstreams = 64
    private static let deadUpstreamTTL: TimeInterval = 5

    private enum PendingRequestEvent {
        case head(MITMRequestHead, url: String?, endStream: Bool)
        case data(streamID: UInt32, Data, endStream: Bool)
        case trailers(streamID: UInt32, [(name: String, value: String)])
        case abort(streamID: UInt32)
    }
    private var pendingRequestEvents: [PendingRequestEvent] = []
    private var pendingRequestBytes = 0
    private static let maxPendingRequestBytes = 8 * 1024 * 1024

    private var pendingRequestStreamIDs: Set<UInt32> = []

    private func clearPendingRequests() {
        pendingRequestEvents.removeAll()
        pendingRequestStreamIDs.removeAll()
        pendingRequestBytes = 0
    }

    private final class BridgeStream {
        let clientStreamID: UInt32
        var proxyClient: ProxyClient?
        var connection: ProxyConnection?
        var tlsClient: TLSClient?
        var upstreamRecord: TLSRecordConnection?
        let responseStream: MITMHTTP1Stream
        var responseIRSink: MITMHTTP1ResponseIRSink?
        let responseLog: MITMRequestLog
        var framing: MITMBridgeBodyFraming = .none
        var pendingToUpstream = Data()
        var unsentUpstreamBytes = 0
        var handshakeDone = false
        var dialTarget: UpstreamKey?

        init(clientStreamID: UInt32, responseStream: MITMHTTP1Stream, responseLog: MITMRequestLog) {
            self.clientStreamID = clientStreamID
            self.responseStream = responseStream
            self.responseLog = responseLog
        }
    }

    private final class BridgeResponseIRSink: MITMHTTP1ResponseIRSink {
        let streamID: UInt32
        private struct WeakClient: Sendable { weak var value: MITMBridgeClientLeg? }
        private let clientBox: WeakClient
        private var client: MITMBridgeClientLeg? { clientBox.value }
        let onReset: @Sendable (UInt32) -> Void
        init(streamID: UInt32, client: MITMBridgeClientLeg?, onReset: @escaping @Sendable (UInt32) -> Void) {
            self.streamID = streamID
            self.clientBox = WeakClient(value: client)
            self.onReset = onReset
        }
        func http1ResponseHead(status: Int, headers: [(name: String, value: String)], endStream: Bool) {
            client?.deliverResponseHead(streamID: streamID, status: status, headers: headers, endStream: endStream)
        }
        func http1ResponseInterim(status: Int, headers: [(name: String, value: String)]) {
            client?.deliverResponseInterim(streamID: streamID, status: status, headers: headers)
        }
        func http1ResponseBody(_ data: Data, endStream: Bool) {
            client?.deliverResponseData(streamID: streamID, data, endStream: endStream)
        }
        func http1ResponseReset() {
            onReset(streamID)
        }
    }

    private var bridgeStreams: [UInt32: BridgeStream] = [:]
    private var sessionUnsentUpstreamBytes = 0
    private static let maxConcurrentBridgeStreams = 128
    private static let maxBridgeUpstreamBufferedBytes = 8 * 1024 * 1024
    private static let maxSessionUpstreamBufferedBytes = 16 * 1024 * 1024

    private var sharedUpstreamRecord: TLSRecordConnection?
    private var sharedUpstreamConnection: ProxyConnection?
    private var sharedUpstreamProxyClient: ProxyClient?
    private var sharedUpstreamTLSClient: TLSClient?

    private var inbound: any MITMMessageRewriter { requestStream }
    private var outbound: any MITMMessageRewriter { responseStream }

    private let h2Rewriter: MITMHTTP2Rewriter

    private let h2FlowController = MITMHTTP2FlowController()

    private let requestLog = MITMRequestLog()

    private enum Phase: PhaseTransitionable {
        case live
        case draining
        case torn

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.live, .draining),
                 (.live, .torn),
                 (.draining, .torn):
                return true
            default:
                return false
            }
        }
    }
    private var phase: Phase = .live

    @discardableResult
    private func transition(to new: Phase) -> Bool {
        Phase.transition(&phase, to: new)
    }

    // MARK: - Task tree

    private enum SessionJob: Sendable {
        case mintLeaf(sni: String, alpns: [String], tlsVersions: Set<UInt16>)
        case inboundPump(inner: any MITMByteLeg)
        case outboundPump(inner: any MITMByteLeg, outer: any MITMByteLeg)
        case bridgeInboundPump(inner: TLSRecordConnection)
        case h2UpstreamPump(record: TLSRecordConnection)
        case bridgeUpstreamPump(streamID: UInt32)
        case deferredDial(host: String, port: UInt16, innerALPN: String)
        case outerHandshake(connection: ProxyConnection, host: String, innerALPN: String)
        case firstUpstreamDial
        case firstUpstreamHandshake(host: String, connection: ProxyConnection)
        case bridgeStreamDial(streamID: UInt32, host: String, port: UInt16)
        case bridgeStreamHandshake(streamID: UInt32, host: String)
        case upstreamHandshakeTimeout(gate: OneShotLatch, disarm: AsyncInbox<Void>, onTimeout: @Sendable () -> Void)
    }

    private let sessionJobs: AsyncStream<SessionJob>
    private nonisolated let sessionJobContinuation: AsyncStream<SessionJob>.Continuation

    private func spawn(_ job: SessionJob) {
        sessionJobContinuation.yield(job)
    }

    private var rootTask: Task<Void, Never>?

    // MARK: - Deferred actions

    private enum DeferredAction {
        case cancel(reason: Error?)
        case failInnerLegWith502(error: Error?)
        case failPendingBridgeRequests(reason: Error)
        case abortBridgeStream(streamID: UInt32, acceptResponseAborted: Bool)
        case bridgeUpstreamDrained(streamID: UInt32, count: Int, sendError: Error?)
        case failBridgeStreamOnTimeout(streamID: UInt32)
    }
    private let deferredActions: AsyncStream<DeferredAction>
    private nonisolated let deferredActionContinuation: AsyncStream<DeferredAction>.Continuation

    private nonisolated func post(_ action: DeferredAction) {
        deferredActionContinuation.yield(action)
    }

    private func apply(_ action: DeferredAction) {
        switch action {
        case .cancel(let reason):
            cancel(error: reason)
        case .failInnerLegWith502(let error):
            failInnerLegWith502(error)
        case .failPendingBridgeRequests(let reason):
            failPendingBridgeRequests(error: reason)
        case .abortBridgeStream(let streamID, let acceptResponseAborted):
            abortBridgeStream(streamID, acceptResponseAborted: acceptResponseAborted)
        case .bridgeUpstreamDrained(let streamID, let count, let sendError):
            noteBridgeUpstreamDrained(streamID: streamID, count: count, sendError: sendError)
        case .failBridgeStreamOnTimeout(let streamID):
            failBridgeStreamOnTimeout(streamID)
        }
    }

    weak var host: MITMSessionHost? {
        didSet { innerTransport.setHost(host) }
    }

    // MARK: - Init

    init(
        dstHost: String,
        dstPort: UInt16,
        clientHello: Data,
        leafCache: MITMLeafCertificateCache?,
        upstreamALPNCache: MITMUpstreamALPNCache,
        policy: MITMRewritePolicy,
        sessionContext: SessionExecutionContext,
        isPlaintext: Bool = false
    ) {
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.pendingClientBytes = clientHello
        self.leafCache = leafCache
        self.upstreamALPNCache = upstreamALPNCache
        self.policy = policy
        self.sessionContext = sessionContext
        self.isPlaintext = isPlaintext
        self.innerTransport = InnerTransport()
        (self.deferredActions, self.deferredActionContinuation) = AsyncStream.makeStream(of: DeferredAction.self)
        (self.sessionJobs, self.sessionJobContinuation) = AsyncStream.makeStream(of: SessionJob.self)
        let scheme = isPlaintext ? "http" : "https"
        self.requestStream = MITMHTTP1Stream(
            host: dstHost,
            scheme: scheme,
            direction: .httpRequest,
            policy: policy,
            effectiveAuthority: nil,
            requestLog: requestLog,
            sessionContext: sessionContext
        )
        self.responseStream = MITMHTTP1Stream(
            host: dstHost,
            scheme: scheme,
            direction: .httpResponse,
            policy: policy,
            effectiveAuthority: nil,
            requestLog: requestLog,
            sessionContext: sessionContext
        )
        self.h2Rewriter = MITMHTTP2Rewriter(
            host: dstHost,
            policy: policy,
            effectiveAuthority: nil,
            requestLog: requestLog
        )
    }

    // MARK: - Lifecycle

    func start(sni: String) {
        rootTask = Task { await self.run() }
        installStreamHandlers()
        guard !isPlaintext else {
            startPlaintext()
            return
        }
        let parsed = parseClientHello(pendingClientBytes)
        let clientALPNs = parsed?.alpnProtocols ?? []
        clientSupportsTLS13 = parsed?.supportedVersions.contains(0x0304) ?? false
        startInnerHandshakeFromClientOffer(
            sni: sni,
            clientALPNs: clientALPNs,
            clientSupportsTLS13: clientSupportsTLS13
        )
    }

    private func installStreamHandlers() {
        requestStream.assumeIsolated { $0.delegate = self }
        responseStream.assumeIsolated { $0.delegate = self }
    }

    // MARK: - Task tree driver

    private func run() async {
        await withDiscardingTaskGroup { group in
            group.addTask { [deferredActions] in
                for await action in deferredActions {
                    await self.apply(action)
                }
            }
            for await job in sessionJobs {
                group.addTask { await self.runJob(job) }
            }
            group.cancelAll()
        }
    }

    private func runJob(_ job: SessionJob) async {
        switch job {
        case .mintLeaf(let sni, let alpns, let tlsVersions):
            await runLeafMint(sni: sni, alpns: alpns, tlsVersions: tlsVersions)
        case .inboundPump(let inner):
            await runInboundPump(inner: inner)
        case .outboundPump(let inner, let outer):
            await runOutboundPump(inner: inner, outer: outer)
        case .bridgeInboundPump(let inner):
            await runBridgeInboundPump(inner: inner)
        case .h2UpstreamPump(let record):
            await runH2UpstreamPump(record: record)
        case .bridgeUpstreamPump(let streamID):
            await runBridgeUpstreamPump(streamID: streamID)
        case .deferredDial(let host, let port, let innerALPN):
            await runDeferredDial(host: host, port: port, innerALPN: innerALPN)
        case .outerHandshake(let connection, let host, let innerALPN):
            await runOuterHandshake(over: connection, host: host, innerALPN: innerALPN)
        case .firstUpstreamDial:
            await runFirstUpstreamDial()
        case .firstUpstreamHandshake(let host, let connection):
            await runFirstUpstreamHandshake(host: host, connection: connection)
        case .bridgeStreamDial(let streamID, let host, let port):
            await runBridgeStreamDial(streamID: streamID, host: host, port: port)
        case .bridgeStreamHandshake(let streamID, let host):
            await runBridgeStreamHandshake(streamID: streamID, host: host)
        case .upstreamHandshakeTimeout(let gate, let disarm, let onTimeout):
            await runUpstreamHandshakeTimeout(gate: gate, disarm: disarm, onTimeout: onTimeout)
        }
    }

    private func startPlaintext() {
        let inner = PlaintextLeg(transport: innerTransport)
        if !pendingClientBytes.isEmpty {
            inner.prependToReceiveBuffer(pendingClientBytes)
            pendingClientBytes.removeAll(keepingCapacity: false)
        }
        innerRecord = inner
        spawn(.inboundPump(inner: inner))
    }

    func feedClientBytes(_ data: Data) {
        guard phase != .torn else {
            host?.mitmSessionDidConsumeClientBytes(data.count)
            return
        }
        if innerRecord != nil {
            innerTransport.feedFromClient(data)
            return
        }
        host?.mitmSessionDidConsumeClientBytes(data.count)
        if let tlsServer {
            tlsServer.feed(data)
        } else {
            if pendingClientBytes.count + data.count > Self.maxPendingClientBytes {
                logger.warning("[MITM] \(dstHost): Pre-handshake buffer full")
                cancel(error: nil)
                return
            }
            pendingClientBytes.append(data)
        }
    }

    func cancel(error: Error? = nil) {
        guard phase != .torn else { return }
        bridgeClient?.assumeIsolated { $0.sendGoAwayToClient(code: MITMHTTP2FrameCodec.ErrorCode.internalError) }
        transition(to: .torn)
        requestStream.assumeIsolated { $0.markTorn() }
        responseStream.assumeIsolated { $0.markTorn() }
        bridgeClient?.assumeIsolated { $0.markTorn() }
        bridgeClient = nil
        h2Upstream?.assumeIsolated { $0.markTorn() }
        h2Upstream = nil
        for bridgeStream in bridgeStreams.values {
            bridgeStream.tlsClient?.cancel()
            bridgeStream.connection?.cancel()
            bridgeStream.proxyClient?.cancel()
            bridgeStream.upstreamRecord?.cancel()
            bridgeStream.responseStream.assumeIsolated { $0.markTorn() }
        }
        bridgeStreams.removeAll()
        sessionUnsentUpstreamBytes = 0
        sharedUpstreamRecord?.cancel()
        sharedUpstreamRecord = nil
        sharedUpstreamConnection?.cancel()
        sharedUpstreamConnection = nil
        sharedUpstreamProxyClient?.cancel()
        sharedUpstreamProxyClient = nil
        sharedUpstreamTLSClient?.cancel()
        sharedUpstreamTLSClient = nil
        clearPendingRequests()
        tlsServer = nil
        tlsClient?.cancel()
        tlsClient = nil
        let inner = innerRecord
        let innerWriter = inner.flatMap { legWriters.removeValue(forKey: ObjectIdentifier($0)) }
        innerRecord = nil
        outerRecord?.cancel()
        outerRecord = nil
        outerConnection?.cancel()
        outerConnection = nil
        proxyClient?.cancel()
        proxyClient = nil
        pendingUpstreamBytes = Data()
        for writer in legWriters.values { writer.assumeIsolated { $0.abort() } }
        legWriters.removeAll()
        for abort in legAborts.values { abort.continuation.finish() }
        legAborts.removeAll()
        let host = self.host
        let transport = innerTransport
        if let inner, let innerWriter, error == nil {
            innerWriter.assumeIsolated {
                $0.close(gracePeriod: .milliseconds(500)) { [weak host] in
                    inner.cancel()
                    transport.cancel()
                    host?.mitmSessionDidTearDown(error: nil)
                }
            }
        } else {
            innerWriter?.assumeIsolated { $0.abort() }
            inner?.cancel()
            transport.cancel()
            host?.mitmSessionDidTearDown(error: error)
        }
        sessionJobContinuation.finish()
        deferredActionContinuation.finish()
        rootTask?.cancel()
        rootTask = nil
    }

    // MARK: - Inner Handshake

    private func startInnerHandshake(sni: String, alpns: [String], tlsVersions: Set<UInt16>) {
        guard leafCache != nil else {
            cancel(error: nil)
            return
        }
        spawn(.mintLeaf(sni: sni, alpns: alpns, tlsVersions: tlsVersions))
    }

    private func runLeafMint(sni: String, alpns: [String], tlsVersions: Set<UInt16>) async {
        guard let leafCache else {
            cancel(error: nil)
            return
        }
        do {
            let leaf = try await leafCache.leaf(for: sni)
            guard phase != .torn else { return }
            beginInnerHandshake(with: leaf, alpns: alpns, tlsVersions: tlsVersions)
        } catch {
            guard phase != .torn else { return }
            cancel(error: error)
        }
    }

    private func beginInnerHandshake(with leaf: MITMLeafCertificateCache.Leaf, alpns: [String], tlsVersions: Set<UInt16>) {
        let server = TLSServer(
            leafCertDER: leaf.certificateDER,
            leafSigningKeyP256: leaf.privateKey,
            acceptableALPNs: alpns,
            acceptableTLSVersions: tlsVersions
        )
        server.delegate = self
        tlsServer = server

        server.feed(pendingClientBytes)
        pendingClientBytes.removeAll(keepingCapacity: false)
    }

    private func startInnerHandshakeFromClientOffer(
        sni: String,
        clientALPNs: [String],
        clientSupportsTLS13: Bool
    ) {
        let supported: Set<String> = ["h2", "http/1.1"]
        var intersected = clientALPNs.filter { supported.contains($0) }
        if intersected.contains("h2"), intersected.contains("http/1.1"),
           upstreamALPNCache.lacksHTTP2(host: dstHost, port: dstPort) {
            intersected.removeAll { $0 == "h2" }
        }
        let alpns: [String] = intersected.isEmpty ? ["http/1.1"] : intersected
        var tlsVersions: Set<UInt16> = [0x0303]
        if clientSupportsTLS13 { tlsVersions.insert(0x0304) }
        startInnerHandshake(sni: sni, alpns: alpns, tlsVersions: tlsVersions)
    }

    // MARK: - Outer Handshake

    private func startCleartextUpstream(over connection: ProxyConnection) {
        guard phase != .torn, let inner = innerRecord else {
            connection.cancel()
            return
        }
        let outer = PlaintextLeg(transport: TunneledTransport(tunnel: connection))
        outerRecord = outer
        finishDialAndShuttle(inner: inner, outer: outer)
    }

    private func startOuterHandshakeAfterDial(
        over connection: ProxyConnection,
        host: String,
        innerALPN: String
    ) {
        spawn(.outerHandshake(connection: connection, host: host, innerALPN: innerALPN))
    }

    private func runOuterHandshake(over connection: ProxyConnection, host: String, innerALPN: String) async {
        guard phase != .torn else {
            connection.cancel()
            return
        }
        let configuration = TLSConfiguration(
            serverName: host,
            alpn: [innerALPN],
            minVersion: .tls12,
            maxVersion: .tls13,
            fingerprint: .plain
        )
        let client = TLSClient(configuration: configuration)
        tlsClient = client
        let disarm = armUpstreamHandshakeTimeout { [weak self] in
            self?.post(.failInnerLegWith502(error: AnywhereError.mitm(.upstreamHandshakeTimeout)))
        }
        do {
            let record = try await client.connect(overTunnel: connection)
            guard disarm() else {
                record.cancel()
                connection.cancel()
                return
            }
            guard phase != .torn, let inner = innerRecord else {
                record.cancel()
                connection.cancel()
                return
            }
            guard record.negotiatedALPN.isEmpty || record.negotiatedALPN == "http/1.1" else {
                logger.warning("[MITM] \(dstHost): Unexpected upstream ALPN: \(record.negotiatedALPN)")
                cancel(error: nil)
                return
            }
            outerRecord = record
            finishDialAndShuttle(inner: inner, outer: record)
        } catch {
            guard disarm() else {
                connection.cancel()
                return
            }
            guard phase != .torn else { return }
            if Self.isCertificateVerificationFailure(error) {
                logger.report("[MITM] \(dstHost): Upstream connect failed", error: error)
                cancel(error: nil)
            } else {
                failInnerLegWith502(error)
            }
        }
    }

    private static func isCertificateVerificationFailure(_ error: Error) -> Bool {
        if case AnywhereError.tls(.certificateValidationFailed) = error { return true }
        return false
    }

    // MARK: - ClientHello parsing

    private func parseClientHello(_ buffer: Data) -> TLSClientHelloParsed? {
        guard !buffer.isEmpty else { return nil }
        return try? TLSClientHelloParser.parse(buffer)
    }

    // MARK: - Shuttle

    private func finishDialAndShuttle(inner: any MITMByteLeg, outer: any MITMByteLeg) {
        let buffered = pendingUpstreamBytes
        pendingUpstreamBytes = Data()
        if !buffered.isEmpty {
            write(buffered, to: outer)
        }
        spawn(.outboundPump(inner: inner, outer: outer))
        if isInboundReadPaused {
            isInboundReadPaused = false
            spawn(.inboundPump(inner: inner))
        }
    }

    private var legWriters: [ObjectIdentifier: MITMLegWriter] = [:]
    private var replyFloodReported = false

    private func writer(for leg: any MITMByteLeg, failingSession: Bool = true) -> MITMLegWriter {
        let key = ObjectIdentifier(leg)
        if let existing = legWriters[key] { return existing }
        var onFailure: (@Sendable (Error) -> Void)?
        if failingSession {
            onFailure = { [weak self] error in self?.post(.cancel(reason: error)) }
        }
        let writer = MITMLegWriter(leg: leg, sessionContext: sessionContext, onFailure: onFailure)
        legWriters[key] = writer
        return writer
    }

    private func write(_ data: Data, to leg: any MITMByteLeg, isReply: Bool = false) {
        guard phase != .torn else { return }
        guard writer(for: leg).assumeIsolated({ $0.write(data, isReply: isReply) }) else {
            guard !replyFloodReported else { return }
            replyFloodReported = true
            logger.warning("[MITM] \(dstHost): Control reply queue full")
            post(.cancel(reason: nil))
            return
        }
    }

    private func writeWithBackpressure(_ data: Data, to leg: any MITMByteLeg) async throws {
        guard phase != .torn else { throw AnywhereError.transport(.notConnected) }
        try await writer(for: leg).writeWithBackpressure(data)
    }

    private func drainWrites(to leg: any MITMByteLeg) async throws {
        guard phase != .torn else { throw AnywhereError.transport(.notConnected) }
        try await writer(for: leg).drain()
    }

    private func writeThenCancel(_ data: Data, to leg: any MITMByteLeg) {
        guard phase != .torn else { return }
        transition(to: .draining)
        writer(for: leg).assumeIsolated {
            $0.write(data) { [weak self] _ in self?.post(.cancel(reason: nil)) }
        }
    }

    // MARK: - Per-leg retirement

    private var legAborts: [ObjectIdentifier: (token: UInt64, continuation: AsyncStream<Never>.Continuation)] = [:]
    private var nextLegAbortToken: UInt64 = 0

    private func pumpUntilRetired(_ leg: AnyObject, _ body: @escaping @Sendable () async -> Void) async {
        let key = ObjectIdentifier(leg)
        let (signal, continuation) = AsyncStream.makeStream(of: Never.self)
        nextLegAbortToken &+= 1
        let token = nextLegAbortToken
        legAborts.updateValue((token, continuation), forKey: key)?.continuation.finish()
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await body() }
            group.addTask { for await _ in signal {} }
            await group.next()
            group.cancelAll()
        }
        if legAborts[key]?.token == token { legAborts.removeValue(forKey: key) }
    }

    private func retireLeg(_ leg: AnyObject) {
        let key = ObjectIdentifier(leg)
        legWriters.removeValue(forKey: key)?.assumeIsolated { $0.abort() }
        legAborts.removeValue(forKey: key)?.continuation.finish()
    }

    private func runInboundPump(inner: any MITMByteLeg) async {
        while true {
            if phase == .torn { return }
            let data: Data?
            do { data = try await inner.receive() }
            catch {
                guard phase != .torn else { return }
                cancel(error: error)
                return
            }
            guard let data else {
                if let outer = outerRecord { try? await drainWrites(to: outer) }
                guard phase != .torn else { return }
                cancel(error: nil)
                return
            }
            guard !data.isEmpty else { continue }

            let transformed = await inbound.feed(data)
            if phase == .torn { return }

            let injected = inbound.drainPendingClientBytes()
            if !injected.isEmpty {
                write(injected, to: inner)
            }

            if transformed.isEmpty { continue }

            guard let outer = outerRecord else {
                bufferUpstreamAndDial(transformed, inner: inner)
                return
            }

            if resolvedUpstreamMatchesDialed() {
                do {
                    try await writeWithBackpressure(transformed, to: outer)
                } catch {
                    guard phase != .torn else { return }
                    cancel(error: error)
                    return
                }
                continue
            }

            do {
                try await drainWrites(to: outer)
            } catch {
                guard phase != .torn else { return }
                cancel(error: error)
                return
            }
            guard phase != .torn else { return }

            if canReconnectOuterLeg() {
                reconnectOuterLeg(with: transformed, inner: inner)
            } else {
                cancel(error: nil)
            }
            return
        }
    }

    private func bufferUpstreamAndDial(_ transformed: Data, inner: any MITMByteLeg) {
        pendingUpstreamBytes.append(transformed)
        if pendingUpstreamBytes.count > Self.maxPendingUpstreamBytes {
            logger.warning("[MITM] \(dstHost): Pre-dial buffer full")
            cancel(error: nil)
            return
        }
        if isDialing {
            guard resolvedUpstreamMatchesDialed() else {
                cancel(error: nil)
                return
            }
            resumeOrPauseInboundPreDial(inner: inner)
            return
        }
        isDialing = true
        let resolved = inbound.resolvedUpstream
        let host = resolved?.host ?? dstHost
        let port = resolved?.port ?? dstPort
        dialedHost = host
        dialedPort = port
        let negotiatedInnerALPN = innerRecord?.negotiatedALPN ?? ""
        let innerALPN = negotiatedInnerALPN.isEmpty ? "http/1.1" : negotiatedInnerALPN
        guard self.host != nil else {
            failInnerLegWith502(nil)
            return
        }
        spawn(.deferredDial(host: host, port: port, innerALPN: innerALPN))
        resumeOrPauseInboundPreDial(inner: inner)
    }

    private func runDeferredDial(host: String, port: UInt16, innerALPN: String) async {
        guard let sessionHost = self.host else {
            failInnerLegWith502(nil)
            return
        }
        do {
            let dial = try await sessionHost.mitmDialUpstream(host: host, port: port)
            guard phase != .torn else {
                dial.connection.cancel()
                await dial.proxyClient?.cancel()
                return
            }
            proxyClient = dial.proxyClient
            outerConnection = dial.connection
            if isPlaintext {
                startCleartextUpstream(over: dial.connection)
            } else {
                startOuterHandshakeAfterDial(over: dial.connection, host: host, innerALPN: innerALPN)
            }
        } catch {
            guard phase != .torn else { return }
            failInnerLegWith502(error)
        }
    }

    private func resumeOrPauseInboundPreDial(inner: any MITMByteLeg) {
        if pendingUpstreamBytes.count >= Self.maxPendingClientBytes {
            isInboundReadPaused = true
        } else {
            spawn(.inboundPump(inner: inner))
        }
    }

    private func resolvedUpstreamMatchesDialed() -> Bool {
        guard let dialedHost, let dialedPort else { return true }
        let resolved = inbound.resolvedUpstream
        return (resolved?.host ?? dstHost) == dialedHost
            && (resolved?.port ?? dstPort) == dialedPort
    }

    static func canSwapOuterLeg(responseBetweenMessages: Bool, http1InFlightCount: Int) -> Bool {
        responseBetweenMessages && http1InFlightCount == 1
    }

    private func canReconnectOuterLeg() -> Bool {
        Self.canSwapOuterLeg(
            responseBetweenMessages: responseStream.assumeIsolated { $0.isBetweenMessages },
            http1InFlightCount: requestLog.http1InFlightCount
        )
    }

    private func reconnectOuterLeg(with transformed: Data, inner: any MITMByteLeg) {
        let oldOuter = outerRecord
        outerRecord = nil
        if let oldOuter {
            retireLeg(oldOuter)
            oldOuter.cancel()
        }
        tlsClient?.cancel()
        tlsClient = nil
        outerConnection?.cancel()
        outerConnection = nil
        proxyClient?.cancel()
        proxyClient = nil
        isDialing = false
        dialedHost = nil
        dialedPort = nil
        pendingUpstreamBytes = Data()
        isInboundReadPaused = false
        bufferUpstreamAndDial(transformed, inner: inner)
    }

    private func armUpstreamHandshakeTimeout(_ onTimeout: @escaping @Sendable () -> Void) -> () -> Bool {
        let gate = OneShotLatch()
        let disarmPoke = AsyncInbox<Void>(capacity: 1)
        spawn(.upstreamHandshakeTimeout(gate: gate, disarm: disarmPoke, onTimeout: onTimeout))
        return { [gate, disarmPoke] in
            guard gate.claim() else { return false }
            disarmPoke.yield(())
            return true
        }
    }

    private func runUpstreamHandshakeTimeout(
        gate: OneShotLatch,
        disarm: AsyncInbox<Void>,
        onTimeout: @Sendable () -> Void
    ) async {
        let timedOut = await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                do {
                    try await Task.sleep(seconds: TunnelConstants.handshakeTimeout, precision: .relaxed)
                    return true
                } catch {
                    return false
                }
            }
            group.addTask {
                _ = try? await disarm.next()
                return false
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
        guard timedOut, gate.claim() else { return }
        onTimeout()
    }

    private func failInnerLegWith502(_ error: Error?) {
        guard phase != .torn else { return }
        if let error {
            logger.report("[MITM] \(dstHost): Upstream connect failed", error: error)
        }
        guard let inner = innerRecord else {
            cancel(error: nil)
            return
        }
        let body = Data("502 Bad Gateway".utf8)
        var head = "HTTP/1.1 502 Bad Gateway\r\n"
        head += "Content-Type: text/plain; charset=utf-8\r\n"
        head += "Content-Length: \(body.count)\r\n"
        head += "Connection: close\r\n\r\n"
        var response = Data(head.utf8)
        response.append(body)
        writeThenCancel(response, to: inner)
    }

    private func handleResponseUpgrade() {
        guard phase != .torn else { return }
        let buffered = requestStream.assumeIsolated { $0.forcePassthrough() }
        guard !buffered.isEmpty, let outer = outerRecord else { return }
        write(buffered, to: outer)
    }

    // MARK: MITMHTTP1StreamDelegate

    nonisolated func http1StreamDidUpgrade(_ stream: MITMHTTP1Stream) {
        guard stream.bridgeClientStreamID == nil else { return }
        assumeIsolated { $0.handleResponseUpgrade() }
    }

    nonisolated func http1StreamFatalClose(_ stream: MITMHTTP1Stream) {
        if let streamID = stream.bridgeClientStreamID {
            post(.abortBridgeStream(streamID: streamID, acceptResponseAborted: true))
            return
        }
        switch stream.direction {
        case .httpRequest:
            post(.cancel(reason: nil))
        case .httpResponse:
            post(.failInnerLegWith502(error: nil))
        }
    }

    nonisolated func http1StreamHardClose(_ stream: MITMHTTP1Stream) {
        guard stream.bridgeClientStreamID == nil else { return }
        post(.cancel(reason: nil))
    }

    private func runOutboundPump(inner: any MITMByteLeg, outer: any MITMByteLeg) async {
        await pumpUntilRetired(outer) { await self.driveOutboundPump(inner: inner, outer: outer) }
    }

    private func driveOutboundPump(inner: any MITMByteLeg, outer: any MITMByteLeg) async {
        while true {
            let data: Data?
            let error: Error?
            do {
                data = try await outer.receive()
                error = nil
            } catch let caught {
                data = nil
                error = caught
            }
            if outerRecord !== outer {
                return
            }
            if let error {
                cancel(error: error)
                return
            }
            guard let data, !data.isEmpty else {
                let flushed = await responseStream.finish()
                guard phase != .torn else { return }
                writeThenCancel(flushed, to: inner)
                return
            }
            let transformed = await outbound.feed(data)
            if transformed.isEmpty { continue }
            do {
                try await writeWithBackpressure(transformed, to: inner)
            } catch {
                guard phase != .torn else { return }
                cancel(error: error)
                return
            }
        }
    }
}

// MARK: - TLSServerDelegate

extension MITMSession: TLSServerDelegate {
    nonisolated func tlsServer(_ server: TLSServer, didProduceOutput data: Data) {
        assumeIsolated { $0.emitToClient(data) }
    }

    nonisolated func tlsServer(
        _ server: TLSServer,
        didCompleteHandshake record: TLSRecordConnection,
        sni: String,
        alpn: String,
        clientFinishedHandshakeTrailer: Data
    ) {
        assumeIsolated { $0.completeInnerHandshake(record: record, trailer: clientFinishedHandshakeTrailer) }
    }

    private func emitToClient(_ data: Data) {
        host?.mitmSessionSendToClient(data)
    }

    private func completeInnerHandshake(record: TLSRecordConnection, trailer: Data) {
        record.adoptTransport(innerTransport)
        record.prependToReceiveBuffer(trailer)
        innerRecord = record
        tlsServer = nil

        if record.negotiatedALPN == "h2" {
            let client = MITMBridgeClientLeg(
                host: dstHost,
                rewriter: h2Rewriter,
                flowController: h2FlowController,
                sessionContext: sessionContext
            )
            client.assumeIsolated { $0.delegate = self }
            bridgeClient = client
            spawn(.bridgeInboundPump(inner: record))
            return
        }

        spawn(.inboundPump(inner: record))
    }

    nonisolated func tlsServer(_ server: TLSServer, didFail error: AnywhereError) {
        assumeIsolated { $0.cancel(error: error) }
    }
}

// MARK: - h2 → http/1.1 bridge

extension MITMSession: MITMBridgeClientLegDelegate, MITMUpstreamLegDelegate {
    private func runBridgeInboundPump(inner: TLSRecordConnection) async {
        while true {
            let data: Data?
            let error: Error?
            do {
                data = try await inner.receive()
                error = nil
            } catch let caught {
                data = nil
                error = caught
            }
            if phase == .torn { return }
            if let error {
                cancel(error: error)
                return
            }
            guard let data else {
                cancel(error: nil)
                return
            }
            if data.isEmpty { continue }
            guard let client = bridgeClient else { return }
            await client.feed(data)
        }
    }

    nonisolated func clientLegWriteToClient(_ data: Data) {
        assumeIsolated { $0.writeToClient(data) }
    }
    nonisolated func clientLegWriteReplyToClient(_ data: Data) {
        assumeIsolated { $0.writeToClient(data, isReply: true) }
    }
    private func writeToClient(_ data: Data, isReply: Bool = false) {
        guard phase != .torn, !data.isEmpty, let inner = innerRecord else { return }
        write(data, to: inner, isReply: isReply)
    }

    nonisolated func clientLegFatalError(_ message: String) {
        assumeIsolated { $0.handleClientLegFatalError(message) }
    }
    private func handleClientLegFatalError(_ message: String) {
        logger.warning("[MITM] \(dstHost): HTTP/2 client: \(message)")
        cancel(error: nil)
    }

    nonisolated func clientLegResponseDrained(streamID: UInt32, byteCount: Int) {
        assumeIsolated { $0.h2Upstream?.assumeIsolated { $0.creditDrainedResponse(clientID: streamID, byteCount) } }
    }

    // MARK: Request IR routing (client leg → upstream)

    nonisolated func clientLegSendRequestHead(_ head: MITMRequestHead, url: String?, endStream: Bool) {
        assumeIsolated { $0.sendRequestHeadUpstream(head, url: url, endStream: endStream) }
    }
    private func sendRequestHeadUpstream(_ head: MITMRequestHead, url: String?, endStream: Bool) {
        guard phase != .torn else { return }
        switch upstreamProtocol {
        case .h2:
            if failStreamIfOffBoundH2Upstream(head) { return }
            h2Rewriter.requestLog.recordHTTP2(streamID: head.clientStreamID, method: head.method, url: url, originalURL: head.originalURL)
            h2Upstream?.assumeIsolated { $0.sendRequestHead(head, endStream: endStream) }
        case .h1:
            openH1Stream(head, url: url)
        case .undetermined:
            if failStreamIfUpstreamDead(head) { return }
            pendingRequestEvents.append(.head(head, url: url, endStream: endStream))
            pendingRequestStreamIDs.insert(head.clientStreamID)
            startFirstUpstreamDial()
        }
    }

    nonisolated func clientLegSendRequestData(streamID: UInt32, _ data: Data, endStream: Bool) {
        assumeIsolated { $0.sendRequestDataUpstream(streamID: streamID, data, endStream: endStream) }
    }
    private func sendRequestDataUpstream(streamID: UInt32, _ data: Data, endStream: Bool) {
        guard phase != .torn else { return }
        switch upstreamProtocol {
        case .h2:
            h2Upstream?.assumeIsolated { $0.sendRequestData(streamID: streamID, data, endStream: endStream) }
        case .h1:
            appendH1RequestData(streamID: streamID, data, endStream: endStream)
        case .undetermined:
            guard pendingRequestStreamIDs.contains(streamID) else { return }
            guard pendingRequestBytes + data.count <= Self.maxPendingRequestBytes else {
                handleClientLegFatalError(
                    "buffered \(pendingRequestBytes + data.count) B of request body before an upstream was bound"
                )
                return
            }
            pendingRequestBytes += data.count
            pendingRequestEvents.append(.data(streamID: streamID, data, endStream: endStream))
        }
    }

    nonisolated func clientLegSendRequestTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)]) {
        assumeIsolated { $0.sendRequestTrailersUpstream(streamID: streamID, trailers) }
    }
    private func sendRequestTrailersUpstream(streamID: UInt32, _ trailers: [(name: String, value: String)]) {
        guard phase != .torn else { return }
        switch upstreamProtocol {
        case .h2:
            h2Upstream?.assumeIsolated { $0.sendRequestTrailers(streamID: streamID, trailers) }
        case .h1:
            logger.warning("[MITM] \(dstHost): Request trailers dropped")
            appendH1RequestData(streamID: streamID, Data(), endStream: true)
        case .undetermined:
            guard pendingRequestStreamIDs.contains(streamID) else { return }
            pendingRequestEvents.append(.trailers(streamID: streamID, trailers))
        }
    }

    nonisolated func clientLegAbortRequest(streamID: UInt32) {
        assumeIsolated { $0.abortRequestUpstream(streamID: streamID) }
    }
    private func abortRequestUpstream(streamID: UInt32) {
        guard phase != .torn else { return }
        switch upstreamProtocol {
        case .h2: h2Upstream?.assumeIsolated { $0.abortRequest(streamID: streamID) }
        case .h1: bridgeAbortStream(streamID)
        case .undetermined:
            guard pendingRequestStreamIDs.contains(streamID) else { return }
            pendingRequestEvents.append(.abort(streamID: streamID))
        }
    }

    nonisolated func clientLegResponseComplete(streamID: UInt32) {
        assumeIsolated { $0.responseCompleteUpstream(streamID: streamID) }
    }
    private func responseCompleteUpstream(streamID: UInt32) {
        if upstreamProtocol == .h1 { bridgeAbortStream(streamID) }
    }

    // MARK: Pinned upstream failures

    private func upstreamKey(for head: MITMRequestHead) -> UpstreamKey {
        let resolved = head.resolvedUpstream
        return UpstreamKey(host: resolved?.host ?? dstHost, port: resolved?.port ?? dstPort)
    }

    private func markUpstreamDead(_ key: UpstreamKey) {
        pruneExpiredDeadUpstreams()
        guard !deadUpstreams.contains(where: { $0.key == key }) else { return }
        if deadUpstreams.count >= Self.maxDeadUpstreams { deadUpstreams.removeFirst() }
        deadUpstreams.append(DeadUpstream(key: key, expiresAt: MonotonicClock.now + Self.deadUpstreamTTL))
    }

    private func isUpstreamDead(_ key: UpstreamKey) -> Bool {
        pruneExpiredDeadUpstreams()
        return deadUpstreams.contains(where: { $0.key == key })
    }

    private func pruneExpiredDeadUpstreams() {
        guard !deadUpstreams.isEmpty else { return }
        let now = MonotonicClock.now
        deadUpstreams.removeAll { $0.expiresAt <= now }
    }

    private func failStreamIfUpstreamDead(_ head: MITMRequestHead) -> Bool {
        guard isUpstreamDead(upstreamKey(for: head)) else { return false }
        bridgeClient?.assumeIsolated { $0.failStream(streamID: head.clientStreamID, status: 502, message: "Bad Gateway") }
        return true
    }

    // MARK: First dial (protocol probe) + late binding

    private func startFirstUpstreamDial() {
        guard !firstUpstreamDialStarted else { return }
        firstUpstreamDialStarted = true
        spawn(.firstUpstreamDial)
    }

    private func runFirstUpstreamDial() async {
        let firstHead = pendingRequestEvents.lazy.compactMap { event -> MITMRequestHead? in
            if case .head(let head, _, _) = event { return head }
            return nil
        }.first
        let resolved = firstHead?.resolvedUpstream
        let dialHost = resolved?.host ?? dstHost
        let port = resolved?.port ?? dstPort
        guard let host else {
            failPendingBridgeRequests(error: AnywhereError.transport(.notConnected))
            return
        }
        firstUpstreamDialTarget = UpstreamKey(host: dialHost, port: port)
        do {
            let dial = try await host.mitmDialUpstream(host: dialHost, port: port)
            guard phase != .torn else {
                dial.connection.cancel()
                await dial.proxyClient?.cancel()
                return
            }
            sharedUpstreamProxyClient = dial.proxyClient
            sharedUpstreamConnection = dial.connection
            startFirstUpstreamHandshake(host: dialHost, connection: dial.connection)
        } catch {
            guard phase != .torn else { return }
            failPendingBridgeRequests(error: error)
        }
    }

    private func failPendingBridgeRequests(error: Error) {
        guard phase != .torn else { return }
        logger.report("[MITM] \(dstHost): Upstream connect failed", error: error)
        if !AnywhereError.isTermination(error), let target = firstUpstreamDialTarget {
            markUpstreamDead(target)
        }
        firstUpstreamDialTarget = nil
        sharedUpstreamRecord = nil
        sharedUpstreamTLSClient?.cancel()
        sharedUpstreamTLSClient = nil
        sharedUpstreamConnection?.cancel()
        sharedUpstreamConnection = nil
        sharedUpstreamProxyClient?.cancel()
        sharedUpstreamProxyClient = nil
        firstUpstreamDialStarted = false
        let events = pendingRequestEvents
        clearPendingRequests()
        for event in events {
            if case .head(let head, _, _) = event {
                bridgeClient?.assumeIsolated { $0.failStream(streamID: head.clientStreamID, status: 502, message: "Bad Gateway") }
            }
        }
    }

    private func startFirstUpstreamHandshake(host: String, connection: ProxyConnection) {
        spawn(.firstUpstreamHandshake(host: host, connection: connection))
    }

    private func runFirstUpstreamHandshake(host: String, connection: ProxyConnection) async {
        guard phase != .torn else {
            connection.cancel()
            return
        }
        let configuration = TLSConfiguration(
            serverName: host,
            alpn: ["h2", "http/1.1"],
            minVersion: .tls12,
            maxVersion: .tls13,
            fingerprint: .plain
        )
        let client = TLSClient(configuration: configuration)
        sharedUpstreamTLSClient = client
        let disarm = armUpstreamHandshakeTimeout { [weak self] in
            self?.post(.failPendingBridgeRequests(reason: AnywhereError.mitm(.upstreamHandshakeTimeout)))
        }
        do {
            let record = try await client.connect(overTunnel: connection)
            guard disarm() else {
                record.cancel()
                connection.cancel()
                return
            }
            guard phase != .torn else {
                record.cancel()
                connection.cancel()
                return
            }
            sharedUpstreamRecord = record
            let dialTarget = firstUpstreamDialTarget
            firstUpstreamDialTarget = nil
            if let dialTarget {
                upstreamALPNCache.record(negotiatedALPN: record.negotiatedALPN, host: dialTarget.host, port: dialTarget.port)
            }
            if record.negotiatedALPN == "h2" {
                bindH2Upstream(record: record, target: dialTarget)
            } else {
                bindH1Upstream()
            }
        } catch {
            guard disarm() else {
                connection.cancel()
                return
            }
            guard phase != .torn else { return }
            if Self.isCertificateVerificationFailure(error) {
                logger.report("[MITM] \(dstHost): Upstream connect failed", error: error)
                cancel(error: nil)
            } else {
                failPendingBridgeRequests(error: error)
            }
        }
    }

    private func bindH2Upstream(record: TLSRecordConnection, target: UpstreamKey?) {
        upstreamProtocol = .h2
        boundH2Target = target
        let leg = MITMHTTP2UpstreamLeg(host: dstHost, rewriter: h2Rewriter, flowController: h2FlowController, sessionContext: sessionContext)
        h2Upstream = leg
        bridgeClient?.assumeIsolated { $0.isUploadDrainCoupled = true }
        let pending = pendingRequestEvents
        clearPendingRequests()
        var offBound: Set<UInt32> = []
        let events = pending.filter { event in
            switch event {
            case .head(let head, _, _):
                guard failStreamIfOffBoundH2Upstream(head) else { return true }
                offBound.insert(head.clientStreamID)
                return false
            case .data(let streamID, _, _), .trailers(let streamID, _), .abort(let streamID):
                return !offBound.contains(streamID)
            }
        }
        let client = bridgeClient
        let rewriter = h2Rewriter
        leg.assumeIsolated { upstream in
            upstream.sink = client
            upstream.delegate = self
            for event in events {
                switch event {
                case .head(let head, let url, let endStream):
                    rewriter.requestLog.recordHTTP2(streamID: head.clientStreamID, method: head.method, url: url, originalURL: head.originalURL)
                    upstream.sendRequestHead(head, endStream: endStream)
                case .data(let streamID, let data, let endStream):
                    upstream.sendRequestData(streamID: streamID, data, endStream: endStream)
                case .trailers(let streamID, let trailers):
                    upstream.sendRequestTrailers(streamID: streamID, trailers)
                case .abort(let streamID):
                    upstream.abortRequest(streamID: streamID)
                }
            }
        }
        spawn(.h2UpstreamPump(record: record))
    }

    private func failStreamIfOffBoundH2Upstream(_ head: MITMRequestHead) -> Bool {
        guard let bound = boundH2Target else { return false }
        let key = upstreamKey(for: head)
        guard key != bound else { return false }
        logger.warning("[MITM] \(dstHost): Cannot reroute HTTP/2 stream to \(key.host):\(key.port)")
        bridgeClient?.assumeIsolated { $0.failStream(streamID: head.clientStreamID, status: 502, message: "Bad Gateway") }
        return true
    }

    private func runH2UpstreamPump(record: TLSRecordConnection) async {
        while true {
            let data: Data?
            let error: Error?
            do {
                data = try await record.receive()
                error = nil
            } catch let caught {
                data = nil
                error = caught
            }
            guard phase != .torn, let leg = h2Upstream else { return }
            if let error {
                cancel(error: error)
                return
            }
            guard let data, !data.isEmpty else {
                cancel(error: nil)
                return
            }
            await leg.feed(data)
        }
    }

    nonisolated func upstreamLegWriteToOrigin(_ data: Data) {
        assumeIsolated { session in
            guard session.phase != .torn, !data.isEmpty, let record = session.sharedUpstreamRecord else { return }
            session.write(data, to: record)
        }
    }

    nonisolated func upstreamLegWriteReplyToOrigin(_ data: Data) {
        assumeIsolated { session in
            guard session.phase != .torn, !data.isEmpty, let record = session.sharedUpstreamRecord else { return }
            session.write(data, to: record, isReply: true)
        }
    }

    nonisolated func upstreamLegFatalError(_ message: String) {
        post(.cancel(reason: nil))
    }

    nonisolated func upstreamLegDraining() {
        assumeIsolated { session in session.bridgeClient?.assumeIsolated { $0.sendGoAwayToClient(code: MITMHTTP2FrameCodec.ErrorCode.noError) } }
    }

    nonisolated func upstreamLegRequestDrained(clientID: UInt32, count: Int) {
        assumeIsolated { session in session.bridgeClient?.assumeIsolated { $0.creditUploadDrained(clientID, count) } }
    }

    private func bindH1Upstream() {
        upstreamProtocol = .h1
        let events = pendingRequestEvents
        clearPendingRequests()
        for event in events {
            switch event {
            case .head(let head, let url, _):
                openH1Stream(head, url: url)
            case .data(let streamID, let data, let endStream):
                appendH1RequestData(streamID: streamID, data, endStream: endStream)
            case .trailers(let streamID, _):
                appendH1RequestData(streamID: streamID, Data(), endStream: true)
            case .abort(let streamID):
                bridgeAbortStream(streamID)
            }
        }
    }

    // MARK: Per-stream HTTP/1.1 upstream

    private func openH1Stream(_ head: MITMRequestHead, url: String?) {
        let streamID = head.clientStreamID
        if failStreamIfUpstreamDead(head) { return }
        guard bridgeStreams.count < Self.maxConcurrentBridgeStreams else {
            logger.warning("[MITM] \(dstHost): Bridge stream limit reached")
            bridgeClient?.assumeIsolated { $0.rejectStream(streamID, errorCode: MITMHTTP2FrameCodec.ErrorCode.refusedStream) }
            return
        }
        let responseLog = MITMRequestLog()
        responseLog.recordHTTP1(method: head.method, url: url, originalURL: head.originalURL)
        let responseStream = MITMHTTP1Stream(
            host: dstHost, direction: .httpResponse, policy: policy, effectiveAuthority: nil,
            requestLog: responseLog, sessionContext: sessionContext,
            bridgeClientStreamID: streamID
        )
        responseStream.assumeIsolated { $0.delegate = self }
        let bridgeStream = BridgeStream(clientStreamID: streamID, responseStream: responseStream, responseLog: responseLog)
        let irSink = BridgeResponseIRSink(streamID: streamID, client: bridgeClient) { [weak self] abortedStreamID in
            self?.assumeIsolated { session in session.bridgeClient?.assumeIsolated { $0.acceptResponseAborted(streamID: abortedStreamID) } }
            self?.post(.abortBridgeStream(streamID: abortedStreamID, acceptResponseAborted: false))
        }
        responseStream.assumeIsolated { $0.responseIRSink = irSink }
        bridgeStream.responseIRSink = irSink
        bridgeStream.framing = head.framing
        bridgeStream.pendingToUpstream = MITMHTTP1Serializer.requestHead(head, host: dstHost)
        bridgeStream.unsentUpstreamBytes = bridgeStream.pendingToUpstream.count
        sessionUnsentUpstreamBytes += bridgeStream.unsentUpstreamBytes
        bridgeStreams[streamID] = bridgeStream

        if let record = sharedUpstreamRecord {
            sharedUpstreamRecord = nil
            bridgeStream.proxyClient = sharedUpstreamProxyClient
            sharedUpstreamProxyClient = nil
            bridgeStream.connection = sharedUpstreamConnection
            sharedUpstreamConnection = nil
            bridgeStream.tlsClient = sharedUpstreamTLSClient
            sharedUpstreamTLSClient = nil
            bridgeStream.upstreamRecord = record
            bridgeStream.handshakeDone = true
            let pending = bridgeStream.pendingToUpstream
            bridgeStream.pendingToUpstream = Data()
            flushToBridgeUpstream(pending, streamID: streamID, record: record)
            spawn(.bridgeUpstreamPump(streamID: streamID))
            return
        }

        let resolved = head.resolvedUpstream
        let host = resolved?.host ?? dstHost
        let port = resolved?.port ?? dstPort
        guard self.host != nil else {
            bridgeAbortStream(streamID)
            return
        }
        bridgeStream.dialTarget = UpstreamKey(host: host, port: port)
        spawn(.bridgeStreamDial(streamID: streamID, host: host, port: port))
    }

    private func runBridgeStreamDial(streamID: UInt32, host: String, port: UInt16) async {
        guard let sessionHost = self.host else {
            bridgeAbortStream(streamID)
            return
        }
        do {
            let dial = try await sessionHost.mitmDialUpstream(host: host, port: port)
            guard phase != .torn, let bridgeStream = bridgeStreams[streamID] else {
                dial.connection.cancel()
                await dial.proxyClient?.cancel()
                return
            }
            bridgeStream.proxyClient = dial.proxyClient
            bridgeStream.connection = dial.connection
            startBridgeUpstreamHandshake(streamID: streamID, host: host)
        } catch {
            guard phase != .torn else { return }
            logger.report("[MITM] \(dstHost): Upstream connect failed", error: error)
            if !AnywhereError.isTermination(error) {
                markUpstreamDead(UpstreamKey(host: host, port: port))
            }
            bridgeAbortStream(streamID)
            await bridgeClient?.failStream(streamID: streamID, status: 502, message: "Bad Gateway")
        }
    }

    private func appendH1RequestData(streamID: UInt32, _ data: Data, endStream: Bool) {
        guard let bridgeStream = bridgeStreams[streamID] else { return }
        let out: Data
        switch bridgeStream.framing {
        case .chunked:
            var chunked = data.isEmpty ? Data() : MITMHTTP1Serializer.chunk(data)
            if endStream { chunked.append(MITMHTTP1Serializer.chunkTerminator) }
            out = chunked
        case .contentLength:
            out = data
        case .none:
            out = Data()
        }
        guard !out.isEmpty else { return }
        bridgeStream.unsentUpstreamBytes += out.count
        sessionUnsentUpstreamBytes += out.count
        if bridgeStream.unsentUpstreamBytes > Self.maxBridgeUpstreamBufferedBytes {
            logger.warning("[MITM] \(dstHost): Upstream buffer full")
            bridgeClient?.assumeIsolated { $0.acceptResponseAborted(streamID: streamID) }
            bridgeAbortStream(streamID)
            return
        }
        if sessionUnsentUpstreamBytes > Self.maxSessionUpstreamBufferedBytes,
           let victim = bridgeStreams.max(by: { $0.value.unsentUpstreamBytes < $1.value.unsentUpstreamBytes })?.key {
            logger.warning("[MITM] \(dstHost): Upstream buffer full")
            bridgeClient?.assumeIsolated { $0.acceptResponseAborted(streamID: victim) }
            bridgeAbortStream(victim)
            if victim == streamID { return }
        }
        if bridgeStream.handshakeDone, let record = bridgeStream.upstreamRecord {
            flushToBridgeUpstream(out, streamID: streamID, record: record)
        } else {
            bridgeStream.pendingToUpstream.append(out)
        }
    }

    private func flushToBridgeUpstream(_ data: Data, streamID: UInt32, record: TLSRecordConnection) {
        guard !data.isEmpty, phase != .torn else { return }
        let count = data.count
        writer(for: record, failingSession: false).assumeIsolated {
            $0.write(data) { [weak self] error in
                self?.post(.bridgeUpstreamDrained(streamID: streamID, count: count, sendError: error))
            }
        }
    }

    private func noteBridgeUpstreamDrained(streamID: UInt32, count: Int, sendError: Error?) {
        guard phase != .torn else { return }
        if let bridgeStream = bridgeStreams[streamID] {
            bridgeStream.unsentUpstreamBytes -= count
            sessionUnsentUpstreamBytes -= count
        }
        if sendError != nil { bridgeClient?.assumeIsolated { $0.acceptResponseAborted(streamID: streamID) } }
    }

    private func bridgeAbortStream(_ streamID: UInt32) {
        guard let bridgeStream = bridgeStreams.removeValue(forKey: streamID) else { return }
        sessionUnsentUpstreamBytes -= bridgeStream.unsentUpstreamBytes
        bridgeStream.tlsClient?.cancel()
        bridgeStream.connection?.cancel()
        bridgeStream.proxyClient?.cancel()
        if let record = bridgeStream.upstreamRecord {
            retireLeg(record)
            record.cancel()
        }
        bridgeStream.responseStream.assumeIsolated { $0.markTorn() }
    }

    private func abortBridgeStream(_ streamID: UInt32, acceptResponseAborted: Bool) {
        bridgeAbortStream(streamID)
        if acceptResponseAborted { bridgeClient?.assumeIsolated { $0.acceptResponseAborted(streamID: streamID) } }
    }

    private func startBridgeUpstreamHandshake(streamID: UInt32, host: String) {
        guard bridgeStreams[streamID]?.connection != nil else { return }
        spawn(.bridgeStreamHandshake(streamID: streamID, host: host))
    }

    private func runBridgeStreamHandshake(streamID: UInt32, host: String) async {
        guard let bridgeStream = bridgeStreams[streamID], let connection = bridgeStream.connection else { return }
        let configuration = TLSConfiguration(
            serverName: host,
            alpn: ["http/1.1"],
            minVersion: .tls12,
            maxVersion: .tls13,
            fingerprint: .plain
        )
        let client = TLSClient(configuration: configuration)
        bridgeStream.tlsClient = client
        let disarm = armUpstreamHandshakeTimeout { [weak self] in
            self?.post(.failBridgeStreamOnTimeout(streamID: streamID))
        }
        do {
            let record = try await client.connect(overTunnel: connection)
            guard disarm() else {
                record.cancel()
                connection.cancel()
                return
            }
            guard phase != .torn, let bridgeStream = bridgeStreams[streamID] else {
                record.cancel()
                connection.cancel()
                return
            }
            bridgeStream.upstreamRecord = record
            bridgeStream.handshakeDone = true
            let pending = bridgeStream.pendingToUpstream
            bridgeStream.pendingToUpstream = Data()
            flushToBridgeUpstream(pending, streamID: streamID, record: record)
            spawn(.bridgeUpstreamPump(streamID: streamID))
        } catch {
            guard disarm() else {
                connection.cancel()
                return
            }
            guard phase != .torn else { return }
            guard bridgeStreams[streamID] === bridgeStream else {
                connection.cancel()
                return
            }
            logger.report("[MITM] \(dstHost): Upstream connect failed", error: error)
            if Self.isCertificateVerificationFailure(error) {
                cancel(error: nil)
            } else {
                if !AnywhereError.isTermination(error), let target = bridgeStream.dialTarget {
                    markUpstreamDead(target)
                }
                bridgeAbortStream(streamID)
                await bridgeClient?.failStream(streamID: streamID, status: 502, message: "Bad Gateway")
            }
        }
    }

    private func failBridgeStreamOnTimeout(_ streamID: UInt32) {
        guard phase != .torn, let bridgeStream = bridgeStreams[streamID] else { return }
        logger.report("[MITM] \(dstHost): Upstream connect failed", error: AnywhereError.mitm(.upstreamHandshakeTimeout))
        if let target = bridgeStream.dialTarget {
            markUpstreamDead(target)
        }
        bridgeAbortStream(streamID)
        bridgeClient?.assumeIsolated { $0.failStream(streamID: streamID, status: 502, message: "Bad Gateway") }
    }

    private func runBridgeUpstreamPump(streamID: UInt32) async {
        guard let record = bridgeStreams[streamID]?.upstreamRecord else { return }
        await pumpUntilRetired(record) { await self.driveBridgeUpstreamPump(streamID: streamID, record: record) }
    }

    private func driveBridgeUpstreamPump(streamID: UInt32, record: TLSRecordConnection) async {
        while true {
            let data: Data?
            let error: Error?
            do {
                data = try await record.receive()
                error = nil
            } catch let caught {
                data = nil
                error = caught
            }
            enum Step { case stop, eof(MITMHTTP1Stream), transform(MITMHTTP1Stream, Data) }
            let step: Step
            if phase == .torn {
                step = .stop
            } else if let bridgeStream = bridgeStreams[streamID], let client = bridgeClient {
                if let error {
                    if !AnywhereError.isPeerClose(error) {
                        logger.report("[MITM] \(dstHost): Upstream read failed", error: error)
                    }
                    await client.acceptResponseAborted(streamID: streamID)
                    bridgeAbortStream(streamID)
                    step = .stop
                } else if let data, !data.isEmpty {
                    step = .transform(bridgeStream.responseStream, data)
                } else {
                    step = .eof(bridgeStream.responseStream)
                }
            } else {
                step = .stop
            }
            switch step {
            case .stop:
                return
            case .eof(let responseStream):
                _ = await responseStream.finish()
                guard phase != .torn else { return }
                if bridgeStreams[streamID] != nil { bridgeAbortStream(streamID) }
                return
            case .transform(let responseStream, let data):
                _ = await responseStream.transform(data)
                guard phase != .torn else { return }
                guard bridgeStreams[streamID] != nil else { return }
            }
        }
    }
}
