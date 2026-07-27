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
    func mitmSessionDidTearDown(error: Error?)
}

actor MITMSession: MITMHTTP1StreamDelegate {

    nonisolated var unownedExecutor: UnownedSerialExecutor {
        lwipBridge.executor.asUnownedSerialExecutor()
    }

    // MARK: - Inner Transport
    
    final class InnerTransport: ByteTransport, Sendable {
        let lwipBridge: LWIPConcurrencyBridge
        
        private let inbox = AsyncInbox<Data>()
        private struct State {
            var closed = false
            weak var host: MITMSessionHost?
        }
        private let state = Mutex(State())

        var isReady: Bool { state.withLock { !$0.closed } }
        
        func setHost(_ host: MITMSessionHost?) {
            state.withLock { $0.host = host }
        }

        init(lwipBridge: LWIPConcurrencyBridge) {
            self.lwipBridge = lwipBridge
        }

        // MARK: ByteTransport

        func send(_ data: Data) async throws {
            guard !state.withLock({ $0.closed }) else { throw AnywhereError.transport(.notConnected) }
            lwipBridge.enqueue { [self] in
                let host = state.withLock { $0.closed ? nil : $0.host }
                host?.mitmSessionSendToClient(data)
            }
        }

        func receive() async throws -> TransportChunk {
            if let next = try await inbox.next() { return .bytes(next) }
            return .end
        }

        func cancel() {
            state.withLock { $0.closed = true }
            inbox.finish()
        }

        // MARK: External Inputs

        func feedFromClient(_ data: Data) {
            guard !state.withLock({ $0.closed }) else { return }
            inbox.yield(data)
        }
    }

    // MARK: - Properties

    private let dstHost: String
    private let dstPort: UInt16
    
    private let lwipBridge: LWIPConcurrencyBridge

    private let isPlaintext: Bool
    
    private let leafCache: MITMLeafCertCache?
    private let policy: MITMRewritePolicy
    
    private var proxyClient: ProxyClient?
    
    private var outerConnection: ProxyConnection?
    
    private var pendingUpstreamBytes = Data()
    
    private var dialing = false
    
    private var inboundReadPaused = false
    
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
    
    private enum PendingRequestEvent {
        case head(MITMRequestHead, url: String?, endStream: Bool)
        case data(streamID: UInt32, Data, endStream: Bool)
        case trailers(streamID: UInt32, [(name: String, value: String)])
        case abort(streamID: UInt32)
    }
    private var pendingRequestEvents: [PendingRequestEvent] = []
    
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
    private static let maxConcurrentBridgeStreams = 128
    private static let maxBridgeUpstreamBufferedBytes = 8 * 1024 * 1024
    
    private var sharedUpstreamRecord: TLSRecordConnection?
    private var sharedUpstreamConnection: ProxyConnection?
    private var sharedUpstreamProxyClient: ProxyClient?
    private var sharedUpstreamTLSClient: TLSClient?
    
    private var inbound: any MITMMessageRewriter { requestStream }
    private var outbound: any MITMMessageRewriter { responseStream }

    private let h2Rewriter: MITMHTTP2Rewriter
    
    private let h2FlowController = MITMHTTP2FlowController()
    
    private let scriptEngineProvider: MITMScriptEngine.Provider
    
    private let requestLog = MITMRequestLog()

    private var torn = false

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
        case awaitDrain(pending: SerialSender.Pending, completion: DrainCompletion)
        case upstreamHandshakeTimeout(gate: HandshakeRaceGate, disarm: AsyncInbox<Void>, onTimeout: @Sendable () -> Void)
    }
    
    private enum DrainCompletion: Sendable {
        case cancelOnError
        case thenCancel
        case bridgeUpstream(streamID: UInt32, count: Int)
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
        case failInnerLegWith502(reason: String)
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
        case .failInnerLegWith502(let reason):
            failInnerLegWith502(reason)
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
        leafCache: MITMLeafCertCache?,
        policy: MITMRewritePolicy,
        lwipBridge: LWIPConcurrencyBridge,
        isPlaintext: Bool = false
    ) {
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.pendingClientBytes = clientHello
        self.leafCache = leafCache
        self.policy = policy
        self.lwipBridge = lwipBridge
        self.isPlaintext = isPlaintext
        self.innerTransport = InnerTransport(lwipBridge: lwipBridge)
        (self.deferredActions, self.deferredActionContinuation) = AsyncStream.makeStream(of: DeferredAction.self)
        (self.sessionJobs, self.sessionJobContinuation) = AsyncStream.makeStream(of: SessionJob.self)
        let scheme = isPlaintext ? "http" : "https"
        self.scriptEngineProvider = MITMScriptEngine.Provider(scope: policy.set(for: dstHost)?.id)
        self.requestStream = MITMHTTP1Stream(
            host: dstHost,
            scheme: scheme,
            phase: .httpRequest,
            policy: policy,
            effectiveAuthority: nil,
            scriptEngineProvider: scriptEngineProvider,
            requestLog: requestLog,
            lwipBridge: lwipBridge
        )
        self.responseStream = MITMHTTP1Stream(
            host: dstHost,
            scheme: scheme,
            phase: .httpResponse,
            policy: policy,
            effectiveAuthority: nil,
            scriptEngineProvider: scriptEngineProvider,
            requestLog: requestLog,
            lwipBridge: lwipBridge
        )
        self.h2Rewriter = MITMHTTP2Rewriter(
            host: dstHost,
            policy: policy,
            effectiveAuthority: nil,
            scriptEngineProvider: scriptEngineProvider,
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
        case .awaitDrain(let pending, let completion):
            await runAwaitDrain(pending: pending, completion: completion)
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
        guard !torn else { return }
        if innerRecord != nil {
            innerTransport.feedFromClient(data)
        } else if let tlsServer {
            tlsServer.feed(data)
        } else {
            if pendingClientBytes.count + data.count > Self.maxPendingClientBytes {
                logger.warning("\(dstHost): pre-handshake buffer would exceed \(Self.maxPendingClientBytes) B; tearing down session")
                cancel(error: nil)
                return
            }
            pendingClientBytes.append(data)
        }
    }

    func cancel(error: Error? = nil) {
        guard !torn else { return }
        bridgeClient?.assumeIsolated { $0.sendGoAwayToClient(code: MITMHTTP2FrameCodec.ErrorCode.internalError) }
        torn = true
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
        sharedUpstreamRecord?.cancel()
        sharedUpstreamRecord = nil
        sharedUpstreamConnection?.cancel()
        sharedUpstreamConnection = nil
        sharedUpstreamProxyClient?.cancel()
        sharedUpstreamProxyClient = nil
        sharedUpstreamTLSClient?.cancel()
        sharedUpstreamTLSClient = nil
        pendingRequestEvents.removeAll()
        tlsServer = nil
        tlsClient?.cancel()
        tlsClient = nil
        innerRecord?.cancel()
        innerRecord = nil
        outerRecord?.cancel()
        outerRecord = nil
        outerConnection?.cancel()
        outerConnection = nil
        proxyClient?.cancel()
        proxyClient = nil
        pendingUpstreamBytes = Data()
        legSenders.removeAll()
        innerTransport.cancel()
        sessionJobContinuation.finish()
        deferredActionContinuation.finish()
        rootTask?.cancel()
        rootTask = nil
        host?.mitmSessionDidTearDown(error: error)
    }

    // MARK: - Inner Handshake

    private func startInnerHandshake(sni: String, alpns: [String], tlsVersions: Set<UInt16>) {
        guard leafCache != nil else { cancel(error: nil); return }
        spawn(.mintLeaf(sni: sni, alpns: alpns, tlsVersions: tlsVersions))
    }
    
    private func runLeafMint(sni: String, alpns: [String], tlsVersions: Set<UInt16>) async {
        guard let leafCache else { cancel(error: nil); return }
        do {
            let leaf = try await leafCache.leaf(for: sni)
            guard !torn else { return }
            beginInnerHandshake(with: leaf, alpns: alpns, tlsVersions: tlsVersions)
        } catch {
            guard !torn else { return }
            cancel(error: error)
        }
    }
    
    private func beginInnerHandshake(with leaf: MITMLeafCertCache.Leaf, alpns: [String], tlsVersions: Set<UInt16>) {
        let server = TLSServer(
            leafCert: leaf.certificate,
            leafCertDER: leaf.certificateDER,
            leafPrivateKey: leaf.privateKeySecKey,
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
        let intersected = clientALPNs.filter { supported.contains($0) }
        let alpns: [String] = intersected.isEmpty ? ["http/1.1"] : intersected
        var tlsVersions: Set<UInt16> = [0x0303]
        if clientSupportsTLS13 { tlsVersions.insert(0x0304) }
        startInnerHandshake(sni: sni, alpns: alpns, tlsVersions: tlsVersions)
    }

    // MARK: - Outer Handshake
    
    private func startCleartextUpstream(over connection: ProxyConnection) {
        guard !torn, let inner = innerRecord else { connection.cancel(); return }
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
        guard !torn else { connection.cancel(); return }
        let configuration = TLSConfiguration(
            serverName: host,
            alpn: [innerALPN],
            minVersion: .tls12,
            maxVersion: .tls13,
            fingerprint: .nonBrowser
        )
        let client = TLSClient(configuration: configuration)
        tlsClient = client
        let disarm = armUpstreamHandshakeTimeout { [weak self] in
            self?.post(.failInnerLegWith502(reason: "upstream TLS handshake timed out"))
        }
        do {
            let record = try await client.connect(overTunnel: connection)
            guard disarm() else { record.cancel(); connection.cancel(); return }
            guard !torn, let inner = innerRecord else {
                record.cancel(); connection.cancel(); return
            }
            guard record.negotiatedALPN.isEmpty || record.negotiatedALPN == "http/1.1" else {
                logger.warning("\(dstHost): unexpected upstream ALPN \"\(record.negotiatedALPN)\" for an http/1.1 leg; tearing down")
                cancel(error: nil)
                return
            }
            outerRecord = record
            finishDialAndShuttle(inner: inner, outer: record)
        } catch {
            guard disarm() else { connection.cancel(); return }
            guard !torn else { return }
            if Self.isCertVerifyFailure(error) {
                logger.warning("[MITM] \(dstHost): upstream certificate validation failed (\(AnywhereError.describe(error))); closing rather than masking as a 502")
                cancel(error: nil)
            } else {
                failInnerLegWith502("upstream connect failed: \(AnywhereError.describe(error))")
            }
        }
    }
    
    private static func isCertVerifyFailure(_ error: Error) -> Bool {
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
            sendChunkedCancellingOnError(buffered, via: outer)
        }
        spawn(.outboundPump(inner: inner, outer: outer))
        if inboundReadPaused {
            inboundReadPaused = false
            spawn(.inboundPump(inner: inner))
        }
    }
    
    private static let pumpChunkSize: Int = 64 * 1024
    
    private var legSenders: [ObjectIdentifier: SerialSender] = [:]
    
    private static func drainChunked(_ data: Data, over record: any MITMByteLeg, chunkSize: Int) async throws {
        var offset = data.startIndex
        while offset < data.endIndex {
            let take = min(chunkSize, data.distance(from: offset, to: data.endIndex))
            let end = data.index(offset, offsetBy: take)
            try await record.send(Data(data[offset..<end]))
            offset = end
        }
    }
    
    private func sendChunked(_ data: Data, via record: any MITMByteLeg) async throws {
        guard !torn else { throw AnywhereError.transport(.notConnected) }
        try await sender(for: record).submit {
            try await Self.drainChunked(data, over: record, chunkSize: Self.pumpChunkSize)
        }.value()
    }
    
    private func sender(for record: any MITMByteLeg) -> SerialSender {
        let key = ObjectIdentifier(record)
        if let existing = legSenders[key] { return existing }
        let sender = SerialSender()
        legSenders[key] = sender
        return sender
    }
    
    private func sendChunkedCancellingOnError(_ data: Data, via record: any MITMByteLeg) {
        guard !torn else { return }
        let pending = sender(for: record).submit {
            try await Self.drainChunked(data, over: record, chunkSize: Self.pumpChunkSize)
        }
        spawn(.awaitDrain(pending: pending, completion: .cancelOnError))
    }

    private func sendChunkedThenCancel(_ data: Data, via record: any MITMByteLeg) {
        guard !torn else { return }
        let pending = sender(for: record).submit {
            try await Self.drainChunked(data, over: record, chunkSize: Self.pumpChunkSize)
        }
        spawn(.awaitDrain(pending: pending, completion: .thenCancel))
    }
    
    private func runAwaitDrain(pending: SerialSender.Pending, completion: DrainCompletion) async {
        switch completion {
        case .cancelOnError:
            do { try await pending.value() }
            catch { post(.cancel(reason: error)) }
        case .thenCancel:
            _ = try? await pending.value()
            post(.cancel(reason: nil))
        case .bridgeUpstream(let streamID, let count):
            var sendError: Error?
            do { try await pending.value() } catch { sendError = error }
            post(.bridgeUpstreamDrained(streamID: streamID, count: count, sendError: sendError))
        }
    }
    
    private func runInboundPump(inner: any MITMByteLeg) async {
        while true {
            if torn { return }
            let data: Data?
            do { data = try await inner.receive() }
            catch {
                guard !torn else { return }
                cancel(error: error)
                return
            }
            guard let data, !data.isEmpty else { return }

            let transformed = await inbound.feed(data)
            if torn { return }

            let injected = inbound.drainPendingClientBytes()
            if !injected.isEmpty {
                sendChunkedCancellingOnError(injected, via: inner)
            }

            if transformed.isEmpty { continue }

            guard let outer = outerRecord else {
                bufferUpstreamAndDial(transformed, inner: inner)
                return
            }

            if resolvedUpstreamMatchesDialed() {
                do {
                    try await sendChunked(transformed, via: outer)
                } catch {
                    guard !torn else { return }
                    cancel(error: error)
                    return
                }
                continue
            }

            if canReconnectOuterLeg() {
                reconnectOuterLeg(with: transformed, inner: inner)
            } else {
                logger.warning("\(dstHost): request resolved a different upstream while the leg was busy; tearing down so the client retries")
                cancel(error: nil)
            }
            return
        }
    }

    private func bufferUpstreamAndDial(_ transformed: Data, inner: any MITMByteLeg) {
        pendingUpstreamBytes.append(transformed)
        if pendingUpstreamBytes.count > Self.maxPendingUpstreamBytes {
            logger.warning("\(dstHost): pre-dial upstream buffer exceeded \(Self.maxPendingUpstreamBytes) B; tearing down session")
            cancel(error: nil)
            return
        }
        if dialing {
            guard resolvedUpstreamMatchesDialed() else {
                logger.warning("\(dstHost): pipelined request resolved an upstream different from the dialed one; tearing down so the client retries")
                cancel(error: nil)
                return
            }
            resumeOrPauseInboundPreDial(inner: inner)
            return
        }
        dialing = true
        let resolved = inbound.resolvedUpstream
        let host = resolved?.host ?? dstHost
        let port = resolved?.port ?? dstPort
        dialedHost = host
        dialedPort = port
        let negotiatedInnerALPN = innerRecord?.negotiatedALPN ?? ""
        let innerALPN = negotiatedInnerALPN.isEmpty ? "http/1.1" : negotiatedInnerALPN
        guard self.host != nil else {
            failInnerLegWith502("upstream connect failed: session detached")
            return
        }
        spawn(.deferredDial(host: host, port: port, innerALPN: innerALPN))
        resumeOrPauseInboundPreDial(inner: inner)
    }
    
    private func runDeferredDial(host: String, port: UInt16, innerALPN: String) async {
        guard let sessionHost = self.host else {
            failInnerLegWith502("upstream connect failed: session detached")
            return
        }
        do {
            let dial = try await sessionHost.mitmDialUpstream(host: host, port: port)
            guard !torn else { dial.connection.cancel(); await dial.proxyClient?.cancel(); return }
            proxyClient = dial.proxyClient
            outerConnection = dial.connection
            if isPlaintext {
                startCleartextUpstream(over: dial.connection)
            } else {
                startOuterHandshakeAfterDial(over: dial.connection, host: host, innerALPN: innerALPN)
            }
        } catch {
            guard !torn else { return }
            failInnerLegWith502("upstream connect failed: \(AnywhereError.describe(error))")
        }
    }

    private func resumeOrPauseInboundPreDial(inner: any MITMByteLeg) {
        if pendingUpstreamBytes.count >= Self.maxPendingClientBytes {
            inboundReadPaused = true
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
        logger.info("\(dstHost): later request resolved a new upstream; reconnecting the idle outer leg instead of tearing down")
        let oldOuter = outerRecord
        outerRecord = nil
        if let oldOuter {
            legSenders.removeValue(forKey: ObjectIdentifier(oldOuter))
            oldOuter.cancel()
        }
        tlsClient?.cancel()
        tlsClient = nil
        outerConnection?.cancel()
        outerConnection = nil
        proxyClient?.cancel()
        proxyClient = nil
        dialing = false
        dialedHost = nil
        dialedPort = nil
        pendingUpstreamBytes = Data()
        inboundReadPaused = false
        bufferUpstreamAndDial(transformed, inner: inner)
    }
    
    private final class HandshakeRaceGate: Sendable {
        private let settled = Atomic(false)
        func claim() -> Bool {
            settled.compareExchange(expected: false, desired: true, ordering: .relaxed).exchanged
        }
    }
    
    private func armUpstreamHandshakeTimeout(_ onTimeout: @escaping @Sendable () -> Void) -> () -> Bool {
        let gate = HandshakeRaceGate()
        let disarmPoke = AsyncInbox<Void>(capacity: 1)
        spawn(.upstreamHandshakeTimeout(gate: gate, disarm: disarmPoke, onTimeout: onTimeout))
        return { [gate, disarmPoke] in
            guard gate.claim() else { return false }
            disarmPoke.yield(())
            return true
        }
    }

    private func runUpstreamHandshakeTimeout(
        gate: HandshakeRaceGate,
        disarm: AsyncInbox<Void>,
        onTimeout: @Sendable () -> Void
    ) async {
        let timedOut = await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                do { try await Task.sleep(for: .seconds(TunnelConstants.handshakeTimeout)); return true }
                catch { return false }
            }
            group.addTask {
                _ = try? await disarm.next(); return false
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
        guard timedOut, gate.claim() else { return }
        onTimeout()
    }
    
    private func failInnerLegWith502(_ reason: String) {
        guard !torn else { return }
        guard let inner = innerRecord else { cancel(error: nil); return }
        logger.warning("[MITM] \(dstHost): \(reason); answering client 502 over the inner leg")
        let body = Data("502 Bad Gateway".utf8)
        var head = "HTTP/1.1 502 Bad Gateway\r\n"
        head += "Content-Type: text/plain; charset=utf-8\r\n"
        head += "Content-Length: \(body.count)\r\n"
        head += "Connection: close\r\n\r\n"
        var response = Data(head.utf8)
        response.append(body)
        sendChunkedThenCancel(response, via: inner)
    }
    
    private func handleResponseUpgrade() {
        guard !torn else { return }
        let buffered = requestStream.assumeIsolated { $0.forcePassthrough() }
        guard !buffered.isEmpty, let outer = outerRecord else { return }
        sendChunkedCancellingOnError(buffered, via: outer)
    }

    // MARK: MITMHTTP1StreamDelegate

    nonisolated func http1StreamDidUpgrade(_ stream: MITMHTTP1Stream) {
        guard stream.bridgeClientStreamID == nil else { return }
        assumeIsolated { $0.handleResponseUpgrade() }
    }

    nonisolated func http1StreamFatalClose(_ stream: MITMHTTP1Stream) {
        if let sid = stream.bridgeClientStreamID {
            post(.abortBridgeStream(streamID: sid, acceptResponseAborted: true))
            return
        }
        switch stream.phase {
        case .httpRequest:
            post(.cancel(reason: nil))
        case .httpResponse:
            post(.failInnerLegWith502(reason: "rejected a malformed or oversized upstream response"))
        }
    }

    nonisolated func http1StreamHardClose(_ stream: MITMHTTP1Stream) {
        guard stream.bridgeClientStreamID == nil else { return }
        post(.cancel(reason: nil))
    }
    
    private func runOutboundPump(inner: any MITMByteLeg, outer: any MITMByteLeg) async {
        while true {
            let data: Data?
            let error: Error?
            do { data = try await outer.receive(); error = nil }
            catch let e { data = nil; error = e }
            if outerRecord !== outer {
                return
            }
            if let error {
                cancel(error: error)
                return
            }
            guard let data, !data.isEmpty else {
                let flushed = await responseStream.finish()
                guard !torn else { return }
                if flushed.isEmpty {
                    cancel(error: nil)
                } else {
                    sendChunkedThenCancel(flushed, via: inner)
                }
                return
            }
            let transformed = await outbound.feed(data)
            if transformed.isEmpty { continue }
            do {
                try await sendChunked(transformed, via: inner)
            } catch {
                guard !torn else { return }
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
                lwipBridge: lwipBridge
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
            do { data = try await inner.receive(); error = nil }
            catch let e { data = nil; error = e }
            // Resumes on the actor.
            if torn { return }
            if let error { cancel(error: error); return }
            guard let data, !data.isEmpty, let client = bridgeClient else {
                return
            }
            await client.feed(data)
        }
    }

    nonisolated func clientLegWriteToClient(_ data: Data) {
        assumeIsolated { $0.writeToClient(data) }
    }
    private func writeToClient(_ data: Data) {
        guard !torn, !data.isEmpty, let inner = innerRecord else { return }
        sendChunkedCancellingOnError(data, via: inner)
    }

    nonisolated func clientLegFatalError(_ message: String) {
        assumeIsolated { $0.handleClientLegFatalError(message) }
    }
    private func handleClientLegFatalError(_ message: String) {
        logger.warning("\(dstHost): client leg fatal: \(message); tearing down")
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
        guard !torn else { return }
        switch upstreamProtocol {
        case .h2:
            h2Rewriter.requestLog.recordHTTP2(streamID: head.clientStreamID, method: head.method, url: url, originalUrl: head.originalURL)
            h2Upstream?.assumeIsolated { $0.sendRequestHead(head, endStream: endStream) }
        case .h1:
            openH1Stream(head, url: url)
        case .undetermined:
            pendingRequestEvents.append(.head(head, url: url, endStream: endStream))
            startFirstUpstreamDial()
        }
    }

    nonisolated func clientLegSendRequestData(streamID: UInt32, _ data: Data, endStream: Bool) {
        assumeIsolated { $0.sendRequestDataUpstream(streamID: streamID, data, endStream: endStream) }
    }
    private func sendRequestDataUpstream(streamID: UInt32, _ data: Data, endStream: Bool) {
        guard !torn else { return }
        switch upstreamProtocol {
        case .h2:
            h2Upstream?.assumeIsolated { $0.sendRequestData(streamID: streamID, data, endStream: endStream) }
        case .h1:
            appendH1RequestData(streamID: streamID, data, endStream: endStream)
        case .undetermined:
            pendingRequestEvents.append(.data(streamID: streamID, data, endStream: endStream))
        }
    }

    nonisolated func clientLegSendRequestTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)]) {
        assumeIsolated { $0.sendRequestTrailersUpstream(streamID: streamID, trailers) }
    }
    private func sendRequestTrailersUpstream(streamID: UInt32, _ trailers: [(name: String, value: String)]) {
        guard !torn else { return }
        switch upstreamProtocol {
        case .h2:
            h2Upstream?.assumeIsolated { $0.sendRequestTrailers(streamID: streamID, trailers) }
        case .h1:
            logger.warning("\(dstHost): dropping h2 request trailers toward h1 upstream stream \(streamID)")
            appendH1RequestData(streamID: streamID, Data(), endStream: true)
        case .undetermined:
            pendingRequestEvents.append(.trailers(streamID: streamID, trailers))
        }
    }

    nonisolated func clientLegAbortRequest(streamID: UInt32) {
        assumeIsolated { $0.abortRequestUpstream(streamID: streamID) }
    }
    private func abortRequestUpstream(streamID: UInt32) {
        guard !torn else { return }
        switch upstreamProtocol {
        case .h2: h2Upstream?.assumeIsolated { $0.abortRequest(streamID: streamID) }
        case .h1: bridgeAbortStream(streamID)
        case .undetermined: pendingRequestEvents.append(.abort(streamID: streamID))
        }
    }

    nonisolated func clientLegResponseComplete(streamID: UInt32) {
        assumeIsolated { $0.responseCompleteUpstream(streamID: streamID) }
    }
    private func responseCompleteUpstream(streamID: UInt32) {
        if upstreamProtocol == .h1 { bridgeAbortStream(streamID) }
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
        guard let host else { failPendingBridgeRequests(error: AnywhereError.transport(.notConnected)); return }
        do {
            let dial = try await host.mitmDialUpstream(host: dialHost, port: port)
            guard !torn else { dial.connection.cancel(); await dial.proxyClient?.cancel(); return }
            sharedUpstreamProxyClient = dial.proxyClient
            sharedUpstreamConnection = dial.connection
            startFirstUpstreamHandshake(host: dialHost, connection: dial.connection)
        } catch {
            guard !torn else { return }
            failPendingBridgeRequests(error: error)
        }
    }
    
    private func failPendingBridgeRequests(error: Error) {
        guard !torn else { return }
        logger.warning("[MITM] \(dstHost): first upstream connect failed: \(AnywhereError.describe(error)); answering pending streams 502, keeping the connection")
        // Discard the failed probe connection; nothing to reuse.
        sharedUpstreamRecord = nil
        sharedUpstreamTLSClient?.cancel(); sharedUpstreamTLSClient = nil
        sharedUpstreamConnection?.cancel(); sharedUpstreamConnection = nil
        sharedUpstreamProxyClient?.cancel(); sharedUpstreamProxyClient = nil
        // Let the next request re-probe (upstreamProtocol stays .undetermined).
        firstUpstreamDialStarted = false
        let events = pendingRequestEvents
        pendingRequestEvents.removeAll()
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
        guard !torn else { connection.cancel(); return }
        let configuration = TLSConfiguration(
            serverName: host,
            alpn: ["h2", "http/1.1"],
            minVersion: .tls12,
            maxVersion: .tls13,
            fingerprint: .nonBrowser
        )
        let client = TLSClient(configuration: configuration)
        sharedUpstreamTLSClient = client
        let disarm = armUpstreamHandshakeTimeout { [weak self] in
            self?.post(.failPendingBridgeRequests(reason: AnywhereError.mitm(.upstreamHandshakeTimeout)))
        }
        do {
            let record = try await client.connect(overTunnel: connection)
            guard disarm() else { record.cancel(); connection.cancel(); return }
            guard !torn else { record.cancel(); connection.cancel(); return }
            sharedUpstreamRecord = record
            if record.negotiatedALPN == "h2" {
                bindH2Upstream(record: record)
            } else {
                bindH1Upstream()
            }
        } catch {
            guard disarm() else { connection.cancel(); return }
            guard !torn else { return }
            if Self.isCertVerifyFailure(error) {
                logger.warning("[MITM] \(dstHost): upstream certificate validation failed (\(AnywhereError.describe(error))); closing rather than masking as a 502")
                cancel(error: nil)
            } else {
                failPendingBridgeRequests(error: error)
            }
        }
    }

    private func bindH2Upstream(record: TLSRecordConnection) {
        upstreamProtocol = .h2
        let leg = MITMHTTP2UpstreamLeg(host: dstHost, rewriter: h2Rewriter, flowController: h2FlowController, lwipBridge: lwipBridge)
        h2Upstream = leg
        bridgeClient?.assumeIsolated { $0.uploadDrainCoupled = true }
        let events = pendingRequestEvents
        pendingRequestEvents.removeAll()
        let client = bridgeClient
        let rewriter = h2Rewriter
        leg.assumeIsolated { legSelf in
            legSelf.sink = client
            legSelf.delegate = self
            for event in events {
                switch event {
                case .head(let head, let url, let endStream):
                    rewriter.requestLog.recordHTTP2(streamID: head.clientStreamID, method: head.method, url: url, originalUrl: head.originalURL)
                    legSelf.sendRequestHead(head, endStream: endStream)
                case .data(let streamID, let data, let endStream):
                    legSelf.sendRequestData(streamID: streamID, data, endStream: endStream)
                case .trailers(let streamID, let trailers):
                    legSelf.sendRequestTrailers(streamID: streamID, trailers)
                case .abort(let streamID):
                    legSelf.abortRequest(streamID: streamID)
                }
            }
        }
        spawn(.h2UpstreamPump(record: record))
    }
    
    private func runH2UpstreamPump(record: TLSRecordConnection) async {
        while true {
            let data: Data?
            let error: Error?
            do { data = try await record.receive(); error = nil }
            catch let e { data = nil; error = e }
            guard !torn, let leg = h2Upstream else { return }
            if let error { cancel(error: error); return }
            guard let data, !data.isEmpty else { cancel(error: nil); return }
            await leg.feed(data)
        }
    }
    
    nonisolated func upstreamLegWriteToOrigin(_ data: Data) {
        assumeIsolated { me in
            guard !me.torn, !data.isEmpty, let record = me.sharedUpstreamRecord else { return }
            me.sendChunkedCancellingOnError(data, via: record)
        }
    }

    nonisolated func upstreamLegFatalError(_ message: String) {
        post(.cancel(reason: nil))
    }
    
    nonisolated func upstreamLegDraining() {
        assumeIsolated { me in me.bridgeClient?.assumeIsolated { $0.sendGoAwayToClient(code: MITMHTTP2FrameCodec.ErrorCode.noError) } }
    }

    nonisolated func upstreamLegRequestDrained(clientID: UInt32, count: Int) {
        assumeIsolated { me in me.bridgeClient?.assumeIsolated { $0.creditUploadDrained(clientID, count) } }
    }

    private func bindH1Upstream() {
        upstreamProtocol = .h1
        logger.info("\(dstHost): bridging h2 client to http/1.1 upstream")
        let events = pendingRequestEvents
        pendingRequestEvents.removeAll()
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
        guard bridgeStreams.count < Self.maxConcurrentBridgeStreams else {
            logger.warning("\(dstHost): bridge concurrent-stream cap reached; refusing stream \(streamID)")
            bridgeClient?.assumeIsolated { $0.rejectStream(streamID, errorCode: MITMHTTP2FrameCodec.ErrorCode.refusedStream) }
            return
        }
        let responseLog = MITMRequestLog()
        responseLog.recordHTTP1(method: head.method, url: url, originalUrl: head.originalURL)
        let responseStream = MITMHTTP1Stream(
            host: dstHost, phase: .httpResponse, policy: policy, effectiveAuthority: nil,
            scriptEngineProvider: scriptEngineProvider, requestLog: responseLog, lwipBridge: lwipBridge,
            bridgeClientStreamID: streamID
        )
        responseStream.assumeIsolated { $0.delegate = self }
        let bs = BridgeStream(clientStreamID: streamID, responseStream: responseStream, responseLog: responseLog)
        let irSink = BridgeResponseIRSink(streamID: streamID, client: bridgeClient) { [weak self] sid in
            self?.assumeIsolated { me in me.bridgeClient?.assumeIsolated { $0.acceptResponseAborted(streamID: sid) } }
            self?.post(.abortBridgeStream(streamID: sid, acceptResponseAborted: false))
        }
        responseStream.assumeIsolated { $0.responseIRSink = irSink }
        bs.responseIRSink = irSink
        bs.framing = head.framing
        bs.pendingToUpstream = MITMHTTP1Serializer.requestHead(head, host: dstHost)
        bs.unsentUpstreamBytes = bs.pendingToUpstream.count
        bridgeStreams[streamID] = bs

        if let record = sharedUpstreamRecord {
            sharedUpstreamRecord = nil
            bs.proxyClient = sharedUpstreamProxyClient; sharedUpstreamProxyClient = nil
            bs.connection = sharedUpstreamConnection; sharedUpstreamConnection = nil
            bs.tlsClient = sharedUpstreamTLSClient; sharedUpstreamTLSClient = nil
            bs.upstreamRecord = record
            bs.handshakeDone = true
            let pending = bs.pendingToUpstream; bs.pendingToUpstream = Data()
            flushToBridgeUpstream(pending, streamID: streamID, record: record)
            spawn(.bridgeUpstreamPump(streamID: streamID))
            return
        }
        
        let resolved = head.resolvedUpstream
        let host = resolved?.host ?? dstHost
        let port = resolved?.port ?? dstPort
        guard self.host != nil else { bridgeAbortStream(streamID); return }
        spawn(.bridgeStreamDial(streamID: streamID, host: host, port: port))
    }
    
    private func runBridgeStreamDial(streamID: UInt32, host: String, port: UInt16) async {
        guard let sessionHost = self.host else { bridgeAbortStream(streamID); return }
        do {
            let dial = try await sessionHost.mitmDialUpstream(host: host, port: port)
            guard !torn, let bs = bridgeStreams[streamID] else {
                dial.connection.cancel(); await dial.proxyClient?.cancel(); return
            }
            bs.proxyClient = dial.proxyClient
            bs.connection = dial.connection
            startBridgeUpstreamHandshake(streamID: streamID, host: host)
        } catch {
            guard !torn else { return }
            logger.warning("\(dstHost): h1 upstream dial failed for stream \(streamID): \(AnywhereError.describe(error))")
            bridgeAbortStream(streamID)
            await bridgeClient?.failStream(streamID: streamID, status: 502, message: "Bad Gateway")
        }
    }

    private func appendH1RequestData(streamID: UInt32, _ data: Data, endStream: Bool) {
        guard let bs = bridgeStreams[streamID] else { return }
        var out = Data()
        switch bs.framing {
        case .chunked:
            if !data.isEmpty { out.append(MITMHTTP1Serializer.chunk(data)) }
            if endStream { out.append(MITMHTTP1Serializer.chunkTerminator) }
        case .contentLength:
            if !data.isEmpty { out.append(data) }
        case .none:
            break
        }
        guard !out.isEmpty else { return }
        bs.unsentUpstreamBytes += out.count
        if bs.unsentUpstreamBytes > Self.maxBridgeUpstreamBufferedBytes {
            logger.warning("\(dstHost): bridge stream \(streamID) upstream-bound backlog \(bs.unsentUpstreamBytes) B over cap; resetting stream")
            bridgeClient?.assumeIsolated { $0.acceptResponseAborted(streamID: streamID) }
            bridgeAbortStream(streamID)
            return
        }
        if bs.handshakeDone, let record = bs.upstreamRecord {
            flushToBridgeUpstream(out, streamID: streamID, record: record)
        } else {
            bs.pendingToUpstream.append(out)
        }
    }
    
    private func flushToBridgeUpstream(_ data: Data, streamID: UInt32, record: TLSRecordConnection) {
        guard !data.isEmpty, !torn else { return }
        let count = data.count
        let pending = sender(for: record).submit {
            try await Self.drainChunked(data, over: record, chunkSize: Self.pumpChunkSize)
        }
        spawn(.awaitDrain(pending: pending, completion: .bridgeUpstream(streamID: streamID, count: count)))
    }

    private func noteBridgeUpstreamDrained(streamID: UInt32, count: Int, sendError: Error?) {
        guard !torn else { return }
        bridgeStreams[streamID]?.unsentUpstreamBytes -= count
        if sendError != nil { bridgeClient?.assumeIsolated { $0.acceptResponseAborted(streamID: streamID) } }
    }

    private func bridgeAbortStream(_ streamID: UInt32) {
        guard let bs = bridgeStreams.removeValue(forKey: streamID) else { return }
        bs.tlsClient?.cancel()
        bs.connection?.cancel()
        bs.proxyClient?.cancel()
        if let record = bs.upstreamRecord {
            legSenders.removeValue(forKey: ObjectIdentifier(record))
            record.cancel()
        }
        bs.responseStream.assumeIsolated { $0.markTorn() }
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
        guard let bs = bridgeStreams[streamID], let connection = bs.connection else { return }
        let configuration = TLSConfiguration(
            serverName: host,
            alpn: ["http/1.1"],
            minVersion: .tls12,
            maxVersion: .tls13,
            fingerprint: .nonBrowser
        )
        let client = TLSClient(configuration: configuration)
        bs.tlsClient = client
        let disarm = armUpstreamHandshakeTimeout { [weak self] in
            self?.post(.failBridgeStreamOnTimeout(streamID: streamID))
        }
        do {
            let record = try await client.connect(overTunnel: connection)
            guard disarm() else { record.cancel(); connection.cancel(); return }
            guard !torn, let bs = bridgeStreams[streamID] else {
                record.cancel(); connection.cancel(); return
            }
            bs.upstreamRecord = record
            bs.handshakeDone = true
            let pending = bs.pendingToUpstream
            bs.pendingToUpstream = Data()
            flushToBridgeUpstream(pending, streamID: streamID, record: record)
            spawn(.bridgeUpstreamPump(streamID: streamID))
        } catch {
            guard disarm() else { connection.cancel(); return }
            guard !torn else { return }
            if Self.isCertVerifyFailure(error) {
                logger.warning("\(dstHost): bridge upstream certificate validation failed for stream \(streamID) (\(AnywhereError.describe(error))); closing rather than masking as a 502")
                cancel(error: nil)
            } else {
                logger.warning("\(dstHost): bridge upstream TLS failed for stream \(streamID): \(AnywhereError.describe(error))")
                bridgeAbortStream(streamID)
                await bridgeClient?.failStream(streamID: streamID, status: 502, message: "Bad Gateway")
            }
        }
    }
    
    private func failBridgeStreamOnTimeout(_ streamID: UInt32) {
        guard !torn else { return }
        logger.warning("\(dstHost): bridge upstream TLS timed out for stream \(streamID); answering 502")
        bridgeAbortStream(streamID)
        bridgeClient?.assumeIsolated { $0.failStream(streamID: streamID, status: 502, message: "Bad Gateway") }
    }
    
    private func runBridgeUpstreamPump(streamID: UInt32) async {
        guard let record = bridgeStreams[streamID]?.upstreamRecord else { return }
        while true {
            let data: Data?
            let error: Error?
            do { data = try await record.receive(); error = nil }
            catch let e { data = nil; error = e }
            enum Step { case stop, eof(MITMHTTP1Stream), transform(MITMHTTP1Stream, Data) }
            let step: Step
            if torn {
                step = .stop
            } else if let bs = bridgeStreams[streamID], let client = bridgeClient {
                if let error {
                    logger.report("\(dstHost): bridge upstream read error for stream \(streamID)", error: error)
                    await client.acceptResponseAborted(streamID: streamID)
                    bridgeAbortStream(streamID)
                    step = .stop
                } else if let data, !data.isEmpty {
                    step = .transform(bs.responseStream, data)
                } else {
                    step = .eof(bs.responseStream)
                }
            } else {
                step = .stop
            }
            switch step {
            case .stop:
                return
            case .eof(let responseStream):
                _ = await responseStream.finish()
                guard !torn else { return }
                if bridgeStreams[streamID] != nil { bridgeAbortStream(streamID) }
                return
            case .transform(let responseStream, let data):
                _ = await responseStream.transform(data)
                guard !torn else { return }
                guard bridgeStreams[streamID] != nil else { return }
            }
        }
    }
}
