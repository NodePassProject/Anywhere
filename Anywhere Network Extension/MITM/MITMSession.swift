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
    /// nil for a direct connection; the session owns its lifetime.
    let proxyClient: ProxyClient?
}

typealias MITMDialer = @Sendable (_ host: String, _ port: UInt16) async throws -> MITMDialResult

actor MITMSession {

    nonisolated var unownedExecutor: UnownedSerialExecutor {
        lwipBridge.executor.asUnownedSerialExecutor()
    }

    // MARK: - Inner Transport (async byte transport for the lwIP side)

    /// Bidirectional pipe between the inner-leg TLS record connection and the lwIP-attached caller.
    /// Client→session bytes arrive via ``feedFromClient(_:)``/``endOfClient()`` and drain through an
    /// `AsyncThrowingStream`; session→client bytes go out ``onSendToClient`` (fire-and-forget, since the
    /// lwIP write buffers and gives no backpressure signal).
    final class InnerTransport: ByteTransport, Sendable {
        let lwipBridge: LWIPConcurrencyBridge

        /// Client→session bytes. The producer (`yield`/`finish`) is `Sendable` (fed from the lwIP
        /// queue); a single consumer pulls via ``receive()``.
        private let inbox = AsyncInbox<Data>()
        private struct State {
            var closed = false
            /// The client half-closed its send side (TCP FIN): the receive side reports EOF, but sends to
            /// the client stay open so an in-flight response still drains — matching the non-MITM path,
            /// which keeps pumping downlink after a client FIN. `closed` (cancel) blocks both sides.
            var receiveClosed = false
            /// Downlink sink to the lwIP client leg; set once before the pumps start and invoked on
            /// the lwIP queue. Held in `State` (not a bare `var`) so the transport stays `Sendable`.
            var onSendToClient: (@Sendable (Data) -> Void)?
        }
        private let state = Mutex(State())

        var isReady: Bool { state.withLock { !$0.closed } }

        /// Installs the downlink sink; called once before the session's pumps begin.
        func setOnSendToClient(_ handler: (@Sendable (Data) -> Void)?) {
            state.withLock { $0.onSendToClient = handler }
        }

        init(lwipBridge: LWIPConcurrencyBridge) {
            self.lwipBridge = lwipBridge
        }

        // MARK: ByteTransport

        func send(_ data: Data) async throws {
            guard !state.withLock({ $0.closed }) else { throw AnywhereError.transport(.notConnected) }
            // Ordered onto the lwIP queue (the confinement for onSendToClient/writeToLWIP); the lwIP
            // write buffers, so there is no completion to await — enqueueing preserves send order.
            lwipBridge.enqueue { [self] in
                let handler = state.withLock { $0.closed ? nil : $0.onSendToClient }
                handler?(data)
            }
        }

        func finishSend() async throws {
            // The inner leg never half-closes the lwIP downlink — an in-flight response still drains
            // after a client FIN — so there is nothing to signal here.
        }

        func receive() async throws -> TransportChunk {
            // Single-consumer pull.
            if let next = try await inbox.next() { return .bytes(next) }
            return .end
        }

        func cancel() {
            state.withLock { $0.closed = true }
            inbox.finish()
        }

        // MARK: External Inputs (from the lwIP side, on `queue`)

        func feedFromClient(_ data: Data) {
            guard !state.withLock({ $0.closed || $0.receiveClosed }) else { return }
            inbox.yield(data)
        }

        func endOfClient() {
            state.withLock { $0.receiveClosed = true }
            inbox.finish()
        }
    }

    // MARK: - Properties

    private let dstHost: String
    private let dstPort: UInt16
    /// The lwIP concurrency boundary; every queue hop and continuation seam routes through it.
    private let lwipBridge: LWIPConcurrencyBridge

    private let isPlaintext: Bool

    /// nil for a plaintext session; cleartext presents no certificate.
    private let leafCache: MITMLeafCertCache?
    private let policy: MITMRewritePolicy

    private let dialer: MITMDialer

    /// Retained so it isn't deallocated mid-stream; nil for a direct connection.
    private var proxyClient: ProxyClient?

    /// Retained so teardown can cancel the dial before the outer handshake completes.
    private var outerConnection: ProxyConnection?

    /// Upstream-bound bytes buffered until the outer leg exists; capped by maxPendingClientBytes.
    private var pendingUpstreamBytes = Data()

    /// True while the dial is in flight; further upstream-bound bytes buffer instead of redialing.
    private var dialing = false

    /// True when the inbound pump paused under backpressure (pre-dial buffer at the high-water mark);
    /// resumed once the outer leg exists and drains.
    private var inboundReadPaused = false

    /// Upstream the dial committed to; a later request resolving a different one is torn down rather than misrouted.
    private var dialedHost: String?
    private var dialedPort: UInt16?

    /// From the ClientHello; caps the inner (client-facing) leg's max TLS version.
    private var clientSupportsTLS13 = false

    /// Client bytes buffered until the inner TLSServer exists.
    private var pendingClientBytes: Data

    /// Pre-handshake buffer cap (256 KiB: tolerates large ClientHellos, bounds memory against a hostile
    /// local app). Also the pre-dial inbound high-water mark: while dialing, the inner read pauses
    /// (backpressure) when the upstream-bound buffer reaches it.
    private static let maxPendingClientBytes: Int = 256 * 1024

    /// Hard backstop on the pre-dial upstream buffer; sits above the 4 MiB body cap (one buffered-body
    /// rewrite can deliver that much in one chunk). Backpressure keeps it near `maxPendingClientBytes`,
    /// so tripping it means a pathological case.
    private static let maxPendingUpstreamBytes: Int = 8 * 1024 * 1024

    private var tlsServer: TLSServer?
    private var tlsClient: TLSClient?

    private let innerTransport: InnerTransport

    /// Post-handshake byte legs; decrypted/cleartext plaintext stays inside the session.
    private var innerRecord: (any MITMByteLeg)?
    private var outerRecord: (any MITMByteLeg)?

    /// HTTP/1.1 stream rewriters, one per direction.
    private let requestStream: MITMHTTP1Stream
    private let responseStream: MITMHTTP1Stream

    // MARK: - Decoupled HTTP/2 client leg (late-bound upstream)
    //
    // An h2 client's `bridgeClient` decodes into protocol-neutral request IR. The first request
    // triggers one dial offering both ALPNs; the upstream leg is bound from the negotiated protocol
    // (one multiplexed h2 leg, or per-stream h1 legs). An h2 upstream multiplexes every stream over
    // its one connection, so a later stream resolving a different host is still sent there; the h1
    // bridge dials per stream and so follows each stream's host.

    private var bridgeClient: MITMBridgeClientLeg?

    /// Multiplexed HTTP/2 upstream leg, bound when the first dial negotiates `h2`.
    private var h2Upstream: MITMHTTP2UpstreamLeg?

    private enum UpstreamProtocol { case undetermined, h2, h1 }
    private var upstreamProtocol: UpstreamProtocol = .undetermined
    private var firstUpstreamDialStarted = false

    /// Request events buffered until the first dial binds the upstream protocol.
    private enum PendingRequestEvent {
        case head(MITMRequestHead, url: String?, endStream: Bool)
        case data(streamID: UInt32, Data, endStream: Bool)
        case trailers(streamID: UInt32, [(name: String, value: String)])
        case abort(streamID: UInt32)
    }
    private var pendingRequestEvents: [PendingRequestEvent] = []

    /// One http/1.1 upstream connection per client h2 stream: carries one request/response, then closes.
    private final class BridgeStream {
        let clientStreamID: UInt32
        var proxyClient: ProxyClient?
        var connection: ProxyConnection?
        var tlsClient: TLSClient?
        var upstreamRecord: TLSRecordConnection?
        /// Response-phase rewriter; delivers rewritten response IR straight to the client leg via
        /// `responseIRSink` (no HTTP/1.1 re-serialize → re-parse round-trip).
        let responseStream: MITMHTTP1Stream
        /// Holds the IR sink strongly (the stream references it weakly) for this stream's lifetime.
        var responseIRSink: MITMHTTP1ResponseIRSink?
        /// Single-entry request log so HEAD/URL correlation can't interleave across streams.
        let responseLog: MITMRequestLog
        var framing: MITMBridgeBodyFraming = .none
        /// Serialized request bytes held until the per-stream TLS handshake completes.
        var pendingToUpstream = Data()
        /// Upstream-bound bytes accepted from the client but not yet confirmed written. Bounds the
        /// eagerly credited client against a slow upstream (see `maxBridgeUpstreamBufferedBytes`).
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
        /// Weak back-reference to the client leg, boxed so this set-once value stays a `let` and the
        /// sink is honestly `Sendable` (the leg is an actor = Sendable; a weak load is atomic).
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

    /// Bounds concurrent upstream sockets per bridged client connection; excess streams
    /// are refused (REFUSED_STREAM) so the client may retry later.
    private static let maxConcurrentBridgeStreams = 128

    /// Per-stream cap on h2→h1 bridge upstream-bound bytes buffered or in flight. The client leg credits
    /// the upload window eagerly (else one stalled stream freezes the multiplexed connection), so a fast
    /// client to a slow h1 origin would otherwise grow memory unbounded. Over cap the stream is reset.
    private static let maxBridgeUpstreamBufferedBytes = 8 * 1024 * 1024

    /// The first dial's established upstream connection. For h2 it's the multiplexed connection (kept
    /// for the session); for h1.1 the first stream reuses it then clears it (others dial their own).
    private var sharedUpstreamRecord: TLSRecordConnection?
    private var sharedUpstreamConnection: ProxyConnection?
    private var sharedUpstreamProxyClient: ProxyClient?
    private var sharedUpstreamTLSClient: TLSClient?

    /// Active inbound/outbound rewriter for an HTTP/1.1 *inner* leg (h2 inner uses the decoupled
    /// client leg above, not these).
    private var inbound: any MITMMessageRewriter { requestStream }
    private var outbound: any MITMMessageRewriter { responseStream }

    private let h2Rewriter: MITMHTTP2Rewriter

    /// Tracks the client's HTTP/2 receive windows so synthesized bodies are paced rather than
    /// truncated; shared by both h2 legs.
    private let h2FlowController = MITMHTTP2FlowController()

    /// JS engine handle, shared per rule set; materializes only when a script rule fires.
    private let scriptEngineProvider: MITMScriptEngine.Provider

    /// Records the in-flight request's method+URL for response-phase scripts.
    private let requestLog = MITMRequestLog()

    private var torn = false

    // MARK: - Deferred actions
    //
    // Upcalls from queue-confined child callbacks (stream hooks, writer completions, handshake
    // timeouts) that must run off the caller's stack — a teardown mid-parse would be re-entrant.
    // A callback yields an action instead of spawning an unowned `Task`; the single session-owned
    // ``deferredActionsTask`` applies them in FIFO order. Same deferral as the former per-event
    // task hops, but with ordering, ownership, and deterministic teardown.

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
    /// The single ordered consumer; spawned by ``start(sni:)``, ended by `cancel()` finishing the
    /// channel (the loop then falls out on its own, releasing the strongly captured session).
    private var deferredActionsTask: Task<Void, Never>?

    /// Defers `action` off the current call stack; safe from any domain, ordered per producer.
    private nonisolated func post(_ action: DeferredAction) {
        deferredActionContinuation.yield(action)
    }

    /// Applies one deferred action on the actor; anything arriving after teardown drops at the
    /// target method's own `torn` guard.
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

    /// Set by the lwIP-side caller to write inner-leg bytes back to the client (fire-and-forget).
    var onSendToClient: (@Sendable (Data) -> Void)? {
        didSet { innerTransport.setOnSendToClient(onSendToClient) }
    }

    /// Called on teardown; `error` is nil for a clean close.
    var onTeardown: ((Error?) -> Void)?

    // MARK: - Init

    init(
        dstHost: String,
        dstPort: UInt16,
        clientHello: Data,
        leafCache: MITMLeafCertCache?,
        policy: MITMRewritePolicy,
        dialer: @escaping MITMDialer,
        lwipBridge: LWIPConcurrencyBridge,
        isPlaintext: Bool = false
    ) {
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.pendingClientBytes = clientHello
        self.leafCache = leafCache
        self.policy = policy
        self.dialer = dialer
        self.lwipBridge = lwipBridge
        self.isPlaintext = isPlaintext
        self.innerTransport = InnerTransport(lwipBridge: lwipBridge)
        (self.deferredActions, self.deferredActionContinuation) = AsyncStream.makeStream(of: DeferredAction.self)
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
            effectiveAuthority: nil, // Host headers do not apply on responses.
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
        deferredActionsTask = Task {
            for await action in deferredActions {
                apply(action)
            }
        }
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
        responseStream.assumeIsolated { $0.onProtocolUpgrade = { [weak self] in
            self?.assumeIsolated { $0.handleResponseUpgrade() }
        } }
        requestStream.assumeIsolated { $0.onFatalClose = { [weak self] in
            self?.post(.cancel(reason: nil))
        } }
        responseStream.assumeIsolated { $0.onFatalClose = { [weak self] in
            self?.post(.failInnerLegWith502(reason: "rejected a malformed or oversized upstream response"))
        } }
        let hardClose: @Sendable () -> Void = { [weak self] in
            self?.post(.cancel(reason: nil))
        }
        requestStream.assumeIsolated { $0.onHardClose = hardClose }
        responseStream.assumeIsolated { $0.onHardClose = hardClose }
    }

    private func startPlaintext() {
        let inner = PlaintextLeg(transport: innerTransport)
        if !pendingClientBytes.isEmpty {
            inner.prependToReceiveBuffer(pendingClientBytes)
            pendingClientBytes.removeAll(keepingCapacity: false)
        }
        innerRecord = inner
        startInboundPump(inner: inner)
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

    func clientDidClose() {
        guard !torn else { return }
        if innerRecord != nil {
            innerTransport.endOfClient()
        } else {
            cancel(error: nil)
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
        deferredActionContinuation.finish()
        deferredActionsTask = nil
        onTeardown?(error)
    }

    // MARK: - Inner Handshake

    private func startInnerHandshake(sni: String, alpns: [String], tlsVersions: Set<UInt16>) {
        guard let leafCache else { cancel(error: nil); return }
        // Actor-isolated task: the leaf mint resumes on the actor (lwIP queue), so `torn` and the
        // handshake state are plain isolated accesses.
        Task {
            do {
                let leaf = try await leafCache.leaf(for: sni)
                guard !torn else { return }
                beginInnerHandshake(with: leaf, alpns: alpns, tlsVersions: tlsVersions)
            } catch {
                guard !torn else { return }
                cancel(error: error)
            }
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

    // MARK: - Outer Handshake (deferred)
    
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
        Task {
            do {
                let record = try await client.connect(overTunnel: connection)
                // Resumes on the actor (lwIP queue).
                guard disarm() else { record.cancel(); connection.cancel(); return }
                guard !torn, let inner = innerRecord else {
                    // Handshake won the timeout race but the session was already torn down; cancel the
                    // freshly-minted record too, not just the socket.
                    record.cancel(); connection.cancel(); return
                }
                // We offered only http/1.1, so the peer must answer http/1.1 or no ALPN; anything
                // else can't be shuttled h1↔h1.
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
                // A cert-validation failure is a security signal: a 502 over the trusted inner leg
                // would render as a padlocked error page and mask the origin's invalid cert. Tear
                // down instead so the client surfaces a connection failure.
                if Self.isCertVerifyFailure(error) {
                    logger.warning("[MITM] \(dstHost): upstream certificate validation failed (\(AnywhereError.describe(error))); closing rather than masking as a 502")
                    cancel(error: nil)
                } else {
                    failInnerLegWith502("upstream connect failed: \(AnywhereError.describe(error))")
                }
            }
        }
    }

    /// True for an upstream TLS certificate-validation failure (vs a transport/timeout failure),
    /// so the deferred-dial paths can reset instead of answering a trusted-looking 502.
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
        startOutboundPump(inner: inner, outer: outer)
        if inboundReadPaused {
            inboundReadPaused = false
            startInboundPump(inner: inner)
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
        Task { [weak self] in
            do { try await pending.value() }
            catch { self?.post(.cancel(reason: error)) }
        }
    }
    
    private func sendChunkedThenCancel(_ data: Data, via record: any MITMByteLeg) {
        guard !torn else { return }
        let pending = sender(for: record).submit {
            try await Self.drainChunked(data, over: record, chunkSize: Self.pumpChunkSize)
        }
        Task { [weak self] in
            _ = try? await pending.value()
            self?.post(.cancel(reason: nil))
        }
    }
    
    private func startInboundPump(inner: any MITMByteLeg) {
        Task {
            let data: Data?
            let error: Error?
            do { data = try await inner.receive(); error = nil }
            catch let e { data = nil; error = e }
            if let error {
                guard !torn else { return }
                cancel(error: error)
                return
            }
            guard let data, !data.isEmpty else {
                return
            }
            let transformed = await inbound.feed(data)
            await routeInbound(inner: inner, transformed: transformed)
        }
    }
    
    private func routeInbound(inner: any MITMByteLeg, transformed: Data) async {
        enum Route { case stop, recurse, sendUpstream(any MITMByteLeg) }
        let route: Route
        if torn {
            route = .stop
        } else {
            let injected = inbound.drainPendingClientBytes()
            if !injected.isEmpty {
                sendChunkedCancellingOnError(injected, via: inner)
            }
            if transformed.isEmpty {
                route = .recurse
            } else if let outer = outerRecord {
                if resolvedUpstreamMatchesDialed() {
                    route = .sendUpstream(outer)
                } else {
                    if canReconnectOuterLeg() {
                        reconnectOuterLeg(with: transformed, inner: inner)
                    } else {
                        logger.warning("\(dstHost): request resolved a different upstream while the leg was busy; tearing down so the client retries")
                        cancel(error: nil)
                    }
                    route = .stop
                }
            } else {
                bufferUpstreamAndDial(transformed, inner: inner)
                route = .stop
            }
        }
        switch route {
        case .stop:
            return
        case .recurse:
            startInboundPump(inner: inner)
        case .sendUpstream(let outer):
            do {
                try await sendChunked(transformed, via: outer)
            } catch {
                guard !torn else { return }
                cancel(error: error)
                return
            }
            startInboundPump(inner: inner)
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
        let dialer = self.dialer
        Task {
            do {
                let dial = try await dialer(host, port)
                // Resumes on the actor (lwIP queue).
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
        resumeOrPauseInboundPreDial(inner: inner)
    }
    
    private func resumeOrPauseInboundPreDial(inner: any MITMByteLeg) {
        if pendingUpstreamBytes.count >= Self.maxPendingClientBytes {
            inboundReadPaused = true
        } else {
            startInboundPump(inner: inner)
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

    /// One-shot winner gate for the deferred-handshake race, shared by the deadline hop and the
    /// disarm closure.
    private final class HandshakeRaceGate: Sendable {
        private let settled = Atomic(false)
        func claim() -> Bool {
            settled.compareExchange(expected: false, desired: true, ordering: .relaxed).exchanged
        }
    }

    /// Bounds a deferred upstream TLS handshake. The per-connection `handshakeTimer` is cancelled once
    /// the session takes over the inner handshake, so the outer handshake would otherwise have only the
    /// 300–600 s idle timer, letting a black-holing origin park the connection for minutes. The deadline
    /// is a cancellable `Task`+`Task.sleep`; the returned `disarm` closure — called on lwipQueue by the
    /// completion — returns `true` if the handshake won the race, `false` if the timeout already fired
    /// (``HandshakeRaceGate/claim`` picks the single winner).
    private func armUpstreamHandshakeTimeout(_ onTimeout: @escaping @Sendable () -> Void) -> () -> Bool {
        let gate = HandshakeRaceGate()
        // No `self`: the gate picks the single winner and `onTimeout` hops onto the actor itself
        // (and its handler re-guards `torn`), so the timer task carries no isolated state.
        let task = Task {
            try? await Task.sleep(for: .seconds(TunnelConstants.handshakeTimeout))
            guard !Task.isCancelled, gate.claim() else { return }
            onTimeout()
        }
        return { [gate, task] in
            guard gate.claim() else { return false }
            task.cancel()
            return true
        }
    }

    /// Answers the HTTP/1.1 client with a 502 over the established inner leg, then closes gracefully.
    /// Used when the deferred upstream dial/handshake fails or the response stream rejects a malformed
    /// / oversized upstream response, instead of a bare TCP reset that hides the cause. h1 inner only;
    /// an h2 inner leg uses `failPendingBridgeRequests` / `failStream`.
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

    /// 101/CONNECT-2xx: flips the request leg to passthrough and flushes its buffer. HTTP/1 only.
    private func handleResponseUpgrade() {
        guard !torn else { return }
        let buffered = requestStream.assumeIsolated { $0.forcePassthrough() }
        guard !buffered.isEmpty, let outer = outerRecord else { return }
        sendChunkedCancellingOnError(buffered, via: outer)
    }

    private func startOutboundPump(inner: any MITMByteLeg, outer: any MITMByteLeg) {
        Task {
            let data: Data?
            let error: Error?
            do { data = try await outer.receive(); error = nil }
            catch let e { data = nil; error = e }
            // Resumes on the actor. A swapped-out leg (host-change reconnect) is ignored so its EOF
            // can't tear down the session or the replacement leg.
            enum Step { case stop, eof, feed(Data) }
            let step: Step
            if outerRecord !== outer {
                step = .stop
            } else if let error {
                cancel(error: error)
                step = .stop
            } else if let data, !data.isEmpty {
                step = .feed(data)
            } else {
                step = .eof
            }
            switch step {
            case .stop:
                return
            case .eof:
                // Upstream half-closed: an HTTP/1 close terminates the body, so flush buffered rewrites.
                let flushed = await responseStream.finish()
                guard !torn else { return }
                if flushed.isEmpty {
                    cancel(error: nil)
                } else {
                    sendChunkedThenCancel(flushed, via: inner)
                }
            case .feed(let data):
                let transformed = await outbound.feed(data)
                if transformed.isEmpty {
                    // Torn resumes the parked continuation via markTorn; recurse re-checks state.
                    startOutboundPump(inner: inner, outer: outer)
                    return
                }
                do {
                    try await sendChunked(transformed, via: inner)
                } catch {
                    guard !torn else { return }
                    cancel(error: error)
                    return
                }
                startOutboundPump(inner: inner, outer: outer)
            }
        }
    }
}

// MARK: - TLSServerDelegate

extension MITMSession: TLSServerDelegate {

    // `TLSServer` is a nonisolated collaborator that invokes these synchronously from `feed(_:)`,
    // which the session drives on the lwIP queue — so the conformance is `nonisolated` and enters
    // the actor's isolation through `assumeIsolated`.

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
        onSendToClient?(data)
    }

    private func completeInnerHandshake(record: TLSRecordConnection, trailer: Data) {
        // The inner leg's byte transport is the lwIP-attached async-native `InnerTransport`.
        record.adoptTransport(innerTransport)
        record.prependToReceiveBuffer(trailer)
        innerRecord = record
        tlsServer = nil

        // An h2 client decodes into neutral request IR via the decoupled client leg; the upstream leg
        // (h2 or http/1.1) is bound after the first dial. An h1.1 client uses the byte-shuttle below.
        if record.negotiatedALPN == "h2" {
            let client = MITMBridgeClientLeg(
                host: dstHost,
                rewriter: h2Rewriter,
                flowController: h2FlowController,
                lwipBridge: lwipBridge
            )
            // The leg shares this actor's lwIP executor, so enter its isolation synchronously to
            // wire the delegate before it's published.
            client.assumeIsolated { $0.delegate = self }
            bridgeClient = client
            startBridgeInboundPump(inner: record)
            return
        }

        startInboundPump(inner: record)
    }

    nonisolated func tlsServer(_ server: TLSServer, didFail error: AnywhereError) {
        assumeIsolated { $0.cancel(error: error) }
    }
}

// MARK: - h2 → http/1.1 bridge

extension MITMSession: MITMBridgeClientLegDelegate {

    /// Pumps client plaintext into the bridge client leg; the leg drives per-stream
    /// upstream dials and client-bound writes via the delegate callbacks below. Actor-isolated task.
    private func startBridgeInboundPump(inner: TLSRecordConnection) {
        Task {
            let data: Data?
            let error: Error?
            do { data = try await inner.receive(); error = nil }
            catch let e { data = nil; error = e }
            // Resumes on the actor.
            if torn { return }
            if let error { cancel(error: error); return }
            guard let data, !data.isEmpty, let client = bridgeClient else {
                // Client half-closed (FIN): stop reading frames but keep in-flight response
                // streams draining to the client; teardown follows on the upstream's EOF or the
                // connection's downlink-only idle timeout, matching the non-MITM path.
                return
            }
            await client.feed(data)
            startBridgeInboundPump(inner: inner)
        }
    }

    // `MITMBridgeClientLeg` is a nonisolated collaborator that invokes these synchronously on the
    // lwIP queue, so each conformance method is a `nonisolated` shim entering via `assumeIsolated`.

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
            // h1 request trailers require chunked framing and are seldom honored upstream; end the body
            // without them rather than risk a malformed chunked trailer section.
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
        // h1: close the per-stream upstream (close-after-response). h2: the multiplexed connection
        // persists for other streams.
        if upstreamProtocol == .h1 { bridgeAbortStream(streamID) }
    }

    // MARK: First dial (protocol probe) + late binding

    /// Dials once on the first request, offering both ALPNs; the upstream leg is bound
    /// from the negotiated protocol.
    private func startFirstUpstreamDial() {
        guard !firstUpstreamDialStarted else { return }
        firstUpstreamDialStarted = true
        // Dial target from the first pending head (captured at its own rewrite time), not the
        // rewriter's shared last-write-wins field — keeps the probe consistent with that request's
        // `:authority` even if a later stream rewrote to a different host meanwhile.
        let firstHead = pendingRequestEvents.lazy.compactMap { event -> MITMRequestHead? in
            if case .head(let head, _, _) = event { return head }
            return nil
        }.first
        let resolved = firstHead?.resolvedUpstream
        let host = resolved?.host ?? dstHost
        let port = resolved?.port ?? dstPort
        let dialer = self.dialer
        Task {
            do {
                let dial = try await dialer(host, port)
                guard !torn else { dial.connection.cancel(); await dial.proxyClient?.cancel(); return }
                sharedUpstreamProxyClient = dial.proxyClient
                sharedUpstreamConnection = dial.connection
                startFirstUpstreamHandshake(host: host, connection: dial.connection)
            } catch {
                guard !torn else { return }
                failPendingBridgeRequests(error: error)
            }
        }
    }

    /// First upstream dial/handshake failed (the protocol probe all pending streams share). Answer
    /// every pending stream with a 502 and keep the h2 client connection up, resetting dial state so a
    /// later request re-probes, rather than tear the whole multiplexed connection down for a possibly
    /// transient failure.
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
        let configuration = TLSConfiguration(
            serverName: host,
            alpn: ["h2", "http/1.1"],
            minVersion: .tls12,
            maxVersion: .tls13, // upstream TLS leg is independent of the client leg — don't cap it to the client's version
            fingerprint: .nonBrowser
        )
        let client = TLSClient(configuration: configuration)
        sharedUpstreamTLSClient = client
        let disarm = armUpstreamHandshakeTimeout { [weak self] in
            self?.post(.failPendingBridgeRequests(reason: AnywhereError.mitm(.upstreamHandshakeTimeout)))
        }
        Task {
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
                // A cert-validation failure is a security signal: a 502 over the trusted inner leg
                // renders as a padlocked error page and masks the origin's invalid cert. Tear down
                // so the client surfaces a connection failure; a transient failure still 502s and
                // re-probes.
                if Self.isCertVerifyFailure(error) {
                    logger.warning("[MITM] \(dstHost): upstream certificate validation failed (\(AnywhereError.describe(error))); closing rather than masking as a 502")
                    cancel(error: nil)
                } else {
                    failPendingBridgeRequests(error: error)
                }
            }
        }
    }

    private func bindH2Upstream(record: TLSRecordConnection) {
        upstreamProtocol = .h2
        let leg = MITMHTTP2UpstreamLeg(host: dstHost, rewriter: h2Rewriter, flowController: h2FlowController, lwipBridge: lwipBridge)
        h2Upstream = leg
        // Drain-coupled backpressure: as response bytes reach the client, credit the upstream's
        // per-stream receive window so a slow client throttles the origin (h2 only).
        // The leg shares this actor's executor; enter its isolation to wire the callback/flag.
        bridgeClient?.assumeIsolated { leg in
            leg.onResponseDrainedToClient = { [weak self] clientStreamID, n in
                // Runs on the lwIP queue (the client leg drains there) = the actor's executor.
                self?.assumeIsolated { $0.h2Upstream?.assumeIsolated { $0.creditDrainedResponse(clientID: clientStreamID, n) } }
            }
            // Upload mirror of the response drain-coupling above: as the origin accepts request DATA,
            // credit the client's upload window by the same amount so a slow origin backpressures the
            // client. Streams opened from here on are drain-coupled; the first (probe) request stays eager.
            leg.uploadDrainCoupled = true
        }
        let events = pendingRequestEvents
        pendingRequestEvents.removeAll()
        // Read the session-isolated collaborators into locals before entering the leg's isolation
        // (the closure below is isolated to the leg, a distinct domain on the same executor).
        let client = bridgeClient
        let rewriter = h2Rewriter
        // The leg is an actor on this same lwIP executor and we are already on the queue, so enter
        // its isolation synchronously to wire up its sink/callbacks and replay the buffered events.
        leg.assumeIsolated { legSelf in
            legSelf.sink = client
            // These leg callbacks fire on the lwIP queue = the actor's executor, so each enters the
            // session's isolation synchronously via `assumeIsolated`; `onFatalError` defers a teardown.
            legSelf.onRequestDrainedToUpstream = { [weak self] clientStreamID, n in
                self?.assumeIsolated { me in me.bridgeClient?.assumeIsolated { $0.creditUploadDrained(clientStreamID, n) } }
            }
            legSelf.onUpstreamBytes = { [weak self] bytes in
                self?.assumeIsolated { me in
                    guard !me.torn, !bytes.isEmpty else { return }
                    me.sendChunkedCancellingOnError(bytes, via: record)
                }
            }
            legSelf.onFatalError = { [weak self] _ in
                self?.post(.cancel(reason: nil))
            }
            // Origin GOAWAY: tell the client we're draining (NO_ERROR — per-stream failures use RST,
            // not this connection-level frame) so it redials new streams while in-flight ones finish.
            legSelf.onDraining = { [weak self] in
                self?.assumeIsolated { me in me.bridgeClient?.assumeIsolated { $0.sendGoAwayToClient(code: MITMHTTP2FrameCodec.ErrorCode.noError) } }
            }
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
        startH2UpstreamPump(record: record)
    }

    private func startH2UpstreamPump(record: TLSRecordConnection) {
        Task {
            let data: Data?
            let error: Error?
            do { data = try await record.receive(); error = nil }
            catch let e { data = nil; error = e }
            // Resumes on the actor.
            guard !torn, let leg = h2Upstream else { return }
            if let error { cancel(error: error); return }
            guard let data, !data.isEmpty else { cancel(error: nil); return }
            await leg.feed(data)
            startH2UpstreamPump(record: record)
        }
    }

    private func bindH1Upstream() {
        upstreamProtocol = .h1
        logger.info("\(dstHost): bridging h2 client to http/1.1 upstream")
        // The shared connection is reused by the first stream in openH1Stream.
        let events = pendingRequestEvents
        pendingRequestEvents.removeAll()
        for event in events {
            switch event {
            case .head(let head, let url, _):
                openH1Stream(head, url: url)
            case .data(let streamID, let data, let endStream):
                appendH1RequestData(streamID: streamID, data, endStream: endStream)
            case .trailers(let streamID, _):
                // h1 can't carry request trailers; end the body without them.
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
            scriptEngineProvider: scriptEngineProvider, requestLog: responseLog, lwipBridge: lwipBridge
        )
        // A malformed / oversized upstream response fails just this stream (RST), not the whole
        // multiplexed h2 connection. The stream shares this actor's executor; enter its isolation.
        responseStream.assumeIsolated { $0.onFatalClose = { [weak self] in
            self?.post(.abortBridgeStream(streamID: streamID, acceptResponseAborted: true))
        } }
        let bs = BridgeStream(clientStreamID: streamID, responseStream: responseStream, responseLog: responseLog)
        let irSink = BridgeResponseIRSink(streamID: streamID, client: bridgeClient) { [weak self] sid in
            // RST the client stream now (fires on the lwIP queue = the actor's executor); free the
            // dead h1 upstream after the current `transform` returns via the deferred-action channel.
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
            // Reuse the established probe connection for the first stream.
            sharedUpstreamRecord = nil
            bs.proxyClient = sharedUpstreamProxyClient; sharedUpstreamProxyClient = nil
            bs.connection = sharedUpstreamConnection; sharedUpstreamConnection = nil
            bs.tlsClient = sharedUpstreamTLSClient; sharedUpstreamTLSClient = nil
            bs.upstreamRecord = record
            bs.handshakeDone = true
            let pending = bs.pendingToUpstream; bs.pendingToUpstream = Data()
            flushToBridgeUpstream(pending, streamID: streamID, record: record)
            startBridgeUpstreamPump(streamID: streamID)
            return
        }

        // Per-stream dial target from the head (`MITMRequestHead.resolvedUpstream`), captured at this
        // request's own rewrite time, not the rewriter's shared last-write-wins field — a request
        // buffered for a body script/rule dials after an async hop a concurrent stream could overwrite.
        let resolved = head.resolvedUpstream
        let host = resolved?.host ?? dstHost
        let port = resolved?.port ?? dstPort
        let dialer = self.dialer
        Task {
            do {
                let dial = try await dialer(host, port)
                guard !torn, let bs = bridgeStreams[streamID] else {
                    dial.connection.cancel(); await dial.proxyClient?.cancel(); return
                }
                bs.proxyClient = dial.proxyClient
                bs.connection = dial.connection
                startBridgeUpstreamHandshake(streamID: streamID, host: host)
            } catch {
                guard !torn else { return }
                // Inner leg is up; answer the stream with a 502 rather than a bare RST_STREAM that
                // hides a transient upstream-connect failure.
                logger.warning("\(dstHost): h1 upstream dial failed for stream \(streamID): \(AnywhereError.describe(error))")
                bridgeAbortStream(streamID)
                await bridgeClient?.failStream(streamID: streamID, status: 502, message: "Bad Gateway")
            }
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
        Task { [weak self] in
            var sendError: Error?
            do { try await pending.value() } catch { sendError = error }
            self?.post(.bridgeUpstreamDrained(streamID: streamID, count: count, sendError: sendError))
        }
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

    /// Deferred abort of a bridge stream, hopped onto the actor from a stream hook. When
    /// `acceptResponseAborted` is set it also notifies the client leg (response-fatal path).
    private func abortBridgeStream(_ streamID: UInt32, acceptResponseAborted: Bool) {
        bridgeAbortStream(streamID)
        if acceptResponseAborted { bridgeClient?.assumeIsolated { $0.acceptResponseAborted(streamID: streamID) } }
    }

    /// Per-stream upstream TLS handshake (offers only http/1.1 — the origin is known h1).
    private func startBridgeUpstreamHandshake(streamID: UInt32, host: String) {
        guard let bs = bridgeStreams[streamID], let connection = bs.connection else { return }
        let configuration = TLSConfiguration(
            serverName: host,
            alpn: ["http/1.1"],
            minVersion: .tls12,
            maxVersion: .tls13, // upstream TLS leg is independent of the client leg — don't cap it to the client's version
            fingerprint: .nonBrowser
        )
        let client = TLSClient(configuration: configuration)
        bs.tlsClient = client
        let disarm = armUpstreamHandshakeTimeout { [weak self] in
            self?.post(.failBridgeStreamOnTimeout(streamID: streamID))
        }
        Task {
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
                startBridgeUpstreamPump(streamID: streamID)
            } catch {
                guard disarm() else { connection.cancel(); return }
                guard !torn else { return }
                // A cert-validation failure is host-level (the origin's cert is invalid for every
                // stream to it): a 502 over the trusted inner leg would mask it as a padlocked page,
                // so tear the connection down. A transient TLS/transport failure still 502s this
                // stream instead of a bare RST.
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
    }

    /// Answers a bridge stream 502 after its per-stream upstream handshake timed out.
    private func failBridgeStreamOnTimeout(_ streamID: UInt32) {
        guard !torn else { return }
        logger.warning("\(dstHost): bridge upstream TLS timed out for stream \(streamID); answering 502")
        bridgeAbortStream(streamID)
        bridgeClient?.assumeIsolated { $0.failStream(streamID: streamID, status: 502, message: "Bad Gateway") }
    }

    /// Reads the upstream response, runs it through the per-stream response rewriter,
    /// and hands the rewritten http/1.1 bytes to the client leg to re-encode as h2.
    private func startBridgeUpstreamPump(streamID: UInt32) {
        guard let record = bridgeStreams[streamID]?.upstreamRecord else { return }
        Task {
            let data: Data?
            let error: Error?
            do { data = try await record.receive(); error = nil }
            catch let e { data = nil; error = e }
            // Resumes on the actor.
            enum Step { case stop, eof(MITMHTTP1Stream), transform(MITMHTTP1Stream, Data) }
            let step: Step
            if torn {
                step = .stop
            } else if let bs = bridgeStreams[streamID], let client = bridgeClient {
                if let error {
                    logger.warning("\(dstHost): bridge upstream read error for stream \(streamID): \(AnywhereError.describe(error))")
                    await client.acceptResponseAborted(streamID: streamID)
                    bridgeAbortStream(streamID) // a reset doesn't notify us; free the dead upstream
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
                // Upstream half-closed: a read-until-close body terminates here, so flush the buffered
                // remainder first, then signal EOF (the IR end / reset was delivered via the sink).
                _ = await responseStream.finish()
                guard !torn else { return }
                // A clean completion already closed the upstream (clientLegResponseComplete);
                // otherwise drop the now-dead upstream rather than pin it until teardown.
                if bridgeStreams[streamID] != nil { bridgeAbortStream(streamID) }
            case .transform(let responseStream, let data):
                // The rewritten response is delivered as IR via the sink during `transform`; it may
                // complete and close this stream's upstream.
                _ = await responseStream.transform(data)
                guard !torn else { return }
                guard bridgeStreams[streamID] != nil else { return }
                startBridgeUpstreamPump(streamID: streamID)
            }
        }
    }
}
