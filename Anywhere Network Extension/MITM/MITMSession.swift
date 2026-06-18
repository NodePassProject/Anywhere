//
//  MITMSession.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITMSession")

struct MITMDialResult {
    let connection: ProxyConnection
    /// nil for a direct connection; the session owns its lifetime.
    let proxyClient: ProxyClient?
}

/// Dials the upstream once the first request resolves host/port; completion runs on the lwIP queue.
typealias MITMDialer = (
    _ host: String,
    _ port: UInt16,
    _ completion: @escaping (Result<MITMDialResult, Error>) -> Void
) -> Void

final class MITMSession {

    // MARK: - Inner Transport (RawTransport adapter for the lwIP side)

    /// Bidirectional pipe between the inner-leg TLS record connection and the lwIP-attached caller.
    final class InnerTransport: RawTransport {
        let queue: DispatchQueue
        var onSendToClient: ((Data, ((Error?) -> Void)?) -> Void)?

        private let lock = UnfairLock()
        private var buffer = Data()
        private var pending: ((Data?, Bool, Error?) -> Void)?
        private var closed = false

        var isTransportReady: Bool { !closed }

        init(queue: DispatchQueue) {
            self.queue = queue
        }

        // MARK: RawTransport

        func send(data: Data, completion: @escaping (Error?) -> Void) {
            queue.async { [self] in
                guard !closed else {
                    completion(SocketError.notConnected)
                    return
                }
                if let onSendToClient {
                    onSendToClient(data, completion)
                } else {
                    completion(nil)
                }
            }
        }

        func send(data: Data) {
            queue.async { [self] in
                guard !closed else { return }
                onSendToClient?(data, nil)
            }
        }

        func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
            lock.lock()
            if !buffer.isEmpty {
                let data = buffer
                buffer = Data()
                lock.unlock()
                completion(data, false, nil)
                return
            }
            if closed {
                lock.unlock()
                completion(nil, true, nil)
                return
            }
            pending = completion
            lock.unlock()
        }

        func forceCancel() {
            lock.lock()
            closed = true
            let cb = pending
            pending = nil
            buffer = Data()
            lock.unlock()
            cb?(nil, true, nil)
        }

        // MARK: External Inputs

        func feedFromClient(_ data: Data) {
            lock.lock()
            if closed {
                lock.unlock()
                return
            }
            if let cb = pending {
                pending = nil
                lock.unlock()
                cb(data, false, nil)
                return
            }
            buffer.append(data)
            lock.unlock()
        }

        func endOfClient() {
            lock.lock()
            closed = true
            let cb = pending
            pending = nil
            let pendingBuffer = buffer
            buffer = Data()
            lock.unlock()
            if let cb {
                if pendingBuffer.isEmpty {
                    cb(nil, true, nil)
                } else {
                    cb(pendingBuffer, true, nil)
                }
            }
        }
    }

    // MARK: - Properties

    private let dstHost: String
    private let dstPort: UInt16
    private let lwipQueue: DispatchQueue

    private let leafCache: MITMLeafCertCache
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

    /// Post-handshake record connections; decrypted plaintext stays inside the session.
    private var innerRecord: TLSRecordConnection?
    private var outerRecord: TLSRecordConnection?

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

    /// Adapts a per-stream response stream's IR to the client leg's sink, tagging each event with the
    /// client stream ID.
    private final class BridgeResponseIRSink: MITMHTTP1ResponseIRSink {
        let streamID: UInt32
        weak var client: MITMBridgeClientLeg?
        let onReset: (UInt32) -> Void
        init(streamID: UInt32, client: MITMBridgeClientLeg?, onReset: @escaping (UInt32) -> Void) {
            self.streamID = streamID
            self.client = client
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

    /// Set by the lwIP-side caller to write inner-leg bytes back to the client.
    var onSendToClient: ((Data, ((Error?) -> Void)?) -> Void)? {
        didSet { innerTransport.onSendToClient = onSendToClient }
    }

    /// Called on teardown; `error` is nil for a clean close.
    var onTeardown: ((Error?) -> Void)?

    // MARK: - Init

    init(
        dstHost: String,
        dstPort: UInt16,
        clientHello: Data,
        leafCache: MITMLeafCertCache,
        policy: MITMRewritePolicy,
        dialer: @escaping MITMDialer,
        lwipQueue: DispatchQueue
    ) {
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.pendingClientBytes = clientHello
        self.leafCache = leafCache
        self.policy = policy
        self.dialer = dialer
        self.lwipQueue = lwipQueue
        self.innerTransport = InnerTransport(queue: lwipQueue)
        // Keyed by the matched set's id so it lines up with the Anywhere.store scope.
        self.scriptEngineProvider = MITMScriptEngine.Provider(scope: policy.set(for: dstHost)?.id)
        // effectiveAuthority is late-bound by a transparent rewrite on the first request.
        self.requestStream = MITMHTTP1Stream(
            host: dstHost,
            phase: .httpRequest,
            policy: policy,
            effectiveAuthority: nil,
            scriptEngineProvider: scriptEngineProvider,
            requestLog: requestLog,
            lwipQueue: lwipQueue
        )
        self.responseStream = MITMHTTP1Stream(
            host: dstHost,
            phase: .httpResponse,
            policy: policy,
            effectiveAuthority: nil, // Host headers do not apply on responses.
            scriptEngineProvider: scriptEngineProvider,
            requestLog: requestLog,
            lwipQueue: lwipQueue
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

    /// Starts the inner-leg TLS handshake; the upstream dial is deferred until
    /// the first request resolves the destination. Must be called on lwipQueue.
    func start(sni: String) {
        responseStream.onProtocolUpgrade = { [weak self] in
            self?.handleResponseUpgrade()
        }
        // Fail closed on a smuggling/injection head or over-cap body (deferred off the parse pass to
        // avoid re-entrant teardown). The request direction can't cleanly answer the client so it just
        // closes; the response direction answers a 502 first.
        requestStream.onFatalClose = { [weak self] in
            self?.lwipQueue.async { self?.cancel(error: nil) }
        }
        responseStream.onFatalClose = { [weak self] in
            self?.lwipQueue.async { self?.failInnerLegWith502("rejected a malformed or oversized upstream response") }
        }
        // Mid-body chunked framing breakage (head already on the wire): tear down both legs. A 502
        // can't be written over an in-flight response, and a synthesized terminator would frame a
        // truncated body as complete and desync the peer.
        let hardClose: () -> Void = { [weak self] in
            self?.lwipQueue.async { self?.cancel(error: nil) }
        }
        requestStream.onHardClose = hardClose
        responseStream.onHardClose = hardClose
        let parsed = parseClientHello(pendingClientBytes)
        let clientALPNs = parsed?.alpnProtocols ?? []
        // Unparseable ClientHello fails closed to TLS 1.2; any 1.3-capable client also speaks 1.2.
        clientSupportsTLS13 = parsed?.supportedVersions.contains(0x0304) ?? false
        startInnerHandshakeFromClientOffer(
            sni: sni,
            clientALPNs: clientALPNs,
            clientSupportsTLS13: clientSupportsTLS13
        )
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
        // Best-effort GOAWAY to an h2 client before suppressing writes (`torn`) so it learns the last
        // processed stream and can retry (RFC 9113 §6.8). Idempotent; nil-safe for an h1 inner leg or
        // pre-handshake teardown.
        bridgeClient?.sendGoAwayToClient(code: MITMHTTP2FrameCodec.ErrorCode.internalError)
        torn = true
        // Disarm in-flight script resumes before they can write to torn legs.
        requestStream.markTorn()
        responseStream.markTorn()
        bridgeClient?.markTorn()
        bridgeClient = nil
        h2Upstream?.markTorn()
        h2Upstream = nil
        for bs in bridgeStreams.values {
            bs.tlsClient?.cancel()
            bs.connection?.cancel()
            bs.proxyClient?.cancel()
            bs.upstreamRecord?.cancel()
            bs.responseStream.markTorn()
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
        // outerConnection covers the pre-handshake race window; cancel() is idempotent.
        outerConnection?.cancel()
        outerConnection = nil
        proxyClient?.cancel()
        proxyClient = nil
        pendingUpstreamBytes = Data()
        legSenders.removeAll()
        innerTransport.forceCancel()
        onTeardown?(error)
    }

    // MARK: - Inner Handshake

    private func startInnerHandshake(sni: String, alpns: [String], tlsVersions: Set<UInt16>) {
        do {
            let leaf = try leafCache.leaf(for: sni)
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
        } catch {
            cancel(error: error)
        }
    }

    /// Picks ALPN and TLS versions from the client's offer (h2 / http/1.1, intersected).
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

    /// Outer handshake for an HTTP/1.1 *inner* leg (h2 inner uses the decoupled bridge dial).
    /// Offers http/1.1; on success shuttles h1↔h1.
    private func startOuterHandshakeAfterDial(
        over connection: ProxyConnection,
        host: String,
        innerALPN: String
    ) {
        // .nonBrowser: a browser fingerprint's ALPS trips strict origins (Google GFE) into fatal unexpected_message.
        let configuration = TLSConfiguration(
            serverName: host,
            alpn: [innerALPN],
            minVersion: .tls12,
            maxVersion: .tls13, // upstream TLS leg is independent of the client leg — don't cap it to the client's version
            fingerprint: .nonBrowser
        )
        let client = TLSClient(configuration: configuration)
        tlsClient = client
        let disarm = armUpstreamHandshakeTimeout { [weak self] in
            self?.failInnerLegWith502("upstream TLS handshake timed out")
        }
        client.connect(overTunnel: connection) { [weak self] result in
            guard let self else { return }
            self.lwipQueue.async {
                guard disarm() else {
                    if case .success(let record) = result { record.cancel() }
                    connection.cancel()
                    return
                }
                guard !self.torn, let inner = self.innerRecord else {
                    // Handshake won the timeout race but the session was already torn down; cancel the
                    // freshly-minted record too, not just the socket.
                    if case .success(let record) = result { record.cancel() }
                    connection.cancel()
                    return
                }
                switch result {
                case .success(let record):
                    // We offered only http/1.1, so the peer must answer http/1.1 or no ALPN; anything
                    // else can't be shuttled h1↔h1.
                    guard record.negotiatedALPN.isEmpty || record.negotiatedALPN == "http/1.1" else {
                        logger.warning("\(self.dstHost): unexpected upstream ALPN \"\(record.negotiatedALPN)\" for an http/1.1 leg; tearing down")
                        self.cancel(error: nil)
                        return
                    }
                    self.outerRecord = record
                    self.finishDialAndShuttle(inner: inner, outer: record)
                case .failure(let error):
                    // A cert-validation failure is a security signal: a 502 over the trusted inner leg
                    // would render as a padlocked error page and mask the origin's invalid cert. Tear
                    // down instead so the client surfaces a connection failure.
                    if Self.isCertVerifyFailure(error) {
                        logger.warning("[MITM] \(self.dstHost): upstream certificate validation failed (\(error)); closing rather than masking as a 502")
                        self.cancel(error: nil)
                    } else {
                        self.failInnerLegWith502("upstream connect failed: \(error)")
                    }
                }
            }
        }
    }

    /// True for an upstream TLS certificate-validation failure (vs a transport/timeout failure),
    /// so the deferred-dial paths can reset instead of answering a trusted-looking 502.
    private static func isCertVerifyFailure(_ error: Error) -> Bool {
        if case TLSError.certificateValidationFailed = error { return true }
        return false
    }

    // MARK: - ClientHello parsing

    private func parseClientHello(_ buffer: Data) -> TLSClientHelloParsed? {
        guard !buffer.isEmpty else { return nil }
        return try? TLSClientHelloParser.parse(buffer)
    }

    // MARK: - Shuttle

    /// Completes the h1↔h1 dial: flushes the buffered first request, starts the outbound pump.
    private func finishDialAndShuttle(inner: TLSRecordConnection, outer: TLSRecordConnection) {
        // Flush the buffered first request before the inbound pump forwards new ones.
        let buffered = pendingUpstreamBytes
        pendingUpstreamBytes = Data()
        if !buffered.isEmpty {
            sendChunked(buffered, via: outer) { [weak self] sendError in
                guard let self, let sendError else { return }
                self.lwipQueue.async { self.cancel(error: sendError) }
            }
        }
        startOutboundPump(inner: inner, outer: outer)
        // Resume the inbound pump only if backpressure paused it while dialing; if it never paused
        // it's still running, so don't double-start it.
        if inboundReadPaused {
            inboundReadPaused = false
            startInboundPump(inner: inner)
        }
    }

    /// sendChunked chunk size; 64 KiB = 4× the TLS plaintext record cap, bounding in-flight bytes per leg.
    private static let pumpChunkSize: Int = 64 * 1024

    /// Per-leg send serializers, keyed by record identity, created lazily.
    private var legSenders: [ObjectIdentifier: LegSendSerializer] = [:]

    /// Serializes per-leg sends so concurrent callers can't interleave bytes mid-frame. Must be called on lwipQueue.
    private func sendChunked(
        _ data: Data,
        via record: TLSRecordConnection,
        completion: @escaping (Error?) -> Void
    ) {
        let key = ObjectIdentifier(record)
        let sender: LegSendSerializer
        if let existing = legSenders[key] {
            sender = existing
        } else {
            sender = LegSendSerializer(record: record, queue: lwipQueue, chunkSize: Self.pumpChunkSize)
            legSenders[key] = sender
        }
        sender.enqueue(data, completion: completion)
    }

    /// Drains one enqueued blob to completion before the next so concurrent writers
    /// can't split a frame mid-payload. All methods must run on queue.
    private final class LegSendSerializer {
        private let record: TLSRecordConnection
        private let queue: DispatchQueue
        private let chunkSize: Int
        private var pending: [(data: Data, completion: (Error?) -> Void)] = []
        private var sending = false

        init(record: TLSRecordConnection, queue: DispatchQueue, chunkSize: Int) {
            self.record = record
            self.queue = queue
            self.chunkSize = chunkSize
        }

        func enqueue(_ data: Data, completion: @escaping (Error?) -> Void) {
            pending.append((data: data, completion: completion))
            drain()
        }

        private func drain() {
            guard !sending, !pending.isEmpty else { return }
            sending = true
            let next = pending.removeFirst()
            sendSlice(next.data, offset: next.data.startIndex, completion: next.completion)
        }

        private func sendSlice(
            _ data: Data,
            offset: Data.Index,
            completion: @escaping (Error?) -> Void
        ) {
            if offset >= data.endIndex {
                completion(nil)
                finishCurrent()
                return
            }
            let take = min(chunkSize, data.distance(from: offset, to: data.endIndex))
            let chunkEnd = data.index(offset, offsetBy: take)
            // Copy so the encoder sees a contiguous slab.
            let chunk = Data(data[offset..<chunkEnd])
            record.send(data: chunk) { [weak self] error in
                guard let self else {
                    completion(error)
                    return
                }
                self.queue.async {
                    if let error {
                        completion(error)
                        self.finishCurrent()
                        return
                    }
                    self.sendSlice(data, offset: chunkEnd, completion: completion)
                }
            }
        }

        private func finishCurrent() {
            sending = false
            drain()
        }
    }

    /// Pumps client plaintext upstream, or drains synthesized responses back to the client.
    private func startInboundPump(inner: TLSRecordConnection) {
        inner.receive { [weak self] data, error in
            guard let self else { return }
            self.lwipQueue.async {
                if let error {
                    self.cancel(error: error)
                    return
                }
                guard let data, !data.isEmpty else {
                    self.cancel(error: nil)
                    return
                }
                let handle: (Data) -> Void = { [weak self] transformed in
                    guard let self, !self.torn else { return }
                    let injected = self.inbound.drainPendingClientBytes()
                    if !injected.isEmpty {
                        self.sendChunked(injected, via: inner) { [weak self] sendError in
                            guard let self, let sendError else { return }
                            self.lwipQueue.async { self.cancel(error: sendError) }
                        }
                    }
                    guard !transformed.isEmpty else {
                        // Buffered fragment or fully-answered synth.
                        self.startInboundPump(inner: inner)
                        return
                    }
                    if let outer = self.outerRecord {
                        // One outer leg carries one authority. When a later request resolves a
                        // different upstream, reconnect the leg if it's fully idle (so the client sees
                        // no drop); otherwise tear down rather than truncate an in-flight response.
                        guard self.resolvedUpstreamMatchesDialed() else {
                            if self.canReconnectOuterLeg() {
                                self.reconnectOuterLeg(with: transformed, inner: inner)
                            } else {
                                logger.warning("\(self.dstHost): request resolved a different upstream while the leg was busy; tearing down so the client retries")
                                self.cancel(error: nil)
                            }
                            return
                        }
                        self.sendChunked(transformed, via: outer) { [weak self] sendError in
                            guard let self else { return }
                            if let sendError {
                                self.lwipQueue.async { self.cancel(error: sendError) }
                                return
                            }
                            self.startInboundPump(inner: inner)
                        }
                    } else {
                        self.bufferUpstreamAndDial(transformed, inner: inner)
                    }
                }
                self.inbound.feed(data, completion: handle)
            }
        }
    }

    /// Buffers upstream-bound bytes and kicks off the deferred dial; mid-dial calls only buffer.
    private func bufferUpstreamAndDial(_ transformed: Data, inner: TLSRecordConnection) {
        pendingUpstreamBytes.append(transformed)
        // Backstop only — `resumeOrPauseInboundPreDial` backpressures at the high-water mark, so this
        // trips only on a pathological single oversized rewrite, not a large streamed upload.
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
        // A transparent rewrite may have replaced the host/port.
        let resolved = inbound.resolvedUpstream
        let host = resolved?.host ?? dstHost
        let port = resolved?.port ?? dstPort
        dialedHost = host
        dialedPort = port
        let innerALPN = innerRecord?.negotiatedALPN ?? "http/1.1"
        dialer(host, port) { [weak self] result in
            // The dialer hops to lwipQueue before calling back.
            guard let self, !self.torn else {
                if case .success(let dial) = result {
                    dial.connection.cancel()
                    dial.proxyClient?.cancel()
                }
                return
            }
            switch result {
            case .success(let dial):
                self.proxyClient = dial.proxyClient
                self.outerConnection = dial.connection
                self.startOuterHandshakeAfterDial(over: dial.connection, host: host, innerALPN: innerALPN)
            case .failure(let error):
                self.failInnerLegWith502("upstream connect failed: \(error)")
            }
        }
        resumeOrPauseInboundPreDial(inner: inner)
    }

    /// While the dial is in flight, keep reading client bytes until the upstream-bound buffer reaches
    /// the high-water mark, then pause — filling the client's TCP window so a fast local uploader is
    /// throttled instead of buffering an unbounded first-request body. lwipQueue only.
    private func resumeOrPauseInboundPreDial(inner: TLSRecordConnection) {
        if pendingUpstreamBytes.count >= Self.maxPendingClientBytes {
            inboundReadPaused = true
        } else {
            startInboundPump(inner: inner)
        }
    }

    /// False when the current request resolves a different upstream than dialed; always true pre-dial.
    private func resolvedUpstreamMatchesDialed() -> Bool {
        guard let dialedHost, let dialedPort else { return true }
        let resolved = inbound.resolvedUpstream
        return (resolved?.host ?? dstHost) == dialedHost
            && (resolved?.port ?? dstPort) == dialedPort
    }

    /// Whether the outer (h1 upstream) leg can be safely closed and re-dialed for a request that
    /// resolved a different upstream host. Safe only when the leg is fully idle: response stream
    /// between messages and the just-routed request the only one outstanding (`http1InFlightCount == 1`;
    /// higher means an earlier request is still owed a response). Else the caller tears down rather
    /// than truncate an in-flight response.
    static func canSwapOuterLeg(responseBetweenMessages: Bool, http1InFlightCount: Int) -> Bool {
        responseBetweenMessages && http1InFlightCount == 1
    }

    /// Live evaluation of ``canSwapOuterLeg`` against this session's response stream and request log.
    private func canReconnectOuterLeg() -> Bool {
        Self.canSwapOuterLeg(
            responseBetweenMessages: responseStream.isBetweenMessages,
            http1InFlightCount: requestLog.http1InFlightCount
        )
    }

    /// Closes the confirmed-idle outer h1 leg and dials a fresh one for a request that resolved a
    /// different upstream host, keeping the inner (client) leg up so the client sees no drop or retry.
    /// Precondition: ``canReconnectOuterLeg`` returned true. lwipQueue only.
    private func reconnectOuterLeg(with transformed: Data, inner: TLSRecordConnection) {
        logger.info("\(dstHost): later request resolved a new upstream; reconnecting the idle outer leg instead of tearing down")
        // Detach before cancelling: the old outbound pump's `outerRecord === outer` guard then sees a
        // non-matching (nil) record and no-ops its EOF, so cancelling here can't recurse into a full
        // session teardown.
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
        // Reset dial state so `bufferUpstreamAndDial` dials afresh; the request's own
        // `resolvedUpstream` picks the new target.
        dialing = false
        dialedHost = nil
        dialedPort = nil
        pendingUpstreamBytes = Data()
        inboundReadPaused = false
        bufferUpstreamAndDial(transformed, inner: inner)
    }

    /// Error marking a deferred upstream handshake that overran `TunnelConstants.handshakeTimeout`.
    private struct UpstreamHandshakeTimeout: Error, CustomStringConvertible {
        var description: String { "upstream TLS handshake timed out" }
    }

    /// Bounds a deferred upstream TLS handshake. The per-connection `handshakeTimer` is cancelled once
    /// the session takes over the inner handshake, so the outer handshake would otherwise have only the
    /// 300–600 s idle timer, letting a black-holing origin park the connection for minutes. The returned
    /// `disarm` closure must be called by the completion: `true` if the handshake won the race, `false`
    /// if the timeout already fired; first to run wins. lwipQueue only.
    private func armUpstreamHandshakeTimeout(_ onTimeout: @escaping () -> Void) -> () -> Bool {
        var settled = false
        lwipQueue.asyncAfter(deadline: .now() + TunnelConstants.handshakeTimeout) { [weak self] in
            guard let self, !self.torn, !settled else { return }
            settled = true
            onTimeout()
        }
        return {
            if settled { return false }
            settled = true
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
        sendChunked(response, via: inner) { [weak self] _ in
            guard let self else { return }
            self.lwipQueue.async { self.cancel(error: nil) }
        }
    }

    /// 101/CONNECT-2xx: flips the request leg to passthrough and flushes its buffer. HTTP/1 only.
    private func handleResponseUpgrade() {
        guard !torn else { return }
        let buffered = requestStream.forcePassthrough()
        guard !buffered.isEmpty, let outer = outerRecord else { return }
        sendChunked(buffered, via: outer) { [weak self] sendError in
            guard let self, let sendError else { return }
            self.lwipQueue.async { self.cancel(error: sendError) }
        }
    }

    private func startOutboundPump(inner: TLSRecordConnection, outer: TLSRecordConnection) {
        outer.receive { [weak self] data, error in
            guard let self else { return }
            self.lwipQueue.async {
                // If this leg was swapped out (host-change reconnect replaced `outerRecord`), ignore
                // its callbacks so its imminent EOF can't tear down the session or the replacement leg.
                guard self.outerRecord === outer else { return }
                if let error {
                    self.cancel(error: error)
                    return
                }
                guard let data, !data.isEmpty else {
                    // Upstream half-closed: an HTTP/1 close terminates the body, so flush buffered rewrites.
                    self.responseStream.finish { [weak self] flushed in
                        guard let self, !self.torn else { return }
                        if flushed.isEmpty {
                            self.cancel(error: nil)
                        } else {
                            self.sendChunked(flushed, via: inner) { [weak self] _ in
                                self?.lwipQueue.async { self?.cancel(error: nil) }
                            }
                        }
                    }
                    return
                }
                let handle: (Data) -> Void = { [weak self] transformed in
                    guard let self, !self.torn else { return }
                    guard !transformed.isEmpty else {
                        self.startOutboundPump(inner: inner, outer: outer)
                        return
                    }
                    self.sendChunked(transformed, via: inner) { [weak self] sendError in
                        guard let self else { return }
                        if let sendError {
                            self.lwipQueue.async { self.cancel(error: sendError) }
                            return
                        }
                        self.startOutboundPump(inner: inner, outer: outer)
                    }
                }
                self.outbound.feed(data, completion: handle)
            }
        }
    }
}

// MARK: - TLSServerDelegate

extension MITMSession: TLSServerDelegate {

    func tlsServer(_ server: TLSServer, didProduceOutput data: Data) {
        onSendToClient?(data, nil)
    }

    func tlsServer(
        _ server: TLSServer,
        didCompleteHandshake record: TLSRecordConnection,
        sni: String,
        alpn: String,
        clientFinishedHandshakeTrailer: Data
    ) {
        record.connection = innerTransport
        record.prependToReceiveBuffer(clientFinishedHandshakeTrailer)
        innerRecord = record
        tlsServer = nil

        // An h2 client decodes into neutral request IR via the decoupled client leg; the upstream leg
        // (h2 or http/1.1) is bound after the first dial. An h1.1 client uses the byte-shuttle below.
        if record.negotiatedALPN == "h2" {
            let client = MITMBridgeClientLeg(
                host: dstHost,
                rewriter: h2Rewriter,
                flowController: h2FlowController,
                lwipQueue: lwipQueue
            )
            client.delegate = self
            bridgeClient = client
            startBridgeInboundPump(inner: record)
            return
        }

        startInboundPump(inner: record)
    }

    func tlsServer(_ server: TLSServer, didFail error: TLSError) {
        cancel(error: error)
    }
}

// MARK: - h2 → http/1.1 bridge

extension MITMSession: MITMBridgeClientLegDelegate {

    /// Pumps client plaintext into the bridge client leg; the leg drives per-stream
    /// upstream dials and client-bound writes via the delegate callbacks below.
    private func startBridgeInboundPump(inner: TLSRecordConnection) {
        inner.receive { [weak self] data, error in
            guard let self else { return }
            self.lwipQueue.async {
                guard !self.torn else { return }
                if let error { self.cancel(error: error); return }
                guard let data, !data.isEmpty else { self.cancel(error: nil); return }
                guard let client = self.bridgeClient else { return }
                client.feed(data) { [weak self] in
                    guard let self, !self.torn else { return }
                    self.startBridgeInboundPump(inner: inner)
                }
            }
        }
    }

    func clientLegWriteToClient(_ data: Data) {
        guard !torn, !data.isEmpty, let inner = innerRecord else { return }
        sendChunked(data, via: inner) { [weak self] sendError in
            guard let self, let sendError else { return }
            self.lwipQueue.async { self.cancel(error: sendError) }
        }
    }

    func clientLegFatalError(_ message: String) {
        logger.warning("\(dstHost): client leg fatal: \(message); tearing down")
        cancel(error: nil)
    }

    // MARK: Request IR routing (client leg → upstream)

    func clientLegSendRequestHead(_ head: MITMRequestHead, url: String?, endStream: Bool) {
        guard !torn else { return }
        switch upstreamProtocol {
        case .h2:
            h2Rewriter.requestLog.recordHTTP2(streamID: head.clientStreamID, method: head.method, url: url)
            h2Upstream?.sendRequestHead(head, endStream: endStream)
        case .h1:
            openH1Stream(head, url: url)
        case .undetermined:
            pendingRequestEvents.append(.head(head, url: url, endStream: endStream))
            startFirstUpstreamDial()
        }
    }

    func clientLegSendRequestData(streamID: UInt32, _ data: Data, endStream: Bool) {
        guard !torn else { return }
        switch upstreamProtocol {
        case .h2:
            h2Upstream?.sendRequestData(streamID: streamID, data, endStream: endStream)
        case .h1:
            appendH1RequestData(streamID: streamID, data, endStream: endStream)
        case .undetermined:
            pendingRequestEvents.append(.data(streamID: streamID, data, endStream: endStream))
        }
    }

    func clientLegSendRequestTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)]) {
        guard !torn else { return }
        switch upstreamProtocol {
        case .h2:
            h2Upstream?.sendRequestTrailers(streamID: streamID, trailers)
        case .h1:
            // h1 request trailers require chunked framing and are seldom honored upstream; end the body
            // without them rather than risk a malformed chunked trailer section.
            logger.warning("\(dstHost): dropping h2 request trailers toward h1 upstream stream \(streamID)")
            appendH1RequestData(streamID: streamID, Data(), endStream: true)
        case .undetermined:
            pendingRequestEvents.append(.trailers(streamID: streamID, trailers))
        }
    }

    func clientLegAbortRequest(streamID: UInt32) {
        guard !torn else { return }
        switch upstreamProtocol {
        case .h2: h2Upstream?.abortRequest(streamID: streamID)
        case .h1: bridgeAbortStream(streamID)
        case .undetermined: pendingRequestEvents.append(.abort(streamID: streamID))
        }
    }

    func clientLegResponseComplete(streamID: UInt32) {
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
        dialer(host, port) { [weak self] result in
            guard let self else {
                if case .success(let dial) = result { dial.connection.cancel(); dial.proxyClient?.cancel() }
                return
            }
            guard !self.torn else {
                if case .success(let dial) = result { dial.connection.cancel(); dial.proxyClient?.cancel() }
                return
            }
            switch result {
            case .success(let dial):
                self.sharedUpstreamProxyClient = dial.proxyClient
                self.sharedUpstreamConnection = dial.connection
                self.startFirstUpstreamHandshake(host: host, connection: dial.connection)
            case .failure(let error):
                self.failPendingBridgeRequests(error: error)
            }
        }
    }

    /// First upstream dial/handshake failed (the protocol probe all pending streams share). Answer
    /// every pending stream with a 502 and keep the h2 client connection up, resetting dial state so a
    /// later request re-probes, rather than tear the whole multiplexed connection down for a possibly
    /// transient failure.
    private func failPendingBridgeRequests(error: Error) {
        guard !torn else { return }
        logger.warning("[MITM] \(dstHost): first upstream connect failed: \(error); answering pending streams 502, keeping the connection")
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
                bridgeClient?.failStream(streamID: head.clientStreamID, status: 502, message: "Bad Gateway")
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
            self?.failPendingBridgeRequests(error: UpstreamHandshakeTimeout())
        }
        client.connect(overTunnel: connection) { [weak self] result in
            guard let self else { return }
            self.lwipQueue.async {
                guard disarm() else {
                    if case .success(let record) = result { record.cancel() }
                    connection.cancel()
                    return
                }
                guard !self.torn else {
                    if case .success(let record) = result { record.cancel() }
                    connection.cancel()
                    return
                }
                switch result {
                case .success(let record):
                    self.sharedUpstreamRecord = record
                    if record.negotiatedALPN == "h2" {
                        self.bindH2Upstream(record: record)
                    } else {
                        self.bindH1Upstream()
                    }
                case .failure(let error):
                    // A cert-validation failure is a security signal: a 502 over the trusted inner leg
                    // renders as a padlocked error page and masks the origin's invalid cert. Tear down
                    // so the client surfaces a connection failure; a transient failure still 502s and
                    // re-probes.
                    if Self.isCertVerifyFailure(error) {
                        logger.warning("[MITM] \(self.dstHost): upstream certificate validation failed (\(error)); closing rather than masking as a 502")
                        self.cancel(error: nil)
                    } else {
                        self.failPendingBridgeRequests(error: error)
                    }
                }
            }
        }
    }

    private func bindH2Upstream(record: TLSRecordConnection) {
        upstreamProtocol = .h2
        let leg = MITMHTTP2UpstreamLeg(host: dstHost, rewriter: h2Rewriter, flowController: h2FlowController, lwipQueue: lwipQueue)
        leg.sink = bridgeClient
        // Drain-coupled backpressure: as response bytes reach the client, credit the upstream's
        // per-stream receive window so a slow client throttles the origin (h2 only).
        bridgeClient?.onResponseDrainedToClient = { [weak self] clientStreamID, n in
            self?.h2Upstream?.creditDrainedResponse(clientID: clientStreamID, n)
        }
        leg.onUpstreamBytes = { [weak self] bytes in
            guard let self, !self.torn, !bytes.isEmpty else { return }
            self.sendChunked(bytes, via: record) { [weak self] sendError in
                guard let self, let sendError else { return }
                self.lwipQueue.async { self.cancel(error: sendError) }
            }
        }
        leg.onFatalError = { [weak self] _ in self?.lwipQueue.async { self?.cancel(error: nil) } }
        // Origin GOAWAY: tell the client we're draining (NO_ERROR — per-stream failures use RST, not
        // this connection-level frame) so it redials new streams while in-flight ones finish here.
        leg.onDraining = { [weak self] in
            self?.bridgeClient?.sendGoAwayToClient(code: MITMHTTP2FrameCodec.ErrorCode.noError)
        }
        h2Upstream = leg
        let events = pendingRequestEvents
        pendingRequestEvents.removeAll()
        for event in events {
            switch event {
            case .head(let head, let url, let endStream):
                h2Rewriter.requestLog.recordHTTP2(streamID: head.clientStreamID, method: head.method, url: url)
                leg.sendRequestHead(head, endStream: endStream)
            case .data(let streamID, let data, let endStream):
                leg.sendRequestData(streamID: streamID, data, endStream: endStream)
            case .trailers(let streamID, let trailers):
                leg.sendRequestTrailers(streamID: streamID, trailers)
            case .abort(let streamID):
                leg.abortRequest(streamID: streamID)
            }
        }
        startH2UpstreamPump(record: record)
    }

    private func startH2UpstreamPump(record: TLSRecordConnection) {
        record.receive { [weak self] data, error in
            guard let self else { return }
            self.lwipQueue.async {
                guard !self.torn, let leg = self.h2Upstream else { return }
                if let error { self.cancel(error: error); return }
                guard let data, !data.isEmpty else { self.cancel(error: nil); return }
                leg.feed(data) { [weak self] in
                    guard let self, !self.torn else { return }
                    self.startH2UpstreamPump(record: record)
                }
            }
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
            bridgeClient?.rejectStream(streamID, errorCode: MITMHTTP2FrameCodec.ErrorCode.refusedStream)
            return
        }
        let responseLog = MITMRequestLog()
        responseLog.recordHTTP1(method: head.method, url: url)
        let responseStream = MITMHTTP1Stream(
            host: dstHost, phase: .httpResponse, policy: policy, effectiveAuthority: nil,
            scriptEngineProvider: scriptEngineProvider, requestLog: responseLog, lwipQueue: lwipQueue
        )
        // A malformed / oversized upstream response fails just this stream (RST), not the whole
        // multiplexed h2 connection.
        responseStream.onFatalClose = { [weak self] in
            self?.lwipQueue.async {
                self?.bridgeAbortStream(streamID)
                self?.bridgeClient?.acceptResponseAborted(streamID: streamID)
            }
        }
        let bs = BridgeStream(clientStreamID: streamID, responseStream: responseStream, responseLog: responseLog)
        let irSink = BridgeResponseIRSink(streamID: streamID, client: bridgeClient) { [weak self] sid in
            guard let self else { return }
            // RST the client stream now; free the dead h1 upstream after the current `transform`
            // returns (don't tear down the stream we're mid-call on).
            self.bridgeClient?.acceptResponseAborted(streamID: sid)
            self.lwipQueue.async { self.bridgeAbortStream(sid) }
        }
        responseStream.responseIRSink = irSink
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
        dialer(host, port) { [weak self] result in
            guard let self else {
                if case .success(let dial) = result { dial.connection.cancel(); dial.proxyClient?.cancel() }
                return
            }
            guard !self.torn, let bs = self.bridgeStreams[streamID] else {
                if case .success(let dial) = result { dial.connection.cancel(); dial.proxyClient?.cancel() }
                return
            }
            switch result {
            case .success(let dial):
                bs.proxyClient = dial.proxyClient
                bs.connection = dial.connection
                self.startBridgeUpstreamHandshake(streamID: streamID, host: host)
            case .failure(let error):
                // Inner leg is up; answer the stream with a 502 rather than a bare RST_STREAM that
                // hides a transient upstream-connect failure.
                logger.warning("\(self.dstHost): h1 upstream dial failed for stream \(streamID): \(error)")
                self.bridgeAbortStream(streamID)
                self.bridgeClient?.failStream(streamID: streamID, status: 502, message: "Bad Gateway")
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
            bridgeClient?.acceptResponseAborted(streamID: streamID)
            bridgeAbortStream(streamID)
            return
        }
        if bs.handshakeDone, let record = bs.upstreamRecord {
            flushToBridgeUpstream(out, streamID: streamID, record: record)
        } else {
            bs.pendingToUpstream.append(out)
        }
    }

    /// Writes framed request bytes to a bridge stream's h1 upstream, clearing the stream's unsent tally
    /// as the write drains so `maxBridgeUpstreamBufferedBytes` measures only bytes still in hand. A send
    /// failure aborts the response — the upstream is gone.
    private func flushToBridgeUpstream(_ data: Data, streamID: UInt32, record: TLSRecordConnection) {
        guard !data.isEmpty else { return }
        sendChunked(data, via: record) { [weak self] sendError in
            guard let self else { return }
            self.lwipQueue.async {
                guard !self.torn else { return }
                self.bridgeStreams[streamID]?.unsentUpstreamBytes -= data.count
                if sendError != nil { self.bridgeClient?.acceptResponseAborted(streamID: streamID) }
            }
        }
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
        bs.responseStream.markTorn()
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
            guard let self else { return }
            logger.warning("\(self.dstHost): bridge upstream TLS timed out for stream \(streamID); answering 502")
            self.bridgeAbortStream(streamID)
            self.bridgeClient?.failStream(streamID: streamID, status: 502, message: "Bad Gateway")
        }
        client.connect(overTunnel: connection) { [weak self] result in
            guard let self else { return }
            self.lwipQueue.async {
                guard disarm() else {
                    if case .success(let record) = result { record.cancel() }
                    connection.cancel()
                    return
                }
                guard !self.torn, let bs = self.bridgeStreams[streamID] else {
                    if case .success(let record) = result { record.cancel() }
                    connection.cancel()
                    return
                }
                switch result {
                case .success(let record):
                    bs.upstreamRecord = record
                    bs.handshakeDone = true
                    let pending = bs.pendingToUpstream
                    bs.pendingToUpstream = Data()
                    self.flushToBridgeUpstream(pending, streamID: streamID, record: record)
                    self.startBridgeUpstreamPump(streamID: streamID)
                case .failure(let error):
                    // A cert-validation failure is host-level (the origin's cert is invalid for every
                    // stream to it): a 502 over the trusted inner leg would mask it as a padlocked page,
                    // so tear the connection down. A transient TLS/transport failure still 502s this
                    // stream instead of a bare RST.
                    if Self.isCertVerifyFailure(error) {
                        logger.warning("\(self.dstHost): bridge upstream certificate validation failed for stream \(streamID) (\(error)); closing rather than masking as a 502")
                        self.cancel(error: nil)
                    } else {
                        logger.warning("\(self.dstHost): bridge upstream TLS failed for stream \(streamID): \(error)")
                        self.bridgeAbortStream(streamID)
                        self.bridgeClient?.failStream(streamID: streamID, status: 502, message: "Bad Gateway")
                    }
                }
            }
        }
    }

    /// Reads the upstream response, runs it through the per-stream response rewriter,
    /// and hands the rewritten http/1.1 bytes to the client leg to re-encode as h2.
    private func startBridgeUpstreamPump(streamID: UInt32) {
        guard let bs = bridgeStreams[streamID], let record = bs.upstreamRecord else { return }
        record.receive { [weak self] data, error in
            guard let self else { return }
            self.lwipQueue.async {
                guard !self.torn, let bs = self.bridgeStreams[streamID], let client = self.bridgeClient else { return }
                if let error {
                    logger.warning("\(self.dstHost): bridge upstream read error for stream \(streamID): \(error)")
                    client.acceptResponseAborted(streamID: streamID)
                    self.bridgeAbortStream(streamID) // a reset doesn't notify us; free the dead upstream
                    return
                }
                guard let data, !data.isEmpty else {
                    // Upstream half-closed: a read-until-close body terminates here, so flush the
                    // buffered remainder first, then signal EOF.
                    bs.responseStream.finish { [weak self] _ in
                        guard let self, !self.torn else { return }
                        // finish() delivered the IR end (or a reset on a truncated body) via the sink.
                        // A clean completion already closed the upstream (clientLegResponseComplete);
                        // otherwise drop the now-dead upstream rather than pin it until teardown.
                        if self.bridgeStreams[streamID] != nil { self.bridgeAbortStream(streamID) }
                    }
                    return
                }
                bs.responseStream.transform(data) { [weak self] _ in
                    guard let self, !self.torn else { return }
                    // The rewritten response was delivered as IR via the sink during `transform`; it may
                    // have completed and closed this stream's upstream.
                    guard self.bridgeStreams[streamID] != nil else { return }
                    self.startBridgeUpstreamPump(streamID: streamID)
                }
            }
        }
    }
}
