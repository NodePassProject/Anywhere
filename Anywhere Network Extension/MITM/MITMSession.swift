//
//  MITMSession.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITMSession")

/// Result of the deferred upstream dial.
struct MITMDialResult {
    let connection: ProxyConnection
    /// nil for a direct connection; the session owns its lifetime.
    let proxyClient: ProxyClient?
}

/// Dials the upstream once the first request resolves the host/port; completion runs on the lwIP queue.
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

    /// Cross-session memory of upstreams that can't bridge h2.
    private let originCapabilities: MITMOriginCapabilityCache

    private let dialer: MITMDialer

    /// Retained so it isn't deallocated mid-stream; nil for a direct connection.
    private var proxyClient: ProxyClient?

    /// Retained so teardown can cancel the dial before the outer handshake completes.
    private var outerConnection: ProxyConnection?

    /// Upstream-bound bytes buffered until the outer leg exists; capped by maxPendingClientBytes.
    private var pendingUpstreamBytes = Data()

    /// True while the dial is in flight; further upstream-bound bytes buffer instead of redialing.
    private var dialing = false

    /// Upstream the dial committed to; a later request resolving a different one is torn down rather than misrouted.
    private var dialedHost: String?
    private var dialedPort: UInt16?

    /// From the ClientHello; caps the outer leg's max TLS version.
    private var clientSupportsTLS13 = false

    /// originCapabilities key — must be the SNI, not dstHost: only the SNI is stable
    /// across client retries, and keying on dstHost would re-offer h2 forever and loop.
    private var handshakeSNI: String?

    /// Client bytes buffered until the inner TLSServer exists.
    private var pendingClientBytes: Data

    /// Pre-handshake buffer cap; 256 KiB tolerates large ClientHellos while bounding memory against a hostile local app.
    private static let maxPendingClientBytes: Int = 256 * 1024

    private var tlsServer: TLSServer?
    private var tlsClient: TLSClient?

    private let innerTransport: InnerTransport

    /// Post-handshake record connections; decrypted plaintext stays inside the session.
    private var innerRecord: TLSRecordConnection?
    private var outerRecord: TLSRecordConnection?

    /// HTTP/1.1 stream rewriters, one per direction.
    private let requestStream: MITMHTTP1Stream
    private let responseStream: MITMHTTP1Stream

    /// HTTP/2 frame translators; inbound is created at inner-leg h2 negotiation, outbound once the outer leg confirms h2.
    private var inboundH2: MITMHTTP2Connection?
    private var outboundH2: MITMHTTP2Connection?

    /// Active inbound (client→server) rewriter: h2 when negotiated, else HTTP/1.
    private var inbound: any MITMMessageRewriter {
        if let inboundH2 { return inboundH2 }
        return requestStream
    }

    /// Active outbound (server→client) rewriter: h2 once both legs are, else HTTP/1.
    private var outbound: any MITMMessageRewriter {
        if let outboundH2 { return outboundH2 }
        return responseStream
    }

    private let h2Rewriter: MITMHTTP2Rewriter

    /// Tracks the client's HTTP/2 receive windows so synthesized bodies are paced rather than truncated; shared by both h2 legs.
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
        originCapabilities: MITMOriginCapabilityCache,
        policy: MITMRewritePolicy,
        dialer: @escaping MITMDialer,
        lwipQueue: DispatchQueue
    ) {
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.pendingClientBytes = clientHello
        self.leafCache = leafCache
        self.originCapabilities = originCapabilities
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
        handshakeSNI = sni
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

    /// Routes client bytes to the current inner-leg stage.
    func feedClientBytes(_ data: Data) {
        guard !torn else { return }
        if innerRecord != nil {
            innerTransport.feedFromClient(data)
        } else if let tlsServer {
            tlsServer.feed(data)
        } else {
            if pendingClientBytes.count + data.count > Self.maxPendingClientBytes {
                logger.warning("[MITM] \(dstHost): pre-handshake buffer would exceed \(Self.maxPendingClientBytes) B; tearing down session")
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
        torn = true
        // Disarm in-flight script resumes before they can write to torn legs.
        requestStream.markTorn()
        responseStream.markTorn()
        inboundH2?.markTorn()
        outboundH2?.markTorn()
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

    /// Picks ALPN and TLS versions from the client's offer, withholding h2 from origins recorded HTTP/1.1-only.
    private func startInnerHandshakeFromClientOffer(
        sni: String,
        clientALPNs: [String],
        clientSupportsTLS13: Bool
    ) {
        let supported: Set<String> = ["h2", "http/1.1"]
        var intersected = clientALPNs.filter { supported.contains($0) }
        if originCapabilities.isHTTP1Only(sni) {
            intersected.removeAll { $0 == "h2" }
        }
        let alpns: [String] = intersected.isEmpty ? ["http/1.1"] : intersected
        var tlsVersions: Set<UInt16> = [0x0303]
        if clientSupportsTLS13 { tlsVersions.insert(0x0304) }
        startInnerHandshake(sni: sni, alpns: alpns, tlsVersions: tlsVersions)
    }

    // MARK: - Outer Handshake (deferred)

    /// Runs the outer TLS handshake offering the inner-negotiated ALPN; on a mismatch the
    /// origin is recorded HTTP/1.1-only and the session tears down so the retry avoids h2.
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
            maxVersion: clientSupportsTLS13 ? .tls13 : .tls12,
            fingerprint: .nonBrowser
        )
        let client = TLSClient(configuration: configuration)
        tlsClient = client
        client.connect(overTunnel: connection) { [weak self] result in
            guard let self else { return }
            self.lwipQueue.async {
                guard !self.torn, let inner = self.innerRecord else {
                    connection.cancel()
                    return
                }
                switch result {
                case .success(let record):
                    // No h2↔http/1.1 conversion; an empty upstream ALPN is acceptable only for http/1.1.
                    let outerOK: Bool
                    if innerALPN == "h2" {
                        outerOK = record.negotiatedALPN == "h2"
                    } else {
                        outerOK = record.negotiatedALPN.isEmpty || record.negotiatedALPN == "http/1.1"
                    }
                    guard outerOK else {
                        self.originCapabilities.markHTTP1Only(self.handshakeSNI ?? self.dstHost)
                        logger.warning("[MITM] \(self.dstHost): upstream ALPN \"\(record.negotiatedALPN)\" can't bridge inner \"\(innerALPN)\"; recorded http/1.1-only, tearing down so the client retries")
                        self.cancel(error: nil)
                        return
                    }
                    self.outerRecord = record
                    self.finishDialAndShuttle(inner: inner, outer: record)
                case .failure(let error):
                    // Alert 120 (no_application_protocol, RFC 7301) on an h2 offer:
                    // record http/1.1-only so the retry negotiates it.
                    if innerALPN == "h2", case TLSError.alert(level: _, description: 120) = error {
                        self.originCapabilities.markHTTP1Only(self.handshakeSNI ?? self.dstHost)
                    }
                    self.cancel(error: error)
                }
            }
        }
    }

    // MARK: - ClientHello parsing

    private func parseClientHello(_ buffer: Data) -> TLSClientHelloParsed? {
        guard !buffer.isEmpty else { return nil }
        return try? TLSClientHelloParser.parse(buffer)
    }

    // MARK: - Shuttle

    /// Completes the dial: wires up h2 translators, flushes the buffered first request, starts the outbound pump.
    private func finishDialAndShuttle(inner: TLSRecordConnection, outer: TLSRecordConnection) {
        if inner.negotiatedALPN == "h2", outer.negotiatedALPN == "h2", let inLeg = inboundH2 {
            let outLeg = MITMHTTP2Connection(direction: .outbound, rewriter: h2Rewriter, flowController: h2FlowController, lwipQueue: lwipQueue)
            // SETTINGS_HEADER_TABLE_SIZE bounds the peer's HPACK encoder (RFC 7541 §4.2),
            // so each leg must inform the other's decoder. Weak captures break the cycle.
            inLeg.onObservedPeerHeaderTableSize = { [weak outLeg] size in
                outLeg?.configureDecoderTableSize(size)
            }
            outLeg.onObservedPeerHeaderTableSize = { [weak inLeg] size in
                inLeg?.configureDecoderTableSize(size)
            }
            // Bodies overflowing a peer's flow-control window hop to the other leg
            // for paced delivery (avoids GOAWAY / FLOW_CONTROL_ERROR).
            outLeg.onPacedResponse = { [weak inLeg] streamID, headerBlock, body, endStream in
                // nil during teardown declines; the outbound leg then emits inline.
                inLeg?.queuePacedClientResponse(streamID: streamID, headerBlock: headerBlock, body: body, endStream: endStream) ?? false
            }
            inLeg.onPacedRequest = { [weak outLeg] streamID, body, endStream in
                outLeg?.queuePacedServerRequest(streamID: streamID, body: body, endStream: endStream) ?? false
            }
            // Drop a paced request body on RST so the buffer isn't pinned until teardown.
            inLeg.onUpstreamRequestAborted = { [weak outLeg] streamID in
                outLeg?.dropPacedRequest(streamID)
            }
            // Replay the table size observed pre-dial so the new decoder's HPACK state stays in sync.
            if let observed = inLeg.lastObservedPeerHeaderTableSize {
                outLeg.configureDecoderTableSize(observed)
            }
            outboundH2 = outLeg
        }
        // Flush the buffered first request before the inbound pump forwards new ones.
        let buffered = pendingUpstreamBytes
        pendingUpstreamBytes = Data()
        if !buffered.isEmpty {
            sendChunked(buffered, via: outer) { [weak self] sendError in
                guard let self, let sendError else { return }
                self.lwipQueue.async { self.cancel(error: sendError) }
            }
        }
        // Hand paced request bodies held pre-dial to the new pacer and drain the first window.
        if let outLeg = outboundH2, let inLeg = inboundH2 {
            for held in inLeg.takeHeldPacedRequests() {
                outLeg.queuePacedServerRequest(streamID: held.streamID, body: held.body, endStream: held.endStream)
            }
            let pacedInit = outLeg.drainPendingServerBytes()
            if !pacedInit.isEmpty {
                sendChunked(pacedInit, via: outer) { [weak self] sendError in
                    guard let self, let sendError else { return }
                    self.lwipQueue.async { self.cancel(error: sendError) }
                }
            }
        }
        startOutboundPump(inner: inner, outer: outer)
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
                    // Must run after `transformed` so the paced request body follows its HEADERS. Empty for HTTP/1.
                    let flushPacedRequest: (TLSRecordConnection) -> Void = { [weak self] outer in
                        guard let self else { return }
                        let pacedReq = self.outboundH2?.drainPendingServerBytes() ?? Data()
                        guard !pacedReq.isEmpty else { return }
                        self.sendChunked(pacedReq, via: outer) { [weak self] sendError in
                            guard let self, let sendError else { return }
                            self.lwipQueue.async { self.cancel(error: sendError) }
                        }
                    }
                    guard !transformed.isEmpty else {
                        // Buffered fragment or fully-answered synth; still flush any paced request body.
                        if let outer = self.outerRecord {
                            flushPacedRequest(outer)
                        }
                        self.startInboundPump(inner: inner)
                        return
                    }
                    if let outer = self.outerRecord {
                        // One outer leg can't carry two authorities; a request resolving
                        // a different upstream is torn down rather than misrouted.
                        guard self.resolvedUpstreamMatchesDialed() else {
                            logger.warning("[MITM] \(self.dstHost): request resolved an upstream different from the dialed one; tearing down so the client retries")
                            self.cancel(error: nil)
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
                        flushPacedRequest(outer)
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
        if pendingUpstreamBytes.count + transformed.count > Self.maxPendingClientBytes {
            logger.warning("[MITM] \(dstHost): pre-dial upstream buffer would exceed \(Self.maxPendingClientBytes) B; tearing down session")
            cancel(error: nil)
            return
        }
        pendingUpstreamBytes.append(transformed)
        if dialing {
            guard resolvedUpstreamMatchesDialed() else {
                logger.warning("[MITM] \(dstHost): pipelined request resolved an upstream different from the dialed one; tearing down so the client retries")
                cancel(error: nil)
                return
            }
            startInboundPump(inner: inner)
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
                self.cancel(error: error)
            }
        }
        startInboundPump(inner: inner)
    }

    /// False when the current request resolves a different upstream than dialed; always true pre-dial.
    private func resolvedUpstreamMatchesDialed() -> Bool {
        guard let dialedHost, let dialedPort else { return true }
        let resolved = inbound.resolvedUpstream
        return (resolved?.host ?? dstHost) == dialedHost
            && (resolved?.port ?? dstPort) == dialedPort
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

    /// Pumps server plaintext from the outer record to the inner record.
    private func startOutboundPump(inner: TLSRecordConnection, outer: TLSRecordConnection) {
        outer.receive { [weak self] data, error in
            guard let self else { return }
            self.lwipQueue.async {
                if let error {
                    self.cancel(error: error)
                    return
                }
                guard let data, !data.isEmpty else {
                    // Upstream half-closed: an HTTP/1 close terminates the body, so flush
                    // buffered rewrites first; HTTP/2 frames bodies with END_STREAM.
                    guard self.outboundH2 == nil else {
                        self.cancel(error: nil)
                        return
                    }
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
                    // Drain flow-control credit and any paced request DATA unblocked by a WINDOW_UPDATE. Empty for HTTP/1.
                    let serverCredit = self.outbound.drainPendingServerBytes()
                    if !serverCredit.isEmpty {
                        self.sendChunked(serverCredit, via: outer) { [weak self] sendError in
                            guard let self, let sendError else { return }
                            self.lwipQueue.async { self.cancel(error: sendError) }
                        }
                    }
                    // Flush a paced response's HEADERS + first window now; the client may
                    // be blocked on it and the next inbound read may never come.
                    let pacedInit = self.inboundH2?.drainPendingClientBytes() ?? Data()
                    if !pacedInit.isEmpty {
                        self.sendChunked(pacedInit, via: inner) { [weak self] sendError in
                            guard let self, let sendError else { return }
                            self.lwipQueue.async { self.cancel(error: sendError) }
                        }
                    }
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

        // Created now so it can decode the first request before the deferred dial.
        if record.negotiatedALPN == "h2" {
            inboundH2 = MITMHTTP2Connection(direction: .inbound, rewriter: h2Rewriter, flowController: h2FlowController, lwipQueue: lwipQueue)
        }
        startInboundPump(inner: record)
    }

    func tlsServer(_ server: TLSServer, didFail error: TLSError) {
        cancel(error: error)
    }
}
