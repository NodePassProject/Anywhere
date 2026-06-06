//
//  MITMSession.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

/// Result of the deferred upstream dial handed back to ``MITMSession``.
struct MITMDialResult {
    let connection: ProxyConnection
    /// The proxy client whose lifetime the session now owns (nil for a direct
    /// connection).
    let proxyClient: ProxyClient?
}

/// Performs the deferred upstream dial. ``MITMSession`` invokes this once it
/// has resolved the upstream host/port from the first request (after URL
/// rewrite); the implementation (``TCPConnection``) dials direct or via the
/// proxy and returns the connected pipe. The completion runs on the session's
/// lwIP queue.
typealias MITMDialer = (
    _ host: String,
    _ port: UInt16,
    _ completion: @escaping (Result<MITMDialResult, Error>) -> Void
) -> Void

final class MITMSession {

    // MARK: - Inner Transport (RawTransport adapter for the lwIP side)

    /// Bidirectional pipe between the inner-leg TLS record connection and
    /// the lwIP-attached caller. Bytes written by ``TLSRecordConnection``
    /// get forwarded to ``onSendToClient``; bytes received from the client
    /// land via ``feedFromClient`` and feed any pending receive completion.
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

        /// Called when the lwIP path delivers bytes from the client.
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

        /// Signals an orderly client-side close.
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

    /// Shared, cross-session memory of upstreams that can't bridge `h2`. Read
    /// when choosing the inner leg's ALPN (to avoid committing to `h2` for a
    /// known HTTP/1.1-only origin) and written when the outer leg discovers one.
    private let originCapabilities: MITMOriginCapabilityCache

    /// Performs the deferred upstream dial. Invoked once the first request's
    /// rewrite resolves the upstream host/port; the implementation
    /// (``TCPConnection``) returns the connected pipe and transfers the
    /// ``ProxyClient`` ownership to this session.
    private let dialer: MITMDialer

    /// The proxy client whose lifetime this session owns once the dial
    /// completes (nil for a direct connection, or before the dial). Retained
    /// so it isn't deallocated mid-stream; cancelled on teardown.
    private var proxyClient: ProxyClient?

    /// The dialed upstream connection, retained from the moment the dial
    /// succeeds so it can be cancelled even if teardown races the outer TLS
    /// handshake (before ``outerRecord`` — which otherwise owns its teardown —
    /// exists).
    private var outerConnection: ProxyConnection?

    /// Bytes destined for the upstream produced before the outer leg existed
    /// (the rewritten first request plus anything the client pipelined while
    /// the dial ran). Flushed once the outer handshake completes. Capped by
    /// ``maxPendingClientBytes``.
    private var pendingUpstreamBytes = Data()

    /// True once the deferred dial has been kicked off, so additional
    /// upstream-bound bytes are buffered rather than starting a second dial.
    private var dialing = false

    /// The upstream the dial committed to (the first request's resolved
    /// host/port, with the original destination as fallback). The leg can
    /// reach only this upstream, so a later request whose transparent rewrite
    /// resolves a different host/port is torn down instead of misrouted to it
    /// (see ``resolvedUpstreamMatchesDialed``). nil until the dial is kicked off.
    private var dialedHost: String?
    private var dialedPort: UInt16?

    /// Whether the client offered TLS 1.3, captured from the ClientHello and
    /// used to cap the outer leg's max version (the outer leg follows the
    /// inner negotiation).
    private var clientSupportsTLS13 = false

    /// The SNI the inner leg negotiated against — the key under which the
    /// shared ``originCapabilities`` cache is both read (when choosing the
    /// inner ALPN) and written (when the outer leg discovers an h2 mismatch).
    /// MUST match the read key: ``MITMOriginCapabilityCache`` is documented as
    /// keyed by SNI, and the SNI is what's stable across the client's retries
    /// (the destination ``dstHost`` can be a bare IP when the client dialed by
    /// address while sending a hostname SNI, so keying the write on ``dstHost``
    /// would store the verdict under a key the next session never checks —
    /// re-offering h2 forever and looping the connection). Captured in
    /// ``start(sni:)``.
    private var handshakeSNI: String?

    /// Bytes received from the client before the inner ``TLSServer`` was
    /// created. Always begins with a complete ClientHello; may also
    /// contain bytes the client pushed while we were finishing the outer
    /// handshake. Drained into ``TLSServer/feed(_:)`` once the inner leg
    /// starts.
    private var pendingClientBytes: Data

    /// Hard cap on ``pendingClientBytes`` while the outer handshake is
    /// running. A correct TLS client blocks on the ServerHello after
    /// emitting its ClientHello, so this buffer stays well under 16 KiB
    /// in real flows; the cap exists to defend against a hostile or
    /// buggy local app that dumps arbitrary data into the SOCKS leg
    /// before TLS negotiation completes. Without a cap, that traffic
    /// would accumulate without bound. 256 KiB is generous (multi-KB JA3
    /// extensions, large GREASE blocks) while still catching abuse.
    private static let maxPendingClientBytes: Int = 256 * 1024

    private var tlsServer: TLSServer?
    private var tlsClient: TLSClient?

    private let innerTransport: InnerTransport

    /// Inner record connection after handshake. Encrypts and decrypts
    /// traffic with the client; plaintext stays inside the session.
    private var innerRecord: TLSRecordConnection?
    /// Outer record connection after handshake. Encrypts and decrypts
    /// traffic with the real server; plaintext stays inside the session.
    private var outerRecord: TLSRecordConnection?

    /// HTTP/1.1 stream rewriters, one per direction. Each owns the
    /// message-framing state machine for its half of the connection.
    private let requestStream: MITMHTTP1Stream
    private let responseStream: MITMHTTP1Stream

    /// HTTP/2 frame translators, populated only when both legs negotiate
    /// `h2` ALPN. ``inboundH2`` rewrites client-to-server traffic;
    /// ``outboundH2`` rewrites server-to-client traffic.
    private var inboundH2: MITMHTTP2Connection?
    private var outboundH2: MITMHTTP2Connection?

    /// The active inbound (client→server) rewriter: the HTTP/2 connection once
    /// the inner leg negotiated `h2`, otherwise the always-present HTTP/1
    /// request stream. Lets the pumps shuttle bytes without branching on the
    /// negotiated protocol at every step.
    private var inbound: any MITMMessageRewriter {
        if let inboundH2 { return inboundH2 }
        return requestStream
    }

    /// The active outbound (server→client) rewriter: the HTTP/2 connection once
    /// both legs are `h2`, otherwise the HTTP/1 response stream.
    private var outbound: any MITMMessageRewriter {
        if let outboundH2 { return outboundH2 }
        return responseStream
    }

    private let h2Rewriter: MITMHTTP2Rewriter

    /// Tracks the client's HTTP/2 receive windows so synth (`Anywhere.respond`)
    /// bodies are paced to them rather than truncated. Shared by both h2 legs;
    /// constructed unconditionally (cheap) and only exercised once the legs
    /// exist. See ``MITMHTTP2FlowController``.
    private let h2FlowController = MITMHTTP2FlowController()

    /// Handle to the JavaScript runtime for this session's rule set,
    /// shared by both HTTP/1 streams and the HTTP/2 rewriter. The engine
    /// itself is shared across every connection to the same rule set and
    /// materializes only when a ``CompiledMITMOperation/script`` rule
    /// actually fires (see ``MITMScriptEngine/Provider``).
    private let scriptEngineProvider: MITMScriptEngine.Provider

    /// Cross-direction record of the in-flight request's method+URL so
    /// the response-phase script ctx can populate `ctx.method` /
    /// `ctx.url` from the request that produced this response.
    private let requestLog = MITMRequestLog()

    private var torn = false

    /// Set by the lwIP-side caller to receive inner-leg bytes that need
    /// to be written back to the client.
    var onSendToClient: ((Data, ((Error?) -> Void)?) -> Void)? {
        didSet { innerTransport.onSendToClient = onSendToClient }
    }

    /// Called when the session tears down. `error` is nil for a clean close.
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
        // One JS engine per rule set, shared across every connection to
        // it and keyed by the matched set's id so it lines up with the
        // ``Anywhere.store`` scope. A nil scope (no matched set) only
        // arises when no script rule can fire, so no engine is built then.
        self.scriptEngineProvider = MITMScriptEngine.Provider(scope: policy.set(for: dstHost)?.id)
        // ``effectiveAuthority`` is late-bound: the rewriters start with nil;
        // a transparent ``MITMOperation/rewrite`` on the first request sets it
        // (and the dial target) once the replacement host is known.
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

    /// Starts the inner-leg TLS handshake first, negotiating ALPN + TLS
    /// version from the client's own ClientHello. The upstream is dialed
    /// lazily — only once the first request resolves the destination (after
    /// URL rewrite) — and the outer leg then follows the inner-negotiated
    /// ALPN. Requests fully answered by a 302 / reject rewrite (or
    /// `Anywhere.respond`) never trigger a dial. Must be called on `lwipQueue`.
    func start(sni: String) {
        // When the HTTP/1 response leg sees a 101 / CONNECT-2xx the connection
        // becomes an opaque tunnel; flip the request leg to passthrough too and
        // flush whatever it had buffered upstream, so client→server tunnel bytes
        // (e.g. WebSocket frames) aren't stranded in its head parser.
        responseStream.onProtocolUpgrade = { [weak self] in
            self?.handleResponseUpgrade()
        }
        // Capture the SNI as the origin-capability cache key so the later
        // ``markHTTP1Only`` write uses the same key as the ``isHTTP1Only`` read
        // below (see ``handshakeSNI``).
        handshakeSNI = sni
        let parsed = parseClientHello(pendingClientBytes)
        let clientALPNs = parsed?.alpnProtocols ?? []
        // Fail-closed default: when the ClientHello fails to parse we assume
        // the client does NOT support TLS 1.3, so the inner leg just offers
        // TLS 1.2. A 1.3-capable client (which by spec also supports 1.2)
        // negotiates 1.2 and the handshake still succeeds — only a
        // hypothetical 1.3-only client would be affected, and none exist in
        // practice.
        clientSupportsTLS13 = parsed?.supportedVersions.contains(0x0304) ?? false
        startInnerHandshakeFromClientOffer(
            sni: sni,
            clientALPNs: clientALPNs,
            clientSupportsTLS13: clientSupportsTLS13
        )
    }

    /// Feeds bytes received from the client. Until the inner ``TLSServer``
    /// exists (i.e. while the outer handshake is still in progress) we
    /// hold the bytes in ``pendingClientBytes``; afterwards they go to the
    /// inner ``TLSServer`` or, post-handshake, to the inner transport.
    func feedClientBytes(_ data: Data) {
        guard !torn else { return }
        if innerRecord != nil {
            innerTransport.feedFromClient(data)
        } else if let tlsServer {
            tlsServer.feed(data)
        } else {
            // Outer handshake still running — buffer for the inner
            // ``TLSServer`` once it is created. Capped at
            // ``maxPendingClientBytes`` to defend the Network
            // Extension's memory budget from a hostile local app that
            // dumps arbitrary bytes into the SOCKS leg before the
            // outer handshake completes.
            if pendingClientBytes.count + data.count > Self.maxPendingClientBytes {
                logger.warning("[MITM] \(dstHost): pre-handshake buffer would exceed \(Self.maxPendingClientBytes) B; tearing down session")
                cancel(error: nil)
                return
            }
            pendingClientBytes.append(data)
        }
    }

    /// Signals an orderly client-side close.
    func clientDidClose() {
        guard !torn else { return }
        if innerRecord != nil {
            innerTransport.endOfClient()
        } else {
            // Client closed mid-handshake — tear everything down.
            cancel(error: nil)
        }
    }

    /// Tears the session down. Best-effort.
    func cancel(error: Error? = nil) {
        guard !torn else { return }
        torn = true
        // Disarm any in-flight script resume so it can't write to a
        // torn-down leg or fire a stale completion once its off-queue hop
        // returns.
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
        // The proxy client + dialed connection are owned solely by this session
        // once the dial completes (TCPConnection transferred them via the
        // dialer). ``outerRecord.cancel()`` tears down the connection once the
        // outer handshake wraps it; cancelling ``outerConnection`` directly
        // covers a teardown that races the handshake. cancel() is idempotent.
        outerConnection?.cancel()
        outerConnection = nil
        proxyClient?.cancel()
        proxyClient = nil
        pendingUpstreamBytes = Data()
        legSenders.removeAll()
        innerTransport.forceCancel()
        onTeardown?(error)
    }

#if DEBUG
    /// Leak tripwire: a session must be torn down via `cancel()` — which
    /// cancels both TLS legs and `forceCancel`s the inner transport — before
    /// being freed. DEBUG-only.
    deinit {
        assert(torn, "MITMSession leaked: freed without cancel()")
    }
#endif

    // MARK: - Inner Handshake

    /// Starts the inner-leg TLS server, negotiating from the supplied ALPN /
    /// TLS-version sets (derived from the client's own offer). The outer leg is
    /// dialed later and made to follow whichever ALPN this negotiates.
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

            // Drive in any bytes already buffered (the ClientHello plus
            // anything the client sent while we were setting up).
            server.feed(pendingClientBytes)
            pendingClientBytes.removeAll(keepingCapacity: false)
        } catch {
            cancel(error: error)
        }
    }

    /// Inner-first entry point. Picks the inner handshake's ALPN + TLS-version
    /// sets from the client's offer — its preference order wins — but withholds
    /// `h2` for origins a prior session recorded as HTTP/1.1-only (see
    /// ``originCapabilities``), since committing to it would only force a
    /// teardown once the outer leg can't match it. Falls back to ``http/1.1``
    /// when no usable ALPN remains.
    private func startInnerHandshakeFromClientOffer(
        sni: String,
        clientALPNs: [String],
        clientSupportsTLS13: Bool
    ) {
        let supported: Set<String> = ["h2", "http/1.1"]
        var intersected = clientALPNs.filter { supported.contains($0) }
        // If a prior session learned this origin can't bridge `h2` (see
        // ``startOuterHandshakeAfterDial``), don't commit the inner leg to it
        // again: the outer leg would only rediscover the mismatch and tear the
        // session down. Dropping `h2` here makes the client negotiate
        // `http/1.1`, which the upstream accepts — no teardown, no retry loop.
        if originCapabilities.isHTTP1Only(sni) {
            intersected.removeAll { $0 == "h2" }
        }
        let alpns: [String] = intersected.isEmpty ? ["http/1.1"] : intersected
        var tlsVersions: Set<UInt16> = [0x0303]
        if clientSupportsTLS13 { tlsVersions.insert(0x0304) }
        startInnerHandshake(sni: sni, alpns: alpns, tlsVersions: tlsVersions)
    }

    // MARK: - Outer Handshake (deferred)

    /// Runs the outer TLS handshake over the freshly-dialed upstream
    /// ``connection``, offering the inner-negotiated ALPN so both legs commit
    /// to the same application protocol: the inner leg negotiates against the
    /// client and the outer leg follows it. On success the buffered first
    /// request is flushed and shuttling begins. An ALPN the upstream can't
    /// honor (e.g. inner `h2` vs an http/1.1-only origin) can't be bridged, so
    /// the origin is recorded as HTTP/1.1-only and the session tears down. The
    /// client retries, and because the inner leg now declines to offer `h2` for
    /// that origin (see ``startInnerHandshakeFromClientOffer``) the retry
    /// negotiates `http/1.1` and completes — no loop.
    private func startOuterHandshakeAfterDial(
        over connection: ProxyConnection,
        host: String,
        innerALPN: String
    ) {
        // Fingerprint: the outer leg performs a REAL TLS handshake to the
        // origin, so correctness matters and camouflage does not — use the
        // ``.nonBrowser`` minimal client (no ALPS/GREASE/cert-compression/ECH/
        // padding), matching a generic OpenSSL-style client. A browser
        // fingerprint's ALPS trips strict origins (Google's GFE) into a fatal
        // `unexpected_message`.
        let configuration = TLSConfiguration(
            serverName: host,
            alpn: [innerALPN],
            fingerprint: .nonBrowser,
            minVersion: .tls12,
            maxVersion: clientSupportsTLS13 ? .tls13 : .tls12
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
                    // The legs are bridged byte-for-byte (HTTP/1) or via the
                    // frame translators (h2); we can't convert between h2 and
                    // http/1.1. The inner leg already committed to the client's
                    // ALPN, so the outer must match it. An empty upstream ALPN is
                    // acceptable only when the inner leg is http/1.1 (the
                    // plaintext default).
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
                    // `no_application_protocol` (alert 120) is the strict-RFC
                    // counterpart of the empty-ALPN case above: an upstream that
                    // rejected our h2-only offer outright. Record it so the
                    // client's retry negotiates http/1.1 and succeeds instead of
                    // looping on h2. Gated on `innerALPN == "h2"` — a 120 when we
                    // offered http/1.1 means the origin speaks neither, which the
                    // http/1.1-only verdict would misrepresent.
                    if innerALPN == "h2", case TLSError.alert(level: _, description: 120) = error {
                        self.originCapabilities.markHTTP1Only(self.handshakeSNI ?? self.dstHost)
                    }
                    self.cancel(error: error)
                }
            }
        }
    }

    // MARK: - ClientHello parsing

    /// Best-effort parse of the buffered inner ClientHello. Returns nil
    /// if the buffer is empty or doesn't yet hold a complete record —
    /// callers fall back to permissive defaults in that case.
    private func parseClientHello(_ buffer: Data) -> TLSClientHelloParsed? {
        guard !buffer.isEmpty else { return nil }
        return try? TLSClientHelloParser.parse(buffer)
    }

    // MARK: - Shuttle

    /// Completes the dial: wires up the h2 translators (the inbound leg already
    /// exists from the inner handshake; the outbound leg is created here when
    /// both legs negotiated h2), flushes the buffered first request upstream,
    /// and starts the outbound pump. The inbound pump is already running (it
    /// triggered the dial) and switches to forwarding now that ``outerRecord``
    /// is set.
    private func finishDialAndShuttle(inner: TLSRecordConnection, outer: TLSRecordConnection) {
        if inner.negotiatedALPN == "h2", outer.negotiatedALPN == "h2", let inLeg = inboundH2 {
            let outLeg = MITMHTTP2Connection(direction: .outbound, rewriter: h2Rewriter, flowController: h2FlowController, lwipQueue: lwipQueue)
            // SETTINGS_HEADER_TABLE_SIZE advertised by one endpoint bounds the
            // *peer's* HPACK encoder, which the opposing leg decodes (RFC 7541
            // §4.2). Weak captures break the otherwise-mutual leg retain cycle;
            // both legs share the serial lwipQueue, so the synchronous cross-leg
            // call can't race the other leg's ``process(_:)``.
            inLeg.onObservedPeerHeaderTableSize = { [weak outLeg] size in
                outLeg?.configureDecoderTableSize(size)
            }
            outLeg.onObservedPeerHeaderTableSize = { [weak inLeg] size in
                inLeg?.configureDecoderTableSize(size)
            }
            // A buffered-rewrite RESPONSE whose body exceeds the client's
            // flow-control window is handed from the outbound leg to the inbound
            // leg — which receives the client's WINDOW_UPDATEs and owns the
            // client-bound buffer — for paced delivery, so a large rewritten body
            // can't overflow the window into a connection-wide GOAWAY (see
            // ``MITMHTTP2Connection.onPacedResponse`` / ``queuePacedClientResponse``).
            // Weak capture: same mutual-retain-cycle break as above; the call is
            // synchronous on the shared lwipQueue from the outbound flush.
            outLeg.onPacedResponse = { [weak inLeg] streamID, headerBlock, body, endStream in
                // nil (inbound leg gone — teardown) declines, so the outbound leg
                // emits inline; harmless since teardown suppresses emission anyway.
                inLeg?.queuePacedClientResponse(streamID: streamID, headerBlock: headerBlock, body: body, endStream: endStream) ?? false
            }
            // Request-direction mirror: a buffered-rewrite REQUEST body that
            // exceeds the upstream window is handed from the inbound leg to the
            // outbound leg — which receives the server's WINDOW_UPDATEs and owns
            // the server-bound buffer — for paced delivery, so it can't overflow
            // the server's window into a FLOW_CONTROL_ERROR. Weak capture: same
            // mutual-retain-cycle break; the call is synchronous on the shared
            // lwipQueue from the inbound flush.
            inLeg.onPacedRequest = { [weak outLeg] streamID, body, endStream in
                outLeg?.queuePacedServerRequest(streamID: streamID, body: body, endStream: endStream) ?? false
            }
            // A client RST / abandon of a stream whose request body the outbound
            // leg is pacing drops it, so a cancelled request isn't delivered and
            // its buffer isn't pinned until teardown.
            inLeg.onUpstreamRequestAborted = { [weak outLeg] streamID in
                outLeg?.dropPacedRequest(streamID)
            }
            // The inbound leg may have already decoded the client's SETTINGS
            // (the h2 preface arrives before the dial completes); replay the
            // observed header-table size to the just-created outbound decoder so
            // it doesn't desync.
            if let observed = inLeg.lastObservedPeerHeaderTableSize {
                outLeg.configureDecoderTableSize(observed)
            }
            outboundH2 = outLeg
        }
        // Flush the rewritten first request (and anything the client pipelined
        // during the dial) upstream, in order, before the inbound pump forwards
        // any new bytes. ``LegSendSerializer`` preserves enqueue order.
        let buffered = pendingUpstreamBytes
        pendingUpstreamBytes = Data()
        if !buffered.isEmpty {
            sendChunked(buffered, via: outer) { [weak self] sendError in
                guard let self, let sendError else { return }
                self.lwipQueue.async { self.cancel(error: sendError) }
            }
        }
        // The deferred dial processed the first request(s) before the outbound leg
        // existed, so any buffered-rewrite request body too large for the upstream
        // window was held on the inbound leg (its HEADERS are part of ``buffered``
        // just flushed above). Hand each to the outbound pacer now, in stream-ID
        // order, and flush the first window's worth toward the server — enqueued
        // after the HEADERS on the shared outer send serializer, so order holds.
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

    /// Chunked-send helper. Splits ``data`` into ``chunkSize``-byte
    /// pieces and writes each one sequentially, chaining the next
    /// write off the previous send's completion callback. Achieves
    /// two things:
    ///   - Caps the per-send TLS record buffer to ``chunkSize``,
    ///     instead of letting a ``buildTLSRecords`` allocate the
    ///     entire (post-script) body in one ~MiB blob (the codec cap
    ///     of ``MITMBodyCodec.maxBufferedBodyBytes`` is 4 MiB).
    ///   - Applies upstream backpressure: the next chunk only
    ///     dispatches after the current chunk's send completes, so a
    ///     slow underlying transport throttles us instead of letting
    ///     us queue arbitrary bytes into NWConnection.
    /// 64 KiB is chosen as 4× the TLS record plaintext cap (16 KiB)
    /// — enough to amortize per-send overhead without pinning more
    /// than ~64 KiB of encrypted bytes in the send pipeline per leg.
    private static let pumpChunkSize: Int = 64 * 1024

    /// Per-leg send serializers, keyed by record identity, created
    /// lazily on first send. See ``LegSendSerializer``.
    private var legSenders: [ObjectIdentifier: LegSendSerializer] = [:]

    /// Chunked, per-leg-serialized send. Splits ``data`` into
    /// ``pumpChunkSize`` pieces written sequentially (next chunk only
    /// after the previous send completes) to cap the per-send TLS record
    /// buffer and apply transport backpressure, and serializes whole
    /// blobs on the same leg so concurrent writers can't interleave
    /// their chunks. Must be called on ``lwipQueue``.
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

    /// Serializes chunked sends on a single TLS leg. ``sendChunked``
    /// breaks a logical blob into several ``TLSRecordConnection/send``
    /// calls; that connection's send lock keeps each call's records
    /// contiguous and sequence-ordered but does NOT stop a second
    /// concurrent caller's chunks from landing between this caller's. On
    /// the inner leg two writers coexist — the inbound pump's synth
    /// (`injected`) bytes and the outbound pump's response
    /// (`transformed`) bytes — so unserialized chunking would interleave
    /// their bytes and split an HTTP/2 frame (or HTTP/1 message)
    /// mid-payload, desyncing the receiver. This drains one enqueued blob
    /// to completion before starting the next, giving each blob the
    /// all-or-nothing atomicity a single ``send`` call has but a
    /// multi-chunk ``sendChunked`` does not.
    ///
    /// All methods must run on the ``queue`` passed at init.
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
            // Fresh ``Data`` so the encoder sees a contiguous slab and the
            // zero-copy slice doesn't outlive this iteration.
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

    /// Reads plaintext from the inner record (= what the client sent) and
    /// writes it to the outer record (= towards the real server).
    ///
    /// Request-phase scripts can short-circuit a request via
    /// ``MITMScriptEngine/SynthesizedResponse`` (the JS-side
    /// `Anywhere.respond(...)` hook). When that happens the stream /
    /// h2 translator emits zero upstream bytes but populates a
    /// client-bound buffer with the synthesized response; we drain
    /// that buffer here and write straight to the inner record,
    /// bypassing the upstream leg entirely. This synth write and the
    /// outbound pump's response write can both target the inner leg at
    /// once; ``sendChunked``'s per-leg ``LegSendSerializer`` drains each
    /// whole blob before the next so their chunks never interleave on
    /// the wire.
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
                // The completion runs on lwipQueue — inline when no script ran,
                // or later from the parked resume. It drains any client-bound
                // synth bytes (a 302 / reject rewrite or request-phase
                // Anywhere.respond) to the inner leg, then either forwards the
                // peer-bound bytes upstream (post-dial) or buffers them and
                // triggers the deferred dial (pre-dial), re-arming the read to
                // keep the one-read-in-flight back-pressure intact across a park.
                let handle: (Data) -> Void = { [weak self] transformed in
                    guard let self, !self.torn else { return }
                    let injected = self.inbound.drainPendingClientBytes()
                    if !injected.isEmpty {
                        self.sendChunked(injected, via: inner) { [weak self] sendError in
                            guard let self, let sendError else { return }
                            self.lwipQueue.async { self.cancel(error: sendError) }
                        }
                    }
                    // Flush any paced request body the outbound leg queued during
                    // this feed toward the server (a buffered-rewrite request body
                    // too large for the upstream window — see
                    // ``MITMHTTP2Connection.onPacedRequest``). Always run AFTER the
                    // request HEADERS/DATA in ``transformed`` so the body follows
                    // its HEADERS on the shared outer serializer; for an early-open
                    // handoff (HEADERS already on the wire, ``transformed`` empty)
                    // there is nothing to order against. nil/empty for HTTP/1 and
                    // whenever no handoff occurred this pass. The remainder drains
                    // later as the server's WINDOW_UPDATEs arrive on the outbound
                    // pump.
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
                        // Buffered fragments (CONTINUATION pending, partial
                        // preface, body buffered for rewrite, etc.) or a request
                        // fully answered on the inner leg (302 / reject /
                        // Anywhere.respond). Post-dial, still flush any paced
                        // request body an early-open handoff queued. Loop back.
                        if let outer = self.outerRecord {
                            flushPacedRequest(outer)
                        }
                        self.startInboundPump(inner: inner)
                        return
                    }
                    if let outer = self.outerRecord {
                        // The dial is committed to the first request's upstream;
                        // a later request that resolves a different one can't be
                        // reached here. Tear down so the client retries it on a
                        // fresh connection rather than misrouting it to the
                        // dialed host.
                        //
                        // ARCHITECTURAL LIMITATION (HTTP/2): there is a single
                        // outer leg per connection, so we cannot proxy two
                        // authorities over one h2 connection. A rewrite rule
                        // that sends some requests to a different host will, on
                        // a coalesced h2 connection, tear the whole connection
                        // down (cancelling every in-flight stream) the moment
                        // such a request arrives — the client then re-opens and
                        // may re-coalesce, so traffic split across hosts by rule
                        // can thrash. Scoping the teardown to the offending
                        // stream isn't possible with one upstream leg; a true
                        // multi-host h2 proxy would need per-authority outer legs.
                        guard self.resolvedUpstreamMatchesDialed() else {
                            logger.warning("[MITM] \(self.dstHost): request resolved an upstream different from the dialed one; tearing down so the client retries")
                            self.cancel(error: nil)
                            return
                        }
                        // Post-dial: forward upstream, then the paced body (if any)
                        // after the HEADERS/DATA it belongs behind.
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
                        // Pre-dial: the first request that needs the upstream.
                        // Buffer it and kick off the deferred dial.
                        self.bufferUpstreamAndDial(transformed, inner: inner)
                    }
                }
                self.inbound.feed(data, completion: handle)
            }
        }
    }

    /// Pre-dial handler for the first upstream-bound bytes. Buffers them
    /// (capped like ``pendingClientBytes``) and, on the first call, resolves the
    /// upstream from the request's transparent rewrite (or the original
    /// destination when there was none) and invokes the ``dialer``. Subsequent
    /// calls — more body or pipelined requests arriving while the dial runs —
    /// only accumulate. Always re-arms the inbound read.
    private func bufferUpstreamAndDial(_ transformed: Data, inner: TLSRecordConnection) {
        if pendingUpstreamBytes.count + transformed.count > Self.maxPendingClientBytes {
            logger.warning("[MITM] \(dstHost): pre-dial upstream buffer would exceed \(Self.maxPendingClientBytes) B; tearing down session")
            cancel(error: nil)
            return
        }
        pendingUpstreamBytes.append(transformed)
        if dialing {
            // A request pipelined while the first dial is in flight that
            // resolves a different upstream can't be reached on this leg; tear
            // down rather than flushing it to the dialed host once the handshake
            // completes.
            guard resolvedUpstreamMatchesDialed() else {
                logger.warning("[MITM] \(dstHost): pipelined request resolved an upstream different from the dialed one; tearing down so the client retries")
                cancel(error: nil)
                return
            }
            startInboundPump(inner: inner)
            return
        }
        dialing = true
        // First-request-wins for the connection's upstream: a transparent
        // rewrite on the first request surfaces the replacement host/port,
        // otherwise dial the original destination.
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

    /// Whether the upstream the rewriters now resolve still matches the one the
    /// connection dialed. The dial commits to the first request's upstream; a
    /// later request whose transparent rewrite resolves a different host/port
    /// can't be reached on this leg, so the caller tears down (the client
    /// retries it on a fresh connection) rather than forwarding it to the dialed
    /// host. Uses the same host/port + original-destination fallback the dial
    /// resolved with. True before the dial — there is nothing to diverge from.
    private func resolvedUpstreamMatchesDialed() -> Bool {
        guard let dialedHost, let dialedPort else { return true }
        let resolved = inbound.resolvedUpstream
        return (resolved?.host ?? dstHost) == dialedHost
            && (resolved?.port ?? dstPort) == dialedPort
    }

    /// Invoked (on the lwIP queue) when the HTTP/1 response leg detects a
    /// protocol switch (101) or CONNECT tunnel. The response leg has already
    /// entered passthrough; flip the request leg too and forward whatever it had
    /// buffered to the upstream, so the now-opaque client→server byte stream
    /// flows instead of piling up unparsed in the request leg's head parser
    /// (the WebSocket / tunnel deadlock). HTTP/2 has its own CONNECT handling,
    /// so this fires only on the HTTP/1 path.
    private func handleResponseUpgrade() {
        guard !torn else { return }
        let buffered = requestStream.forcePassthrough()
        guard !buffered.isEmpty, let outer = outerRecord else { return }
        sendChunked(buffered, via: outer) { [weak self] sendError in
            guard let self, let sendError else { return }
            self.lwipQueue.async { self.cancel(error: sendError) }
        }
    }

    /// Reads plaintext from the outer record (= what the real server sent)
    /// and writes it to the inner record (= towards the client).
    private func startOutboundPump(inner: TLSRecordConnection, outer: TLSRecordConnection) {
        outer.receive { [weak self] data, error in
            guard let self else { return }
            self.lwipQueue.async {
                if let error {
                    self.cancel(error: error)
                    return
                }
                guard let data, !data.isEmpty else {
                    // Upstream half-closed. For an HTTP/1 read-until-close
                    // body the close *is* the body terminator, so give the
                    // response stream a chance to run a buffered script on
                    // what it accumulated and flush the rewritten response
                    // to the client before teardown. HTTP/2 frames every
                    // body with END_STREAM, so it never withholds anything
                    // here. ``finish`` is completion-based: if it parks on a
                    // buffered until-close script, teardown waits for the
                    // resume to deliver the flushed bytes.
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
                // Completion runs on lwipQueue — inline when no script ran,
                // or later from the parked resume. Forwards the peer-bound
                // bytes to the client, then re-arms the read.
                let handle: (Data) -> Void = { [weak self] transformed in
                    guard let self, !self.torn else { return }
                    // Drain the outbound leg's queued server-bound bytes and send
                    // them to the server: flow-control credit it issued for a
                    // buffered response body (so the server keeps sending while the
                    // body is held instead of stalling at its window), plus any
                    // paced request-body DATA a server WINDOW_UPDATE just unblocked
                    // (see ``MITMHTTP2Connection.queuePacedServerRequest``). Mirrors
                    // the inbound leg's pendingClientBytes drain; HTTP/1 has neither.
                    let serverCredit = self.outbound.drainPendingServerBytes()
                    if !serverCredit.isEmpty {
                        self.sendChunked(serverCredit, via: outer) { [weak self] sendError in
                            guard let self, let sendError else { return }
                            self.lwipQueue.async { self.cancel(error: sendError) }
                        }
                    }
                    // A buffered-rewrite response body that overflowed the
                    // client's flow-control window was handed to the inbound leg
                    // during this outbound feed (see
                    // ``MITMHTTP2Connection.onPacedResponse``). Its HEADERS + first
                    // window now sit in the inbound leg's client-bound buffer;
                    // flush them toward the client now rather than waiting on the
                    // next inbound read — which may never come if the client is
                    // blocked awaiting this very response. The remainder drains
                    // later as the client's WINDOW_UPDATEs arrive on the inbound
                    // pump. Inner-leg sends are serialized, so this and the
                    // ``transformed`` bytes (other streams) keep their wire order.
                    // nil/empty for HTTP/1 and whenever no handoff occurred.
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
        // Inner-side wire bytes (ServerHello, encrypted handshake, alerts)
        // — forward to the client via the lwIP-attached sink.
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

        // When the client negotiated h2, the inbound translator must exist now
        // so it can decode the first request's HEADERS before the deferred
        // outer leg is dialed. The outbound translator is created after the
        // dial in ``finishDialAndShuttle``. http/1.1 uses ``requestStream``.
        if record.negotiatedALPN == "h2" {
            inboundH2 = MITMHTTP2Connection(direction: .inbound, rewriter: h2Rewriter, flowController: h2FlowController, lwipQueue: lwipQueue)
        }
        startInboundPump(inner: record)
    }

    func tlsServer(_ server: TLSServer, didFail error: TLSError) {
        cancel(error: error)
    }
}
