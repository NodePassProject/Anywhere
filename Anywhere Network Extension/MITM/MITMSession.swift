//
//  MITMSession.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

final class MITMSession {

    // MARK: - Inner Transport (RawTransport adapter for the lwIP side)

    /// Bidirectional pipe between the inner-leg TLS record connection and
    /// the lwIP-attached caller. Bytes written by ``TLSRecordConnection``
    /// get forwarded to ``onSendToClient``; bytes received from the client
    /// land via ``feedFromClient`` and feed any pending receive completion.
    final class InnerTransport: RawTransport {
        let queue: DispatchQueue
        var onSendToClient: ((Data, ((Error?) -> Void)?) -> Void)?

        private let lock = NSLock()
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
    private let rewriteTarget: MITMRewriteTarget?
    /// nil when the rule set's action synthesizes the response without an
    /// outer leg (``MITMRewriteAction/synthesizesResponse``). The
    /// transparent flow always sets it.
    private let proxyConnection: ProxyConnection?
    private let proxyClient: ProxyClient?

    /// True iff this session must produce its own response (302 / 200)
    /// without ever connecting upstream.
    private var synthesizesResponse: Bool {
        rewriteTarget?.action.synthesizesResponse ?? false
    }

    private var synthesizer: MITMResponseSynthesizer?

    /// Bytes received from the client before the inner ``TLSServer`` was
    /// created. Always begins with a complete ClientHello; may also
    /// contain bytes the client pushed while we were finishing the outer
    /// handshake. Drained into ``TLSServer/feed(_:)`` once the inner leg
    /// starts.
    private var pendingClientBytes: Data

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

    private let h2Rewriter: MITMHTTP2Rewriter

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
        policy: MITMRewritePolicy,
        rewriteTarget: MITMRewriteTarget?,
        proxyClient: ProxyClient?,
        proxyConnection: ProxyConnection?,
        lwipQueue: DispatchQueue
    ) {
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.pendingClientBytes = clientHello
        self.leafCache = leafCache
        self.policy = policy
        self.rewriteTarget = rewriteTarget
        self.proxyClient = proxyClient
        self.proxyConnection = proxyConnection
        self.lwipQueue = lwipQueue
        self.innerTransport = InnerTransport(queue: lwipQueue)
        // Authority string used to auto-rewrite Host (HTTP/1.1) and
        // :authority (HTTP/2) when a redirect is in play. Format follows
        // RFC 9112 section 3.2: bare host or "host:port".
        let effectiveAuthority: String? = rewriteTarget.map { target in
            if let port = target.port { return "\(target.host):\(port)" }
            return target.host
        }
        self.requestStream = MITMHTTP1Stream(
            host: dstHost,
            phase: .httpRequest,
            policy: policy,
            effectiveAuthority: effectiveAuthority
        )
        self.responseStream = MITMHTTP1Stream(
            host: dstHost,
            phase: .httpResponse,
            policy: policy,
            effectiveAuthority: nil // Host headers do not apply on responses.
        )
        self.h2Rewriter = MITMHTTP2Rewriter(
            host: dstHost,
            policy: policy,
            effectiveAuthority: effectiveAuthority
        )
    }

    // MARK: - Lifecycle

    /// Starts the outer handshake first; the inner handshake follows once
    /// the outer leg has negotiated an ALPN, so both sides commit to the
    /// same application protocol (h2 or http/1.1). Must be called on
    /// `lwipQueue`.
    ///
    /// In synthesize-response mode (302 / 200 reject), there is no outer
    /// leg. The inner handshake runs immediately, accepting both ALPNs
    /// (h2 and http/1.1) and both TLS versions the client supports, so
    /// the client's preference wins.
    func start(sni: String) {
        let parsed = parseClientHello(pendingClientBytes)
        let clientALPNs = parsed?.alpnProtocols ?? []
        let clientSupportsTLS13 = parsed?.supportedVersions.contains(0x0304) ?? true

        if synthesizesResponse {
            startSynthesizeOnlyInnerHandshake(
                sni: sni,
                clientALPNs: clientALPNs,
                clientSupportsTLS13: clientSupportsTLS13
            )
            return
        }

        // Outer SNI follows the redirect when present. The inner leaf
        // certificate uses ``sni`` so the client sees the requested host.
        let outerSNI = rewriteTarget?.host ?? sni
        startOuterHandshake(
            innerSNI: sni,
            outerSNI: outerSNI,
            alpns: clientALPNs,
            allowTLS13: clientSupportsTLS13
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
            // ``TLSServer`` once it is created.
            //
            // No size cap by design: a correct TLS client blocks on the
            // ServerHello after sending its ClientHello, so this buffer
            // stays at a few KB in the real-world flows we care about.
            // A misbehaving local app could push more, but the worst
            // case is bounded by the outer handshake's TCP timeout —
            // far short of the Network Extension's memory ceiling.
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
        tlsServer = nil
        tlsClient?.cancel()
        tlsClient = nil
        innerRecord?.cancel()
        innerRecord = nil
        outerRecord?.cancel()
        outerRecord = nil
        synthesizer = nil
        innerTransport.forceCancel()
        onTeardown?(error)
    }

    // MARK: - Synthesize-Response Mode

    /// Starts the response synthesizer once the inner TLS handshake has
    /// completed. The synthesizer handles request parsing and the canned
    /// response on its own; it calls back through ``onTeardown`` (via
    /// ``cancel(error:)``) once the response has been written or an
    /// unrecoverable error occurs.
    private func startResponseSynthesizer(inner: TLSRecordConnection, alpn: String) {
        guard let target = rewriteTarget else {
            cancel(error: nil)
            return
        }
        let httpVersion: MITMResponseSynthesizer.HTTPVersion = (alpn == "h2") ? .http2 : .http11
        let synth = MITMResponseSynthesizer(
            record: inner,
            httpVersion: httpVersion,
            target: target,
            queue: lwipQueue
        ) { [weak self] error in
            guard let self else { return }
            self.cancel(error: error)
        }
        self.synthesizer = synth
        synth.start()
    }

    // MARK: - Inner Handshake

    /// Starts the inner-leg TLS server. Called only after the outer leg
    /// has finished negotiating its TLS version + ALPN, so we can mirror
    /// both back to the client. Mirroring keeps the two legs feature-
    /// equivalent (h2 over TLS 1.2 on both sides, etc.) and prevents
    /// fingerprinting drift between what the user thinks they negotiated
    /// and what we negotiated upstream.
    private func startInnerHandshake(sni: String, alpn: String, tlsVersion: UInt16) {
        startInnerHandshake(sni: sni, alpns: [alpn], tlsVersions: [tlsVersion])
    }

    /// Multi-ALPN / multi-version variant used in synthesize-response
    /// mode, where there is no outer leg to mirror and the client's
    /// preference wins instead.
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
            // anything the client sent while we were finishing the outer
            // handshake).
            server.feed(pendingClientBytes)
            pendingClientBytes.removeAll(keepingCapacity: false)
        } catch {
            logger.error("[MITM] Inner handshake start failed for \(sni): \(error)")
            cancel(error: error)
        }
    }

    /// Synthesize-mode entry point. Picks ALPN and TLS version sets from
    /// the client's offer alone (no outer leg to mirror) and starts the
    /// inner handshake. Both ``http/1.1`` and ``h2`` are accepted; the
    /// client's preference order wins. Falls back to ``http/1.1`` when
    /// the client offered no ALPN.
    private func startSynthesizeOnlyInnerHandshake(
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

    private func startOuterHandshake(
        innerSNI: String,
        outerSNI: String,
        alpns: [String],
        allowTLS13: Bool
    ) {
        // ``TLSClient`` strips TLS 1.3 from the fingerprinted
        // supported_versions extension when ``maxVersion`` is set to
        // .tls12, so capping the outer leg here actually forces the
        // upstream to negotiate 1.2 even against 1.3-capable origins.
        // The inner leg then mirrors whichever version the outer leg
        // actually negotiated (see ``startInnerHandshake``).
        //
        // ALPN: if the inner client didn't offer ALPN, it expects
        // plaintext HTTP/1.1 by default. We must NOT let the outer leg
        // negotiate h2 in that case — we'd end up forwarding h2 binary
        // frames to a client that's parsing HTTP/1.1 text. Only offer
        // h2 upstream when the inner client opted in.
        let outerALPN: [String]
        if alpns.isEmpty {
            outerALPN = ["http/1.1"]
        } else {
            outerALPN = alpns
        }
        let configuration = TLSConfiguration(
            serverName: outerSNI,
            alpn: outerALPN,
            fingerprint: .chrome133,
            minVersion: .tls12,
            maxVersion: allowTLS13 ? .tls13 : .tls12
        )
        let client = TLSClient(configuration: configuration)
        tlsClient = client

        // The outer handshake path is only entered for actions that
        // require an upstream connection; ``proxyConnection`` is
        // guaranteed non-nil here. Synthesize-mode actions (302 / 200)
        // skip ``startOuterHandshake`` entirely in ``start(sni:)``.
        guard let outer = proxyConnection else {
            cancel(error: nil)
            return
        }
        client.connect(overTunnel: outer) { [weak self] result in
            guard let self else { return }
            self.lwipQueue.async {
                guard !self.torn else { return }
                switch result {
                case .success(let record):
                    self.outerRecord = record
                    // Inner handshake commits to whichever ALPN the upstream
                    // server chose; fall back to http/1.1 if the server
                    // omitted the extension.
                    let alpn = record.negotiatedALPN.isEmpty ? "http/1.1" : record.negotiatedALPN
                    self.startInnerHandshake(sni: innerSNI, alpn: alpn, tlsVersion: record.tlsVersion)
                case .failure(let error):
                    logger.error("[MITM] Outer handshake failed for \(self.dstHost): \(error)")
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

    private func tryStartShuttling() {
        guard let innerRecord, let outerRecord else { return }
        // Both legs commit to the same ALPN by construction (the inner
        // server is created with the outer's negotiated value as its
        // sole acceptable ALPN). When that value is `h2`, swap the
        // byte-stream rewriter for the frame-aware h2 translators.
        if innerRecord.negotiatedALPN == "h2", outerRecord.negotiatedALPN == "h2" {
            inboundH2 = MITMHTTP2Connection(direction: .inbound, rewriter: h2Rewriter)
            outboundH2 = MITMHTTP2Connection(direction: .outbound, rewriter: h2Rewriter)
        }
        startInboundPump(inner: innerRecord, outer: outerRecord)
        startOutboundPump(inner: innerRecord, outer: outerRecord)
    }

    /// Reads plaintext from the inner record (= what the client sent) and
    /// writes it to the outer record (= towards the real server).
    private func startInboundPump(inner: TLSRecordConnection, outer: TLSRecordConnection) {
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
                let transformed: Data
                if let inboundH2 = self.inboundH2 {
                    transformed = inboundH2.process(data)
                } else {
                    transformed = self.requestStream.transform(data)
                }
                guard !transformed.isEmpty else {
                    // The h2 translator or HTTP/1.1 stream may have
                    // buffered fragments (CONTINUATION pending, partial
                    // preface, body buffered for rewrite, etc.). Loop
                    // back for more bytes without writing.
                    self.startInboundPump(inner: inner, outer: outer)
                    return
                }
                outer.send(data: transformed) { sendError in
                    if let sendError {
                        self.lwipQueue.async { self.cancel(error: sendError) }
                        return
                    }
                    self.startInboundPump(inner: inner, outer: outer)
                }
            }
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
                    self.cancel(error: nil)
                    return
                }
                let transformed: Data
                if let outboundH2 = self.outboundH2 {
                    transformed = outboundH2.process(data)
                } else {
                    transformed = self.responseStream.transform(data)
                }
                guard !transformed.isEmpty else {
                    self.startOutboundPump(inner: inner, outer: outer)
                    return
                }
                inner.send(data: transformed) { sendError in
                    if let sendError {
                        self.lwipQueue.async { self.cancel(error: sendError) }
                        return
                    }
                    self.startOutboundPump(inner: inner, outer: outer)
                }
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

        if synthesizesResponse {
            startResponseSynthesizer(inner: record, alpn: alpn)
        } else {
            tryStartShuttling()
        }
    }

    func tlsServer(_ server: TLSServer, didFail error: TLSError) {
        logger.error("[MITM] Inner handshake failed for \(dstHost): \(error)")
        cancel(error: error)
    }
}
