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
    private let proxyConnection: ProxyConnection
    private let proxyClient: ProxyClient?

    /// Bytes received from the client before the inner ``TLSServer`` was
    /// created. Always begins with a complete ClientHello; may also
    /// contain bytes the client pushed while we were finishing the outer
    /// handshake. Drained into ``TLSServer/feed(_:)`` once the inner leg
    /// starts.
    private var pendingClientBytes: Data

    private var tlsServer: TLSServer?
    private var tlsClient: TLSClient?

    private let innerTransport: InnerTransport

    /// Inner record connection (post-handshake) — encrypts/decrypts to the
    /// client. Plaintext on the inside.
    private var innerRecord: TLSRecordConnection?
    /// Outer record connection (post-handshake) — encrypts/decrypts to the
    /// real server. Plaintext on the inside.
    private var outerRecord: TLSRecordConnection?

    private let rewriter = MITMRewriter()
    private let h2Rewriter = MITMHTTP2Rewriter()

    /// HTTP/2 frame translators — populated only when both legs
    /// negotiated `h2` ALPN. ``inboundH2`` rewrites the client → server
    /// direction; ``outboundH2`` rewrites the server → client direction.
    private var inboundH2: MITMHTTP2Connection?
    private var outboundH2: MITMHTTP2Connection?

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
        proxyClient: ProxyClient?,
        proxyConnection: ProxyConnection,
        lwipQueue: DispatchQueue
    ) {
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.pendingClientBytes = clientHello
        self.leafCache = leafCache
        self.proxyClient = proxyClient
        self.proxyConnection = proxyConnection
        self.lwipQueue = lwipQueue
        self.innerTransport = InnerTransport(queue: lwipQueue)
    }

    // MARK: - Lifecycle

    /// Starts the outer handshake first; the inner handshake follows once
    /// the outer leg has negotiated an ALPN, so both sides commit to the
    /// same application protocol (h2 or http/1.1). Must be called on
    /// `lwipQueue`.
    func start(sni: String) {
        // Pull the client's ALPN preferences out of the buffered
        // ClientHello so we offer the same set upstream.
        let clientALPNs = parseClientALPNs(from: pendingClientBytes)
        startOuterHandshake(sni: sni, alpns: clientALPNs)
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
        innerTransport.forceCancel()
        onTeardown?(error)
    }

    // MARK: - Inner Handshake

    /// Starts the inner-leg TLS server. Called only after the outer leg
    /// has finished negotiating ALPN, so we can advertise the matching
    /// protocol back to the client.
    private func startInnerHandshake(sni: String, alpn: String) {
        do {
            let leaf = try leafCache.leaf(for: sni)
            let server = TLSServer(
                leafCert: leaf.certificate,
                leafCertDER: leaf.certificateDER,
                leafPrivateKey: leaf.privateKeySecKey,
                leafSigningKeyP256: leaf.privateKey,
                acceptableALPNs: [alpn]
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

    // MARK: - Outer Handshake

    private func startOuterHandshake(sni: String, alpns: [String]) {
        // NOTE: ``minVersion`` / ``maxVersion`` here are decorative —
        // ``TLSClient`` doesn't enforce them for browser-fingerprinted
        // ClientHellos, so the upstream may negotiate either TLS 1.2 or
        // TLS 1.3. ALPN is observed correctly in both cases (TLS 1.3 in
        // EncryptedExtensions, TLS 1.2 in ServerHello). If we ever need
        // a hard version floor, ``TLSClient`` must alert on a TLS 1.2
        // ServerHello when ``maxVersion == .tls13``.
        let configuration = TLSConfiguration(
            serverName: sni,
            alpn: alpns.isEmpty ? ["h2", "http/1.1"] : alpns,
            fingerprint: .chrome133,
            minVersion: .tls13,
            maxVersion: .tls13
        )
        let client = TLSClient(configuration: configuration)
        tlsClient = client

        client.connect(overTunnel: proxyConnection) { [weak self] result in
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
                    self.startInnerHandshake(sni: sni, alpn: alpn)
                case .failure(let error):
                    logger.error("[MITM] Outer handshake failed for \(self.dstHost): \(error)")
                    self.cancel(error: error)
                }
            }
        }
    }

    // MARK: - ALPN parsing

    /// Best-effort extraction of the client's ALPN list out of a buffered
    /// TLS ClientHello. Returns an empty list when parsing fails — the
    /// caller falls back to a default offer.
    private func parseClientALPNs(from buffer: Data) -> [String] {
        guard !buffer.isEmpty else { return [] }
        guard let parsed = try? TLSClientHelloParser.parse(buffer) else { return [] }
        return parsed.alpnProtocols
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
                    transformed = self.rewriter.transformRequest(data)
                }
                guard !transformed.isEmpty else {
                    // The h2 translator may have buffered fragments
                    // (CONTINUATION pending, partial preface, etc.).
                    // Loop back for more bytes without writing.
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
                    transformed = self.rewriter.transformResponse(data)
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
        tryStartShuttling()
    }

    func tlsServer(_ server: TLSServer, didFail error: TLSError) {
        logger.error("[MITM] Inner handshake failed for \(dstHost): \(error)")
        cancel(error: error)
    }
}
