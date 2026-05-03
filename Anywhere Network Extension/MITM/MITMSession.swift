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

    /// Bytes received from the client before the inner handshake began —
    /// at minimum a complete ClientHello.
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

    /// Starts both handshakes in parallel. Must be called on `lwipQueue`.
    func start(sni: String) {
        startInnerHandshake(sni: sni)
        startOuterHandshake(sni: sni)
    }

    /// Feeds bytes received from the client. While the inner handshake is
    /// running, bytes go to ``TLSServer``; afterwards, they land in the
    /// inner transport so ``TLSRecordConnection`` can decrypt them.
    func feedClientBytes(_ data: Data) {
        guard !torn else { return }
        if innerRecord != nil {
            innerTransport.feedFromClient(data)
        } else {
            tlsServer?.feed(data)
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

    private func startInnerHandshake(sni: String) {
        do {
            let leaf = try leafCache.leaf(for: sni)
            let server = TLSServer(
                leafCert: leaf.certificate,
                leafCertDER: leaf.certificateDER,
                leafPrivateKey: leaf.privateKeySecKey,
                leafSigningKeyP256: leaf.privateKey
            )
            server.delegate = self
            tlsServer = server

            // Drive in any bytes already buffered (the ClientHello at minimum).
            server.feed(pendingClientBytes)
            pendingClientBytes.removeAll(keepingCapacity: false)
        } catch {
            logger.error("[MITM] Inner handshake start failed for \(sni): \(error)")
            cancel(error: error)
        }
    }

    // MARK: - Outer Handshake

    private func startOuterHandshake(sni: String) {
        let configuration = TLSConfiguration(
            serverName: sni,
            alpn: ["http/1.1"],
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
                    self.tryStartShuttling()
                case .failure(let error):
                    logger.error("[MITM] Outer handshake failed for \(self.dstHost): \(error)")
                    self.cancel(error: error)
                }
            }
        }
    }

    // MARK: - Shuttle

    private func tryStartShuttling() {
        guard let innerRecord, let outerRecord else { return }
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
                let transformed = self.rewriter.transformRequest(data)
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
                let transformed = self.rewriter.transformResponse(data)
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
