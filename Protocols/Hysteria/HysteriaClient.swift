//
//  HysteriaClient.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation

private let logger = AnywhereLogger(category: "Hysteria")

// MARK: - HysteriaClient

/// Manages a single Hysteria QUIC connection to one server.
///
/// Multiple TCP streams and UDP sessions are multiplexed over the same QUIC connection.
/// The client handles:
/// 1. QUIC + TLS handshake (ALPN `h3`)
/// 2. HTTP/3 auth handshake (POST `/auth` → status 233)
/// 3. Opening TCP proxy streams (frame type 0x401)
/// 4. UDP proxy sessions via QUIC datagrams
class HysteriaClient {

    enum State {
        case idle, quicConnecting, authenticating, ready, closed
    }

    enum HysteriaError: Error, LocalizedError {
        case notReady
        case authFailed(String)
        case connectionFailed(String)
        case serverNoUDP
        case closed

        var errorDescription: String? {
            switch self {
            case .notReady: return "Hysteria: not ready"
            case .authFailed(let m): return "Hysteria auth failed: \(m)"
            case .connectionFailed(let m): return "Hysteria: \(m)"
            case .serverNoUDP: return "Hysteria: server does not support UDP"
            case .closed: return "Hysteria: closed"
            }
        }
    }

    // MARK: Properties

    private let host: String
    private let port: UInt16
    private let serverName: String
    private let auth: String

    private var state: State = .idle
    private let queue = DispatchQueue(label: "com.argsment.Anywhere.hysteria")

    private var quic: QUICConnection?
    private var serverSupportsUDP = false

    /// Auth stream — used for the initial POST /auth handshake.
    private var authStreamId: Int64 = -1
    private var authResponseBuffer = Data()
    private var authResponseHeadersParsed = false
    private var connectCompletion: ((Error?) -> Void)?

    /// Pending QUIC bytes on the auth stream that haven't been ACK'd yet.
    private var authPendingBytes = 0

    // TCP stream routing — maps QUIC stream ID to HysteriaConnection
    private var tcpStreams: [Int64: HysteriaConnection] = [:]

    // UDP session management
    private var udpSessions: [UInt32: HysteriaUDPSession] = [:]
    private var nextUDPSessionID: UInt32 = 1

    // MARK: Init

    init(host: String, port: UInt16, serverName: String, auth: String) {
        self.host = host
        self.port = port
        self.serverName = serverName
        self.auth = auth
    }

    // MARK: - Connect

    /// Establishes the QUIC connection and performs the Hysteria auth handshake.
    func connect(completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self, self.state == .idle else {
                completion(HysteriaError.notReady)
                return
            }
            self.state = .quicConnecting
            self.connectCompletion = completion

            let quicConn = QUICConnection(
                host: self.host,
                port: self.port,
                serverName: self.serverName,
                alpn: ["h3"],
                datagramsEnabled: true
            )
            self.quic = quicConn

            quicConn.connectionClosedHandler = { [weak self] error in
                guard let self else { return }
                self.queue.async {
                    guard self.state != .closed else { return }
                    self.state = .closed
                    // Fail pending connect
                    if let cb = self.connectCompletion {
                        self.connectCompletion = nil
                        cb(error)
                    }
                    // Close all UDP sessions
                    for (_, session) in self.udpSessions {
                        session.close(error: error)
                    }
                    self.udpSessions.removeAll()
                    self.tcpStreams.removeAll()
                }
                HysteriaClientPool.remove(host: self.host, port: self.port, client: self)
            }

            quicConn.streamDataHandler = { [weak self] streamId, data, fin in
                self?.queue.async {
                    self?.handleStreamData(streamId: streamId, data: data, fin: fin)
                }
            }

            quicConn.datagramHandler = { [weak self] data in
                self?.queue.async { self?.handleDatagram(data) }
            }

            quicConn.connect { [weak self] error in
                guard let self else { return }
                if let error {
                    self.queue.async {
                        self.state = .closed
                        self.connectCompletion?(error)
                        self.connectCompletion = nil
                    }
                    return
                }
                self.queue.async { self.performAuth() }
            }
        }
    }

    // MARK: - Auth Handshake

    /// Sends the HTTP/3 control stream + auth POST request.
    private func performAuth() {
        guard let quic else { return }

        // Open control stream (unidirectional, type 0x00) and send SETTINGS
        if let controlStream = quic.openUniStream() {
            var payload = Data()
            payload.append(0x00) // Control stream type
            payload.append(HTTP3Framer.clientSettingsFrame())
            quic.writeStream(controlStream, data: payload) { _ in }
        }
        // QPACK encoder/decoder streams
        if let enc = quic.openUniStream() {
            quic.writeStream(enc, data: Data([0x02])) { _ in }
        }
        if let dec = quic.openUniStream() {
            quic.writeStream(dec, data: Data([0x03])) { _ in }
        }

        // Open auth request stream (bidirectional)
        guard let streamId = quic.openBidiStream() else {
            connectCompletion?(HysteriaError.connectionFailed("Failed to open auth stream"))
            connectCompletion = nil
            return
        }
        authStreamId = streamId
        state = .authenticating

        // Build the auth POST request
        let padding = HysteriaPadding.generate(
            min: HysteriaConstants.authPaddingMin,
            max: HysteriaConstants.authPaddingMax
        )
        let paddingStr = String(data: padding, encoding: .utf8) ?? ""

        let headerBlock = QPACKEncoder.encodePostHeaders(
            authority: HysteriaConstants.urlHost,
            path: HysteriaConstants.urlPath,
            extraHeaders: [
                (name: HysteriaConstants.headerAuth.lowercased(), value: auth),
                (name: HysteriaConstants.headerCCRX.lowercased(), value: "0"),
                (name: HysteriaConstants.headerPadding.lowercased(), value: paddingStr),
            ]
        )
        let headersFrame = HTTP3Framer.headersFrame(headerBlock: headerBlock)

        quic.writeStream(streamId, data: headersFrame) { [weak self] error in
            if let error {
                self?.queue.async {
                    self?.connectCompletion?(error)
                    self?.connectCompletion = nil
                }
            }
        }
    }

    // MARK: - Stream Data Handling

    private func handleStreamData(streamId: Int64, data: Data, fin: Bool) {
        if streamId == authStreamId {
            handleAuthResponse(data, fin: fin)
            return
        }
        // Route to the HysteriaConnection for this TCP stream
        if let conn = tcpStreams[streamId] {
            conn.handleStreamData(data, fin: fin)
            if fin { tcpStreams[streamId] = nil }
        }
    }

    private func handleAuthResponse(_ data: Data, fin: Bool) {
        guard !data.isEmpty else { return }
        authPendingBytes += data.count
        authResponseBuffer.append(data)

        if !authResponseHeadersParsed {
            parseAuthResponseHeaders()
        }
    }

    /// Tears down the QUIC connection and reports an auth failure to the caller.
    /// The connectionClosedHandler will fire as a result of `quic.close()`, but
    /// it bails when `connectCompletion` is already nil, so the caller is
    /// notified exactly once.
    private func failAuth(_ error: Error) {
        let cb = connectCompletion
        connectCompletion = nil
        state = .closed
        quic?.close()
        quic = nil
        cb?(error)
    }

    private func parseAuthResponseHeaders() {
        guard let (frame, consumed) = HTTP3Framer.parseFrame(from: authResponseBuffer) else {
            return // Incomplete, wait for more data
        }
        guard frame.type == HTTP3FrameType.headers.rawValue else {
            failAuth(HysteriaError.authFailed("unexpected frame type \(frame.type)"))
            return
        }

        guard let headers = QPACKEncoder.decodeHeaders(from: frame.payload) else {
            failAuth(HysteriaError.authFailed("malformed QPACK header block"))
            return
        }
        let statusHeader = headers.first(where: { $0.name == ":status" })
        guard let status = statusHeader?.value, status == "\(HysteriaConstants.statusAuthOK)" else {
            let code = statusHeader?.value ?? "unknown"
            failAuth(HysteriaError.authFailed("status \(code)"))
            return
        }

        // Parse server capabilities
        for (name, value) in headers {
            switch name.lowercased() {
            case HysteriaConstants.headerUDPEnabled.lowercased():
                serverSupportsUDP = (value.lowercased() == "true")
            default:
                break
            }
        }

        authResponseHeadersParsed = true
        authResponseBuffer = Data(authResponseBuffer.dropFirst(consumed))

        // ACK consumed bytes
        if authPendingBytes > 0, let quic {
            quic.extendStreamOffset(authStreamId, count: authPendingBytes)
            authPendingBytes = 0
        }

        state = .ready
        connectCompletion?(nil)
        connectCompletion = nil
    }

    // MARK: - TCP Stream

    /// Opens a new TCP proxy stream and returns a `HysteriaConnection`.
    func openTCPStream(
        address: String,
        completion: @escaping (Result<HysteriaConnection, Error>) -> Void
    ) {
        queue.async { [weak self] in
            guard let self, let quic = self.quic, self.state == .ready else {
                completion(.failure(HysteriaError.notReady))
                return
            }
            guard let streamId = quic.openBidiStream() else {
                completion(.failure(HysteriaError.connectionFailed("Failed to open bidi stream")))
                return
            }

            let conn = HysteriaConnection(quic: quic, streamId: streamId, address: address, queue: self.queue, owner: self)
            self.tcpStreams[streamId] = conn

            // Send the full TCPRequest (frame type + address + padding) eagerly so
            // server-first protocols (SSH, SMTP, MySQL, …) don't stall waiting for
            // the client to write first.
            var request = QUICVarint.encode(HysteriaConstants.frameTypeTCPRequest)
            request.append(HysteriaTCPFraming.buildTCPRequest(address: address))
            quic.writeStream(streamId, data: request) { error in
                if let error {
                    self.queue.async { self.tcpStreams[streamId] = nil }
                    completion(.failure(error))
                } else {
                    completion(.success(conn))
                }
            }
        }
    }

    // MARK: - UDP Session

    /// Creates a new UDP session. Returns a session object that can send/receive
    /// UDP messages through QUIC datagrams.
    func openUDPSession(
        completion: @escaping (Result<HysteriaUDPSession, Error>) -> Void
    ) {
        queue.async { [weak self] in
            guard let self, let quic = self.quic, self.state == .ready else {
                completion(.failure(HysteriaError.notReady))
                return
            }
            guard self.serverSupportsUDP else {
                completion(.failure(HysteriaError.serverNoUDP))
                return
            }

            let sessionID = self.nextUDPSessionID
            self.nextUDPSessionID += 1

            let session = HysteriaUDPSession(
                sessionID: sessionID, quic: quic, queue: self.queue
            )
            self.udpSessions[sessionID] = session
            completion(.success(session))
        }
    }

    // MARK: - Internal Cleanup

    /// Removes a TCP stream from the routing table. Called by HysteriaConnection.cancel().
    func removeTCPStream(_ streamId: Int64) {
        queue.async { [weak self] in
            self?.tcpStreams[streamId] = nil
        }
    }

    /// Removes a UDP session from the session table. Called by HysteriaUDPConnection.cancel().
    func removeUDPSession(_ sessionID: UInt32) {
        queue.async { [weak self] in
            self?.udpSessions[sessionID] = nil
        }
    }

    // MARK: - Datagram Handling

    private func handleDatagram(_ data: Data) {
        guard data.count >= 4 else { return }
        let si = data.startIndex
        let sessionID = (UInt32(data[si]) << 24) | (UInt32(data[si + 1]) << 16)
                      | (UInt32(data[si + 2]) << 8) | UInt32(data[si + 3])

        guard let session = udpSessions[sessionID] else { return }
        session.feedDatagram(data)
    }

    // MARK: - Close

    func close() {
        queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            self.quic?.close()
            self.quic = nil
            for (_, session) in self.udpSessions {
                session.close(error: HysteriaError.closed)
            }
            self.udpSessions.removeAll()
            self.tcpStreams.removeAll()
        }
        HysteriaClientPool.remove(host: host, port: port, client: self)
    }

    /// Whether the QUIC connection is authenticated and ready.
    var isReady: Bool { state == .ready }
}

// MARK: - HysteriaUDPSession

/// Represents a single Hysteria UDP session multiplexed over QUIC datagrams.
class HysteriaUDPSession {
    let sessionID: UInt32
    private let quic: QUICConnection
    private let queue: DispatchQueue
    private let defragger = HysteriaDefragger()
    private var receivedMessages: [HysteriaUDPMessage] = []
    private var pendingReceive: ((HysteriaUDPMessage?, Error?) -> Void)?
    private var isClosed = false
    private var closeError: Error?

    init(sessionID: UInt32, quic: QUICConnection, queue: DispatchQueue) {
        self.sessionID = sessionID
        self.quic = quic
        self.queue = queue
    }

    /// Sends a UDP message via QUIC datagram, fragmenting if necessary.
    ///
    /// When fragmentation is needed, all fragments are queued atomically
    /// to prevent interleaving with fragments from other messages.
    func send(address: String, data: Data, completion: @escaping (Error?) -> Void) {
        let msg = HysteriaUDPMessage(
            sessionID: sessionID, packetID: 0,
            fragID: 0, fragCount: 1,
            address: address, data: data
        )

        // Use the actual max datagram payload negotiated with the remote peer.
        let maxSize = quic.maxDatagramPayloadSize
        guard maxSize > 0 else {
            completion(HysteriaClient.HysteriaError.connectionFailed("datagrams not supported by server"))
            return
        }

        if msg.totalSize <= maxSize {
            let serialized = msg.serialize()
            quic.writeDatagram(serialized, completion: completion)
        } else {
            // Fragment and send all fragments atomically so they aren't
            // interleaved with fragments from other concurrent sends.
            var fragMsg = msg
            fragMsg.packetID = UInt16.random(in: 1...UInt16.max)
            let fragments = HysteriaUDPFragmentation.fragment(fragMsg, maxSize: maxSize)
            let datagrams = fragments.map { $0.serialize() }
            quic.writeDatagrams(datagrams, completion: completion)
        }
    }

    /// Receives the next reassembled UDP message.
    func receive(completion: @escaping (HysteriaUDPMessage?, Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else {
                completion(nil, HysteriaClient.HysteriaError.closed)
                return
            }
            if !self.receivedMessages.isEmpty {
                let msg = self.receivedMessages.removeFirst()
                completion(msg, nil)
                return
            }
            if self.isClosed {
                completion(nil, self.closeError)
                return
            }
            self.pendingReceive = completion
        }
    }

    /// Called by HysteriaClient when a datagram arrives for this session.
    func feedDatagram(_ data: Data) {
        guard let msg = HysteriaUDPMessage.parse(data) else { return }
        guard let reassembled = defragger.feed(msg) else { return }

        if let pending = pendingReceive {
            pendingReceive = nil
            pending(reassembled, nil)
        } else {
            receivedMessages.append(reassembled)
        }
    }

    func close(error: Error?) {
        isClosed = true
        closeError = error
        if let pending = pendingReceive {
            pendingReceive = nil
            pending(nil, error ?? HysteriaClient.HysteriaError.closed)
        }
    }
}

// MARK: - Connection Pool

/// Global pool of Hysteria clients, keyed by server address.
/// Reuses existing QUIC connections when connecting to the same server.
/// Callers that arrive while a connection is in progress are queued and
/// notified once the connection completes (or fails).
enum HysteriaClientPool {
    private static let lock = UnfairLock()
    private static var clients: [String: HysteriaClient] = [:]
    /// Waiters for an in-progress connection, keyed by pool key.
    private static var waiters: [String: [(Result<HysteriaClient, Error>) -> Void]] = [:]

    /// Returns an existing ready client for the server, or creates a new one.
    /// Multiple callers for the same server are coalesced: only one connection
    /// attempt runs at a time, and all callers are notified when it completes.
    static func client(
        host: String, port: UInt16, serverName: String, auth: String,
        completion: @escaping (Result<HysteriaClient, Error>) -> Void
    ) {
        let key = "\(host):\(port)"

        lock.lock()

        // Already connected — return immediately
        if let existing = clients[key], existing.isReady {
            lock.unlock()
            completion(.success(existing))
            return
        }

        // Connection in progress — queue this caller
        if waiters[key] != nil {
            waiters[key]!.append(completion)
            lock.unlock()
            return
        }

        // First caller — start a new connection
        waiters[key] = [completion]

        let client = HysteriaClient(
            host: host,
            port: port,
            serverName: serverName,
            auth: auth
        )
        clients[key] = client
        lock.unlock()

        client.connect { error in
            lock.lock()
            let pending = waiters.removeValue(forKey: key) ?? []
            if let error {
                if clients[key] === client { clients[key] = nil }
                lock.unlock()
                for cb in pending { cb(.failure(error)) }
            } else {
                lock.unlock()
                for cb in pending { cb(.success(client)) }
            }
        }
    }

    /// Removes a client from the pool (e.g. on close or error). The client
    /// identity check ensures that a newer client that already replaced the
    /// closed one is not accidentally evicted.
    static func remove(host: String, port: UInt16, client: HysteriaClient) {
        let key = "\(host):\(port)"
        lock.lock()
        if clients[key] === client {
            clients[key] = nil
        }
        lock.unlock()
    }
}
