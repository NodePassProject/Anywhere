//
//  WebSocketConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

// MARK: - WebSocketConnection

/// WebSocket connection implementing RFC 6455 framing over an arbitrary transport.
///
/// Closure-based transport abstraction avoids modifying ``BSDSocket`` or ``TLSRecordConnection``.
class WebSocketConnection {

    // MARK: Transport closures

    private let transportSend: (Data, @escaping (Error?) -> Void) -> Void
    private let transportReceive: (@escaping (Data?, Bool, Error?) -> Void) -> Void
    private let transportCancel: () -> Void

    // MARK: State

    private let configuration: WebSocketConfiguration
    private var receiveBuffer = Data()
    private let lock = UnfairLock()
    private var _isConnected = false
    private var upgraded = false
    private var heartbeatTimer: DispatchSourceTimer?

    /// Chrome User-Agent string matching Xray-core's `utils.ChromeUA`.
    /// Uses a fixed base version (Chrome 144, released 2026-01-13) and advances
    /// by one version every ~35 days (midpoint of Xray-core's 25-45 day range).
    static let chromeUserAgent: String = {
        let baseVersion = 144
        let baseDate = DateComponents(calendar: Calendar(identifier: .gregorian),
                                      timeZone: TimeZone(identifier: "UTC"),
                                      year: 2026, month: 1, day: 13).date!
        let daysSinceBase = max(0, Int(Date().timeIntervalSince(baseDate) / 86400))
        let version = baseVersion + daysSinceBase / 35
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/\(version).0.0.0 Safari/537.36"
    }()

    var isConnected: Bool {
        lock.lock()
        let v = _isConnected
        lock.unlock()
        return v
    }

    // MARK: - Initializers

    /// Creates a WebSocket connection over a plain BSD socket.
    init(socket: BSDSocket, configuration: WebSocketConfiguration) {
        self.configuration = configuration
        self.transportSend = { data, completion in
            socket.send(data: data, completion: completion)
        }
        self.transportReceive = { completion in
            socket.receive(maximumLength: 65536, completion: completion)
        }
        self.transportCancel = {
            socket.forceCancel()
        }
        self._isConnected = true
    }

    /// Creates a WebSocket connection over a TLS record connection (WSS).
    init(tlsConnection: TLSRecordConnection, configuration: WebSocketConfiguration) {
        self.configuration = configuration
        self.transportSend = { data, completion in
            tlsConnection.send(data: data, completion: completion)
        }
        self.transportReceive = { completion in
            tlsConnection.receive { data, error in
                completion(data, false, error)
            }
        }
        self.transportCancel = {
            tlsConnection.cancel()
        }
        self._isConnected = true
    }

    // MARK: - HTTP Upgrade Handshake

    /// Performs the WebSocket HTTP upgrade handshake.
    ///
    /// - Parameters:
    ///   - earlyData: Optional early data to embed in the upgrade request header.
    ///   - completion: Called with `nil` on success or an error on failure.
    func performUpgrade(earlyData: Data? = nil, completion: @escaping (Error?) -> Void) {
        // Generate 16-byte random key, base64-encoded
        var keyBytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &keyBytes)
        let wsKey = Data(keyBytes).base64EncodedString()

        // Build HTTP upgrade request
        var request = "GET \(configuration.path) HTTP/1.1\r\n"
        request += "Host: \(configuration.host)\r\n"
        request += "Upgrade: websocket\r\n"
        request += "Connection: Upgrade\r\n"
        request += "Sec-WebSocket-Key: \(wsKey)\r\n"
        request += "Sec-WebSocket-Version: 13\r\n"

        // Custom headers from configuration
        for (key, value) in configuration.headers {
            request += "\(key): \(value)\r\n"
        }

        // Default User-Agent (Chrome UA) if not set in custom headers.
        // Matches Xray-core's GetRequestHeader() which sets utils.ChromeUA.
        if !configuration.headers.keys.contains(where: { $0.lowercased() == "user-agent" }) {
            request += "User-Agent: \(Self.chromeUserAgent)\r\n"
        }

        // Early data: base64url-encode and place in the configured header
        if let earlyData, !earlyData.isEmpty, configuration.maxEarlyData > 0 {
            let dataToEmbed = earlyData.prefix(configuration.maxEarlyData)
            let encoded = Self.base64URLEncode(dataToEmbed)
            request += "\(configuration.earlyDataHeaderName): \(encoded)\r\n"
        }

        request += "\r\n"

        guard let requestData = request.data(using: .utf8) else {
            completion(WebSocketError.upgradeFailed("Failed to encode upgrade request"))
            return
        }

        transportSend(requestData) { [weak self] error in
            if let error {
                completion(WebSocketError.upgradeFailed(error.localizedDescription))
                return
            }
            self?.receiveUpgradeResponse(completion: completion)
        }
    }

    /// Reads the HTTP 101 response, buffers any leftover data after the header.
    private func receiveUpgradeResponse(completion: @escaping (Error?) -> Void) {
        transportReceive { [weak self] data, _, error in
            guard let self else {
                completion(WebSocketError.upgradeFailed("Connection deallocated"))
                return
            }

            if let error {
                completion(WebSocketError.upgradeFailed(error.localizedDescription))
                return
            }

            guard let data, !data.isEmpty else {
                completion(WebSocketError.upgradeFailed("Empty response from server"))
                return
            }

            self.lock.lock()
            self.receiveBuffer.append(data)

            // Look for the end of HTTP headers
            let headerEnd: Data = Data([0x0D, 0x0A, 0x0D, 0x0A]) // \r\n\r\n
            guard let range = self.receiveBuffer.range(of: headerEnd) else {
                self.lock.unlock()
                // Haven't received the full header yet, keep reading
                self.receiveUpgradeResponse(completion: completion)
                return
            }

            let headerData = self.receiveBuffer[self.receiveBuffer.startIndex..<range.lowerBound]
            let leftover = self.receiveBuffer[range.upperBound...]

            // Replace buffer with any leftover data after headers
            self.receiveBuffer = Data(leftover)
            self.lock.unlock()

            // Validate HTTP 101 response
            guard let headerString = String(data: Data(headerData), encoding: .utf8) else {
                completion(WebSocketError.upgradeFailed("Cannot decode response headers"))
                return
            }

            let firstLine = headerString.split(separator: "\r\n", maxSplits: 1).first ?? ""
            guard firstLine.contains("101") else {
                completion(WebSocketError.upgradeFailed("Expected HTTP 101, got: \(firstLine)"))
                return
            }

            self.lock.lock()
            self.upgraded = true
            self.lock.unlock()
            self.startHeartbeat()
            completion(nil)
        }
    }

    // MARK: - Public API

    /// Sends data as a binary WebSocket frame (masked, opcode 0x02).
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        let frame = buildFrame(opcode: 0x02, payload: data)
        transportSend(frame, completion)
    }

    /// Sends data as a binary WebSocket frame without tracking completion.
    func send(data: Data) {
        send(data: data) { _ in }
    }

    /// Receives a complete WebSocket frame payload.
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        // Try to extract a frame from the existing buffer first
        if let result = tryExtractFrame() {
            lock.unlock()
            handleFrameResult(result, completion: completion)
            return
        }
        lock.unlock()

        // Need more data
        receiveMore(completion: completion)
    }

    /// Cancels the connection.
    func cancel() {
        lock.lock()
        _isConnected = false
        receiveBuffer.removeAll()
        heartbeatTimer?.cancel()
        heartbeatTimer = nil
        lock.unlock()
        transportCancel()
    }

    // MARK: - Heartbeat (Ping Sender)

    /// Starts a periodic ping sender matching Xray-core's heartbeat behavior.
    /// Sends a WebSocket Ping frame every `heartbeatPeriod` seconds.
    /// Stops automatically if the send fails (connection closed).
    private func startHeartbeat() {
        let period = configuration.heartbeatPeriod
        guard period > 0 else { return }

        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + .seconds(Int(period)),
                       repeating: .seconds(Int(period)))
        timer.setEventHandler { [weak self] in
            guard let self, self.isConnected else {
                self?.lock.lock()
                self?.heartbeatTimer?.cancel()
                self?.heartbeatTimer = nil
                self?.lock.unlock()
                return
            }
            let pingFrame = self.buildFrame(opcode: 0x09, payload: Data())
            self.transportSend(pingFrame) { [weak self] error in
                if error != nil {
                    self?.lock.lock()
                    self?.heartbeatTimer?.cancel()
                    self?.heartbeatTimer = nil
                    self?.lock.unlock()
                }
            }
        }

        lock.lock()
        heartbeatTimer = timer
        lock.unlock()
        timer.resume()
    }

    // MARK: - Frame Building (Client → Server, MUST be masked)

    /// Builds a WebSocket frame with masking (client → server).
    private func buildFrame(opcode: UInt8, payload: Data) -> Data {
        var frame = Data()

        // FIN=1, opcode
        frame.append(0x80 | opcode)

        // Mask bit = 1 (client frames are always masked) + payload length
        let length = payload.count
        if length <= 125 {
            frame.append(UInt8(length) | 0x80)
        } else if length <= 65535 {
            frame.append(126 | 0x80)
            frame.append(UInt8((length >> 8) & 0xFF))
            frame.append(UInt8(length & 0xFF))
        } else {
            frame.append(127 | 0x80)
            for i in (0..<8).reversed() {
                frame.append(UInt8((length >> (i * 8)) & 0xFF))
            }
        }

        // 4-byte random mask key
        var maskKey = [UInt8](repeating: 0, count: 4)
        _ = SecRandomCopyBytes(kSecRandomDefault, 4, &maskKey)
        frame.append(contentsOf: maskKey)

        // XOR-masked payload
        var masked = [UInt8](repeating: 0, count: length)
        payload.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            for i in 0..<length {
                masked[i] = base[i] ^ maskKey[i & 3]
            }
        }
        frame.append(contentsOf: masked)

        return frame
    }

    // MARK: - Frame Parsing (Server → Client, NOT masked)

    /// Result of attempting to extract a frame from the buffer.
    private enum FrameResult {
        case binary(Data)
        case ping(Data)
        case pong(Data)
        case close(UInt16, String)
    }

    /// Tries to extract a complete frame from `receiveBuffer`. Must be called with `lock` held.
    private func tryExtractFrame() -> FrameResult? {
        guard receiveBuffer.count >= 2 else { return nil }

        let byte0 = receiveBuffer[receiveBuffer.startIndex]
        let byte1 = receiveBuffer[receiveBuffer.startIndex + 1]
        let isMasked = (byte1 & 0x80) != 0
        var payloadLength = UInt64(byte1 & 0x7F)
        var headerSize = 2

        if payloadLength == 126 {
            guard receiveBuffer.count >= 4 else { return nil }
            payloadLength = UInt64(receiveBuffer[receiveBuffer.startIndex + 2]) << 8
                          | UInt64(receiveBuffer[receiveBuffer.startIndex + 3])
            headerSize = 4
        } else if payloadLength == 127 {
            guard receiveBuffer.count >= 10 else { return nil }
            payloadLength = 0
            for i in 0..<8 {
                payloadLength = (payloadLength << 8) | UInt64(receiveBuffer[receiveBuffer.startIndex + 2 + i])
            }
            headerSize = 10
        }

        if isMasked {
            headerSize += 4
        }

        let totalFrameSize = headerSize + Int(payloadLength)
        guard receiveBuffer.count >= totalFrameSize else { return nil }

        // Extract payload
        var payload: Data
        if isMasked {
            let maskStart = headerSize - 4
            let maskKey = [
                receiveBuffer[receiveBuffer.startIndex + maskStart],
                receiveBuffer[receiveBuffer.startIndex + maskStart + 1],
                receiveBuffer[receiveBuffer.startIndex + maskStart + 2],
                receiveBuffer[receiveBuffer.startIndex + maskStart + 3]
            ]
            let payloadStart = receiveBuffer.startIndex + headerSize
            var bytes = [UInt8](repeating: 0, count: Int(payloadLength))
            for i in 0..<Int(payloadLength) {
                bytes[i] = receiveBuffer[payloadStart + i] ^ maskKey[i & 3]
            }
            payload = Data(bytes)
        } else {
            let payloadStart = receiveBuffer.startIndex + headerSize
            payload = Data(receiveBuffer[payloadStart..<payloadStart + Int(payloadLength)])
        }

        // Consume the frame from the buffer
        receiveBuffer.removeFirst(totalFrameSize)

        let opcode = byte0 & 0x0F
        switch opcode {
        case 0x01, 0x02: // Text or Binary
            return .binary(payload)
        case 0x08: // Close
            var code: UInt16 = 1005 // No status code
            var reason = ""
            if payload.count >= 2 {
                code = UInt16(payload[0]) << 8 | UInt16(payload[1])
                if payload.count > 2 {
                    reason = String(data: payload[2...], encoding: .utf8) ?? ""
                }
            }
            return .close(code, reason)
        case 0x09: // Ping
            return .ping(payload)
        case 0x0A: // Pong
            return .pong(payload)
        default:
            return .binary(payload)
        }
    }

    /// Handles a parsed frame result, auto-responding to pings and propagating close.
    private func handleFrameResult(_ result: FrameResult, completion: @escaping (Data?, Error?) -> Void) {
        switch result {
        case .binary(let data):
            completion(data, nil)
        case .ping(let payload):
            // Auto-respond with Pong containing the same payload
            let pongFrame = buildFrame(opcode: 0x0A, payload: payload)
            transportSend(pongFrame) { [weak self] _ in
                // Continue receiving the next data frame
                self?.receive(completion: completion)
            }
        case .pong:
            // Unsolicited pong, ignore and continue receiving
            receive(completion: completion)
        case .close(let code, let reason):
            // Echo close frame back
            var closePayload = Data()
            closePayload.append(UInt8(code >> 8))
            closePayload.append(UInt8(code & 0xFF))
            let closeFrame = buildFrame(opcode: 0x08, payload: closePayload)
            transportSend(closeFrame) { _ in }
            lock.lock()
            _isConnected = false
            lock.unlock()
            completion(nil, WebSocketError.connectionClosed(code, reason))
        }
    }

    /// Reads more data from the transport and tries to extract a frame.
    private func receiveMore(completion: @escaping (Data?, Error?) -> Void) {
        transportReceive { [weak self] data, _, error in
            guard let self else {
                completion(nil, WebSocketError.invalidFrame("Connection deallocated"))
                return
            }

            if let error {
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                completion(nil, nil) // EOF
                return
            }

            self.lock.lock()
            self.receiveBuffer.append(data)

            if let result = self.tryExtractFrame() {
                self.lock.unlock()
                self.handleFrameResult(result, completion: completion)
            } else {
                self.lock.unlock()
                // Still not enough data, keep reading
                self.receiveMore(completion: completion)
            }
        }
    }

    // MARK: - Base64URL Encoding

    /// RFC 4648 base64url encoding (no padding).
    private static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
