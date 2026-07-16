//
//  WebSocketConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated final class WebSocketConnection: Sendable {

    // MARK: Transport

    private let transport: AsyncTransportClosures

    // MARK: State

    private let configuration: WebSocketConfiguration

    private struct ConnectionState {
        var isConnected = false
        var upgraded = false
        var receiveBuffer = Data()
        var heartbeatTask: Task<Void, Never>?
    }

    private let state: Mutex<ConnectionState>

    /// Caps receive buffer growth (1 MB) against a misbehaving server.
    private static let maxReceiveBufferSize = 1_048_576

    static let chromeUserAgent = ProxyUserAgent.chrome

    var isConnected: Bool {
        state.withLock { $0.isConnected }
    }

    // MARK: - Initializers

    init(transport: AsyncTransportClosures, configuration: WebSocketConfiguration) {
        self.configuration = configuration
        self.transport = transport
        self.state = Mutex(ConnectionState(isConnected: true))
    }

    convenience init(transport: any AsyncByteTransport, configuration: WebSocketConfiguration) {
        self.init(transport: AsyncTransportClosures(transport), configuration: configuration)
    }

    convenience init(tlsConnection: TLSRecordConnection, configuration: WebSocketConfiguration) {
        self.init(transport: AsyncTransportClosures(tls: tlsConnection), configuration: configuration)
    }

    convenience init(tunnel: ProxyConnection, configuration: WebSocketConfiguration) {
        self.init(transport: AsyncTransportClosures(proxyConnection: tunnel), configuration: configuration)
    }

    // MARK: - HTTP Upgrade Handshake

    /// Performs the WebSocket HTTP upgrade handshake, optionally embedding early data in a request header.
    func performUpgrade(earlyData: Data? = nil) async throws {
        var keyBytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &keyBytes)
        let wsKey = Data(keyBytes).base64EncodedString()

        var request = "GET \(configuration.normalizedPath) HTTP/1.1\r\n"
        request += "Host: \(configuration.host)\r\n"
        request += "Upgrade: websocket\r\n"
        request += "Connection: Upgrade\r\n"
        request += "Sec-WebSocket-Key: \(wsKey)\r\n"
        request += "Sec-WebSocket-Version: 13\r\n"

        for (key, value) in configuration.headers {
            request += "\(key): \(value)\r\n"
        }

        if !configuration.headers.keys.contains(where: { $0.lowercased() == "user-agent" }) {
            request += "User-Agent: \(Self.chromeUserAgent)\r\n"
        }

        if let earlyData, !earlyData.isEmpty, configuration.maxEarlyData > 0 {
            let dataToEmbed = earlyData.prefix(configuration.maxEarlyData)
            let encoded = dataToEmbed.base64URLEncodedString()
            request += "\(configuration.earlyDataHeaderName): \(encoded)\r\n"
        }

        request += "\r\n"

        guard let requestData = request.data(using: .utf8) else {
            throw WebSocketError.upgradeFailed("Failed to encode upgrade request")
        }

        do {
            try await transport.send(requestData)
        } catch {
            throw WebSocketError.upgradeFailed(error.localizedDescription)
        }

        try await receiveUpgradeResponse()
    }

    /// Reads the HTTP 101 response, buffers any leftover data after the header.
    private func receiveUpgradeResponse() async throws {
        while true {
            let chunk: TransportChunk
            do {
                chunk = try await transport.receive()
            } catch {
                throw WebSocketError.upgradeFailed(error.localizedDescription)
            }

            guard case .bytes(let data) = chunk, !data.isEmpty else {
                throw WebSocketError.upgradeFailed("Empty response from server")
            }

            let headerData: Data? = self.state.withLock { state in
                state.receiveBuffer.append(data)

                let headerEnd: Data = Data([0x0D, 0x0A, 0x0D, 0x0A]) // \r\n\r\n
                guard let range = state.receiveBuffer.range(of: headerEnd) else {
                    return nil
                }

                let header = Data(state.receiveBuffer[state.receiveBuffer.startIndex..<range.lowerBound])
                let leftover = state.receiveBuffer[range.upperBound...]
                state.receiveBuffer = Data(leftover)
                return header
            }

            guard let headerData else {
                continue // need more bytes
            }

            guard let headerString = String(data: headerData, encoding: .utf8) else {
                throw WebSocketError.upgradeFailed("Cannot decode response headers")
            }

            let firstLine = headerString.split(separator: "\r\n", maxSplits: 1).first ?? ""
            guard firstLine.contains("101") else {
                throw WebSocketError.upgradeFailed("Expected HTTP 101, got: \(firstLine)")
            }

            self.state.withLock { $0.upgraded = true }
            self.startHeartbeat()
            return
        }
    }

    // MARK: - Public API

    /// Sends data as a binary WebSocket frame (masked, opcode 0x02).
    func send(_ data: Data) async throws {
        let frame = buildFrame(opcode: 0x02, payload: data)
        try await transport.send(frame)
    }

    /// Receives one application-data frame; `nil` signals a clean close (EOF). Ping/Pong/Close
    /// control frames are handled inline (auto-Pong, Close acknowledgement) without surfacing.
    func receive() async throws -> Data? {
        while true {
            if let result = state.withLock({ tryExtractFrame(&$0) }) {
                switch result {
                case .binary(let data):
                    return data
                case .ping(let payload):
                    // RFC 6455: echo payload in Pong (best-effort), then keep reading.
                    let pongFrame = buildFrame(opcode: 0x0A, payload: payload)
                    try? await transport.send(pongFrame)
                    continue
                case .pong:
                    continue
                case .close(let code, let reason):
                    var closePayload = Data()
                    closePayload.append(UInt8(code >> 8))
                    closePayload.append(UInt8(code & 0xFF))
                    let closeFrame = buildFrame(opcode: 0x08, payload: closePayload)
                    try? await transport.send(closeFrame)
                    state.withLock { $0.isConnected = false }
                    // A normal (1000) or no-status (1005) close is a graceful end-of-stream, not a
                    // failure — surface it as EOF so callers half-close instead of resetting.
                    if code == 1000 || code == 1005 {
                        return nil
                    }
                    throw WebSocketError.connectionClosed(code, reason)
                }
            }

            // No complete frame buffered: read more bytes.
            guard case .bytes(let data) = try await transport.receive(), !data.isEmpty else {
                return nil // EOF
            }

            let overflow: Bool = state.withLock { state in
                state.receiveBuffer.append(data)
                if state.receiveBuffer.count > Self.maxReceiveBufferSize {
                    state.receiveBuffer.removeAll()
                    return true
                }
                return false
            }
            if overflow {
                throw WebSocketError.invalidFrame("Receive buffer exceeded limit")
            }
        }
    }

    func cancel() {
        state.withLock {
            $0.isConnected = false
            $0.receiveBuffer.removeAll()
            $0.heartbeatTask?.cancel()
            $0.heartbeatTask = nil
        }
        transport.cancel()
    }

    deinit {
        // Reclaim the heartbeat loop if dropped without cancel(); Task.cancel() is thread-safe.
        state.withLock { $0.heartbeatTask?.cancel() }
    }

    // MARK: - Heartbeat (Ping Sender)

    /// Periodic Ping sender (heartbeat); stops when a send fails.
    private func startHeartbeat() {
        let period = configuration.heartbeatPeriod
        guard period > 0 else { return }

        let task = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(period))
                guard !Task.isCancelled, let self, self.isConnected else { return }
                let pingFrame = self.buildFrame(opcode: 0x09, payload: Data())
                do {
                    try await self.transport.send(pingFrame)
                } catch {
                    return   // stop the heartbeat on send failure
                }
            }
        }
        state.withLock { $0.heartbeatTask = task }
    }

    // MARK: - Frame Building (Client → Server, MUST be masked)

    private func buildFrame(opcode: UInt8, payload: Data) -> Data {
        var frame = Data()

        // First byte: 0x80 sets FIN bit, low nibble is the opcode.
        frame.append(0x80 | opcode)

        // 0x80 on length byte sets the mask bit; client frames MUST be masked (RFC 6455 5.3).
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

        var maskKey = [UInt8](repeating: 0, count: 4)
        _ = SecRandomCopyBytes(kSecRandomDefault, 4, &maskKey)
        frame.append(contentsOf: maskKey)

        // XOR-masked payload — append then mask in-place to avoid a temporary copy
        let maskOffset = frame.count
        frame.append(payload)
        frame.withUnsafeMutableBytes { pointer in
            guard let base = pointer.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            for i in 0..<length {
                base[maskOffset + i] ^= maskKey[i & 3]
            }
        }

        return frame
    }

    // MARK: - Frame Parsing (Server → Client, NOT masked)

    private enum FrameResult {
        case binary(Data)
        case ping(Data)
        case pong(Data)
        case close(UInt16, String)
    }

    /// Tries to extract a complete frame from `receiveBuffer`. Call inside `state.withLock`.
    private func tryExtractFrame(_ state: inout ConnectionState) -> FrameResult? {
        guard state.receiveBuffer.count >= 2 else { return nil }
        let receiveBuffer = state.receiveBuffer

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
            payload = receiveBuffer.subdata(in: payloadStart..<payloadStart + Int(payloadLength))
        }

        // Copying the remainder into a new Data releases the original backing store.
        if totalFrameSize >= receiveBuffer.count {
            state.receiveBuffer = Data()
        } else {
            state.receiveBuffer = Data(receiveBuffer.suffix(from: receiveBuffer.startIndex + totalFrameSize))
        }

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
}
