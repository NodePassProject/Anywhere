//
//  WebSocketConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated final class WebSocketConnection: Sendable {

    // MARK: Deadline

    private static let upgradeDeadline: Duration = .seconds(30)

    // MARK: Transport

    private let transport: any ByteTransport

    // MARK: State

    private let configuration: WebSocketConfiguration

    private enum Phase: PhaseTransitionable {
        case upgrading
        case open
        case closed
        case cancelled

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.upgrading, .open):
                return true
            case (_, .closed), (_, .cancelled):
                return old != .closed && old != .cancelled
            default:
                return false
            }
        }
    }

    private struct ConnectionState: PhaseHolding {
        var phase: Phase = .upgrading
        var receiveBuffer = Data()
        var heartbeatDeadline: DeadlineToken?
    }

    private let state: Mutex<ConnectionState>
    
    private static let maxReceiveBufferSize = 1_048_576

    private static let maxResponseHeaderSize = 65_536

    static let chromeUserAgent = ProxyUserAgent.chrome

    var isConnected: Bool {
        state.withLock { $0.phase == .open }
    }

    // MARK: - Initializers

    init(transport: any ByteTransport, configuration: WebSocketConfiguration) {
        self.configuration = configuration
        self.transport = transport
        self.state = Mutex(ConnectionState())
    }

    convenience init(tlsConnection: TLSRecordConnection, configuration: WebSocketConfiguration) {
        self.init(transport: TLSByteTransport(tlsConnection), configuration: configuration)
    }

    convenience init(tunnel: ProxyConnection, configuration: WebSocketConfiguration) {
        self.init(transport: TunneledTransport(tunnel: tunnel), configuration: configuration)
    }

    // MARK: - HTTP Upgrade Handshake

    func performUpgrade(earlyData: Data? = nil) async throws {
        try await withDialDeadline(Self.upgradeDeadline, onExpiry: {
            self.cancel()
        }, error: {
            AnywhereError.proxy(.webSocket, .upgradeFailed(detail: "handshake timed out"))
        }) {
            try await self.sendAndAwaitUpgrade(earlyData: earlyData)
        }
    }

    private func sendAndAwaitUpgrade(earlyData: Data?) async throws {
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
            throw AnywhereError.proxy(.webSocket, .upgradeFailed(detail: "Failed to encode upgrade request"))
        }

        do {
            try await transport.send(requestData)
        } catch {
            throw AnywhereError.capture(error, context: "WebSocket upgrade request")
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
                throw AnywhereError.capture(error, context: "WebSocket upgrade response")
            }

            guard case .bytes(let data) = chunk, !data.isEmpty else {
                throw AnywhereError.proxy(.webSocket, .upgradeFailed(detail: "Empty response from server"))
            }

            let headerData: Data? = try self.state.withLock { state in
                state.receiveBuffer.append(data)

                let headerEnd: Data = Data([0x0D, 0x0A, 0x0D, 0x0A]) // \r\n\r\n
                guard let range = state.receiveBuffer.range(of: headerEnd) else {
                    if state.receiveBuffer.count > Self.maxResponseHeaderSize {
                        throw AnywhereError.proxy(.webSocket, .upgradeFailed(detail: "response headers too large"))
                    }
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
                throw AnywhereError.proxy(.webSocket, .upgradeFailed(detail: "Cannot decode response headers"))
            }

            let firstLine = headerString.split(separator: "\r\n", maxSplits: 1).first ?? ""
            guard firstLine.contains("101") else {
                throw AnywhereError.proxy(.webSocket, .upgradeFailed(detail: "Expected HTTP 101, got: \(firstLine)"))
            }

            let opened: Bool = self.state.withLock { $0.transition(to: .open) }
            guard opened else {
                throw AnywhereError.proxy(.webSocket, .upgradeFailed(detail: "cancelled during upgrade"))
            }
            self.startHeartbeat()
            return
        }
    }

    // MARK: - Public API
    
    func send(_ data: Data) async throws {
        let frame = buildFrame(opcode: 0x02, payload: data)
        try await transport.send(frame)
    }
    
    func receive() async throws -> Data? {
        switch state.withLock({ $0.phase }) {
        case .upgrading:
            throw AnywhereError.proxy(.webSocket, .notReady)
        case .closed:
            return nil
        case .cancelled:
            throw AnywhereError.transport(.terminated)
        case .open:
            break
        }
        while true {
            if let result = state.withLock({ tryExtractFrame(&$0) }) {
                switch result {
                case .binary(let data):
                    if data.isEmpty { continue }
                    return data
                case .ping(let payload):
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
                    _ = state.withLock { $0.transition(to: .closed) }
                    if code == 1000 || code == 1005 {
                        return nil
                    }
                    throw AnywhereError.proxy(.webSocket, .webSocketClosed(code: code, reason: reason))
                }
            }
            
            guard case .bytes(let data) = try await transport.receive(), !data.isEmpty else {
                _ = state.withLock { $0.transition(to: .closed) }
                return nil
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
                throw AnywhereError.proxy(.webSocket, .protocolViolation(detail: "invalid frame: Receive buffer exceeded limit"))
            }
        }
    }

    func cancel() {
        state.withLock {
            $0.transition(to: .cancelled)
            $0.receiveBuffer.removeAll()
            $0.heartbeatDeadline?.cancel()
            $0.heartbeatDeadline = nil
        }
        transport.cancel()
    }

    deinit {
        state.withLock { $0.heartbeatDeadline?.cancel() }
    }

    // MARK: - Heartbeat
    
    private func startHeartbeat() {
        let period = configuration.heartbeatPeriod
        guard period > 0 else { return }

        state.withLock { state in
            guard state.phase == .open, state.heartbeatDeadline == nil else { return }
            state.heartbeatDeadline = scheduleHeartbeat(period: period)
        }
    }

    private func scheduleHeartbeat(period: UInt32) -> DeadlineToken {
        TickScheduler.shared.schedule(in: .seconds(period), precision: .relaxed) { [weak self] in
            guard let self else { return }
            Task { await self.heartbeatFired(period: period) }
        }
    }

    private func heartbeatFired(period: UInt32) async {
        guard isConnected else { return }
        let pingFrame = buildFrame(opcode: 0x09, payload: Data())
        do {
            try await transport.send(pingFrame)
        } catch {
            return
        }
        state.withLock { state in
            guard state.phase == .open, state.heartbeatDeadline != nil else { return }
            state.heartbeatDeadline = scheduleHeartbeat(period: period)
        }
    }

    // MARK: - Frame Building (Client → Server, MUST be masked)

    private func buildFrame(opcode: UInt8, payload: Data) -> Data {
        var frame = Data()
        frame.append(0x80 | opcode)
        
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
        
        guard payloadLength <= UInt64(Self.maxReceiveBufferSize) else {
            state.receiveBuffer = Data()
            return .close(1009, "frame too large")
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
        
        if totalFrameSize >= receiveBuffer.count {
            state.receiveBuffer = Data()
        } else {
            state.receiveBuffer = Data(receiveBuffer.suffix(from: receiveBuffer.startIndex + totalFrameSize))
        }

        let opcode = byte0 & 0x0F
        switch opcode {
        case 0x01, 0x02:
            return .binary(payload)
        case 0x08:
            var code: UInt16 = 1005
            var reason = ""
            if payload.count >= 2 {
                code = UInt16(payload[0]) << 8 | UInt16(payload[1])
                if payload.count > 2 {
                    reason = String(data: payload[2...], encoding: .utf8) ?? ""
                }
            }
            return .close(code, reason)
        case 0x09:
            return .ping(payload)
        case 0x0A:
            return .pong(payload)
        default:
            return .binary(payload)
        }
    }
}
