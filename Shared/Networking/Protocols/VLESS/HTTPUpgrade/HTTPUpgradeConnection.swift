//
//  HTTPUpgradeConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

// MARK: - HTTPUpgradeConnection

/// Performs an HTTP upgrade handshake, then passes data through as raw bytes (no WebSocket framing).
nonisolated final class HTTPUpgradeConnection: Sendable {

    // MARK: Transport

    private let transport: any ByteTransport

    // MARK: State

    private let configuration: HTTPUpgradeConfiguration

    private struct ConnectionState {
        var isConnected = false
        /// Leftover data received after the HTTP 101 response headers.
        var leftoverBuffer = Data()
    }

    private let state: Mutex<ConnectionState>

    static let chromeUserAgent = ProxyUserAgent.chrome

    var isConnected: Bool {
        state.withLock { $0.isConnected }
    }

    // MARK: - Initializers

    init(transport: any ByteTransport, configuration: HTTPUpgradeConfiguration) {
        self.configuration = configuration
        self.transport = transport
        self.state = Mutex(ConnectionState(isConnected: true))
    }

    convenience init(tlsConnection: TLSRecordConnection, configuration: HTTPUpgradeConfiguration) {
        self.init(transport: TLSByteTransport(tlsConnection), configuration: configuration)
    }

    convenience init(tunnel: ProxyConnection, configuration: HTTPUpgradeConfiguration) {
        self.init(transport: TunneledTransport(tunnel: tunnel), configuration: configuration)
    }

    // MARK: - HTTP Upgrade Handshake

    func performUpgrade() async throws {
        var request = "GET \(configuration.normalizedPath) HTTP/1.1\r\n"
        request += "Host: \(configuration.host)\r\n"
        request += "Connection: Upgrade\r\n"
        request += "Upgrade: websocket\r\n"

        for (key, value) in configuration.headers {
            request += "\(key): \(value)\r\n"
        }

        if !configuration.headers.keys.contains(where: { $0.lowercased() == "user-agent" }) {
            request += "User-Agent: \(Self.chromeUserAgent)\r\n"
        }

        request += "\r\n"

        guard let requestData = request.data(using: .utf8) else {
            throw AnywhereError.proxy(.httpUpgrade, .upgradeFailed(detail: "Failed to encode upgrade request"))
        }

        do {
            try await transport.send(requestData)
        } catch {
            throw AnywhereError.proxy(.httpUpgrade, .upgradeFailed(detail: error.localizedDescription))
        }

        try await receiveUpgradeResponse()
    }

    /// Reads the HTTP 101 response, validating status and Upgrade/Connection headers (case-insensitive).
    private func receiveUpgradeResponse() async throws {
        while true {
            let chunk: TransportChunk
            do {
                chunk = try await transport.receive()
            } catch {
                throw AnywhereError.proxy(.httpUpgrade, .upgradeFailed(detail: error.localizedDescription))
            }

            guard case .bytes(let data) = chunk, !data.isEmpty else {
                throw AnywhereError.proxy(.httpUpgrade, .upgradeFailed(detail: "Empty response from server"))
            }

            let headerData: Data? = state.withLock { state in
                state.leftoverBuffer.append(data)

                let headerEnd = Data([0x0D, 0x0A, 0x0D, 0x0A]) // \r\n\r\n
                guard let range = state.leftoverBuffer.range(of: headerEnd) else {
                    return nil
                }

                let header = Data(state.leftoverBuffer[state.leftoverBuffer.startIndex..<range.lowerBound])
                let leftover = state.leftoverBuffer[range.upperBound...]
                state.leftoverBuffer = Data(leftover)
                return header
            }

            guard let headerData else {
                continue // need more bytes
            }

            guard let headerString = String(data: headerData, encoding: .utf8) else {
                throw AnywhereError.proxy(.httpUpgrade, .upgradeFailed(detail: "Cannot decode response headers"))
            }

            let lines = headerString.split(separator: "\r\n")
            guard let statusLine = lines.first else {
                throw AnywhereError.proxy(.httpUpgrade, .upgradeFailed(detail: "Empty response"))
            }

            guard statusLine.contains("101") else {
                throw AnywhereError.proxy(.httpUpgrade, .upgradeFailed(detail: "Expected HTTP 101, got: \(statusLine)"))
            }

            var hasUpgradeWebSocket = false
            var hasConnectionUpgrade = false
            for line in lines.dropFirst() {
                let parts = line.split(separator: ":", maxSplits: 1)
                guard parts.count == 2 else { continue }
                let key = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
                let value = parts[1].trimmingCharacters(in: .whitespaces).lowercased()
                if key == "upgrade" && value == "websocket" {
                    hasUpgradeWebSocket = true
                }
                if key == "connection" && value == "upgrade" {
                    hasConnectionUpgrade = true
                }
            }

            guard hasUpgradeWebSocket && hasConnectionUpgrade else {
                throw AnywhereError.proxy(.httpUpgrade, .upgradeFailed(detail: "Missing Upgrade/Connection headers in 101 response"))
            }

            return
        }
    }

    // MARK: - Public API (Raw TCP passthrough)

    func send(_ data: Data) async throws {
        try await transport.send(data)
    }

    /// Receives raw data; the first call drains bytes buffered past the 101 response headers.
    func receive() async throws -> Data? {
        let buffered: Data? = state.withLock { state in
            guard !state.leftoverBuffer.isEmpty else { return nil }
            let data = state.leftoverBuffer
            state.leftoverBuffer.removeAll(keepingCapacity: true)
            return data
        }
        if let buffered {
            return buffered
        }

        guard case .bytes(let data) = try await transport.receive(), !data.isEmpty else {
            return nil // EOF
        }
        return data
    }

    func cancel() {
        state.withLock {
            $0.isConnected = false
            $0.leftoverBuffer.removeAll()
        }
        transport.cancel()
    }
}
