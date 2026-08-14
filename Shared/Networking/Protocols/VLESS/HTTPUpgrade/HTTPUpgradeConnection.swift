//
//  HTTPUpgradeConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

// MARK: - HTTPUpgradeConnection

nonisolated final class HTTPUpgradeConnection: Sendable {

    // MARK: Transport

    private let transport: any ByteTransport

    // MARK: State

    private let configuration: HTTPUpgradeConfiguration

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
        var leftoverBuffer = Data()
    }

    private let state: Mutex<ConnectionState>

    static let chromeUserAgent = ProxyUserAgent.chrome

    var isConnected: Bool {
        state.withLock { $0.phase == .open }
    }

    // MARK: - Initializers

    init(transport: any ByteTransport, configuration: HTTPUpgradeConfiguration) {
        self.configuration = configuration
        self.transport = transport
        self.state = Mutex(ConnectionState())
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
            throw AnywhereError.capture(error, context: "HTTPUpgrade request")
        }

        try await receiveUpgradeResponse()
    }
    
    private func receiveUpgradeResponse() async throws {
        while true {
            let chunk: TransportChunk
            do {
                chunk = try await transport.receive()
            } catch {
                throw AnywhereError.capture(error, context: "HTTPUpgrade response")
            }

            guard case .bytes(let data) = chunk, !data.isEmpty else {
                throw AnywhereError.proxy(.httpUpgrade, .upgradeFailed(detail: "Empty response from server"))
            }

            let headerData: Data? = state.withLock { state in
                state.leftoverBuffer.append(data)

                let headerEnd = Data([0x0D, 0x0A, 0x0D, 0x0A])
                guard let range = state.leftoverBuffer.range(of: headerEnd) else {
                    return nil
                }

                let header = Data(state.leftoverBuffer[state.leftoverBuffer.startIndex..<range.lowerBound])
                let leftover = state.leftoverBuffer[range.upperBound...]
                state.leftoverBuffer = Data(leftover)
                return header
            }

            guard let headerData else {
                continue
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

            let opened: Bool = state.withLock { $0.transition(to: .open) }
            guard opened else {
                throw AnywhereError.proxy(.httpUpgrade, .upgradeFailed(detail: "cancelled during upgrade"))
            }
            return
        }
    }

    // MARK: - Public API

    func send(_ data: Data) async throws {
        try await transport.send(data)
    }
    
    func receive() async throws -> Data? {
        enum Buffered { case data(Data), empty, upgrading, closed, cancelled }
        let buffered: Buffered = state.withLock { state in
            switch state.phase {
            case .upgrading: return .upgrading
            case .closed: return .closed
            case .cancelled: return .cancelled
            case .open: break
            }
            guard !state.leftoverBuffer.isEmpty else { return .empty }
            let data = state.leftoverBuffer
            state.leftoverBuffer.removeAll(keepingCapacity: true)
            return .data(data)
        }
        switch buffered {
        case .data(let data):
            return data
        case .upgrading:
            throw AnywhereError.proxy(.httpUpgrade, .notReady)
        case .closed:
            return nil
        case .cancelled:
            throw AnywhereError.transport(.terminated)
        case .empty:
            break
        }

        guard case .bytes(let data) = try await transport.receive(), !data.isEmpty else {
            _ = state.withLock { $0.transition(to: .closed) }
            return nil
        }
        return data
    }

    func cancel() {
        state.withLock {
            $0.transition(to: .cancelled)
            $0.leftoverBuffer.removeAll()
        }
        transport.cancel()
    }
}
