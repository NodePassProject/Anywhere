//
//  RFCHTTP11Tunnel.swift
//  Anywhere
//
//  Created by NodePassProject on 9/11/26.
//

import Foundation
import Synchronization

// MARK: - RFCHTTP11Tunnel

nonisolated enum RFCHTTP11Tunnel {
    static func establish(
        over connection: ProxyConnection,
        authority: String,
        credentials: String?
    ) async throws -> ProxyConnection {
        let request = RFCProtocol.http11ConnectRequest(authority: authority, credentials: credentials)
        try await connection.send(request)

        var buffer = Data()
        while true {
            if let response = try RFCProtocol.parseHTTP11Response(from: buffer) {
                if let error = RFCProtocol.tunnelError(status: response.status, reason: response.reason, wire: .http11) {
                    throw error
                }
                return response.leftover.isEmpty
                    ? connection
                    : RFCReplayConnection(inner: connection, replay: response.leftover)
            }
            guard let chunk = try await connection.receive() else {
                throw AnywhereError.proxy(.http11, .handshakeFailed(
                    detail: "Proxy closed before completing the CONNECT response"
                ))
            }
            buffer.append(chunk)
        }
    }
}

// MARK: - RFCReplayConnection

nonisolated final class RFCReplayConnection: ProxyConnection {
    private let inner: ProxyConnection
    private let pending: Mutex<Data?>

    init(inner: ProxyConnection, replay: Data) {
        self.inner = inner
        self.pending = Mutex(replay)
    }

    var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    var isConnected: Bool { inner.isConnected }

    func sendRaw(_ data: Data) async throws {
        try await inner.sendRaw(data)
    }

    func receiveRaw() async throws -> Data? {
        let replay = pending.withLock { pending -> Data? in
            let snapshot = pending
            pending = nil
            return snapshot
        }
        if let replay { return replay }
        return try await inner.receiveRaw()
    }

    func cancel() {
        inner.cancel()
    }

    func abort() {
        inner.abort()
    }
}
