//
//  ByteTransportAdapters.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation

/// Exposes a ``TLSRecordConnection``'s async surface as a ``ByteTransport``, for framings
/// (WebSocket, GRPC, XHTTP, …) that ride a TLS record layer. `receive()` returning
/// `nil`/empty at a clean close maps to ``TransportChunk/end``.
nonisolated final class TLSByteTransport: ByteTransport, Sendable {
    private let tls: TLSRecordConnection

    init(_ tls: TLSRecordConnection) {
        self.tls = tls
    }

    var isReady: Bool { true }

    func send(_ data: Data) async throws {
        try await tls.send(data)
    }

    func receive() async throws -> TransportChunk {
        if let data = try await tls.receive(), !data.isEmpty {
            return .bytes(data)
        }
        return .end
    }

    func cancel() {
        tls.cancel()
    }
}

/// A byte seam that is never actually driven — for framing multiplexed over another
/// carrier (e.g. XHTTP-over-HTTP/3, which rides QUIC streams), where the underlying
/// transport is touched by the multiplexer, not the framing.
nonisolated final class NullByteTransport: ByteTransport, Sendable {
    var isReady: Bool { true }
    func send(_ data: Data) async throws {}
    func receive() async throws -> TransportChunk { .end }
    func cancel() {}
}

/// Forwards send/receive to an inner ``ByteTransport`` but drops `cancel()` — for the
/// case where a single underlying transport backs two logical legs and only the primary
/// leg owns teardown, so the secondary must not double-cancel it.
nonisolated final class NonCancelingByteTransport: ByteTransport, Sendable {
    private let inner: any ByteTransport

    init(_ inner: any ByteTransport) {
        self.inner = inner
    }

    var isReady: Bool { inner.isReady }
    func send(_ data: Data) async throws { try await inner.send(data) }
    func receive() async throws -> TransportChunk { try await inner.receive() }
    func cancel() {}
}
