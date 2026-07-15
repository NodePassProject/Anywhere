//
//  AsyncTransportClosures.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

// MARK: - AsyncTransportClosures

struct AsyncTransportClosures: Sendable {
    /// Sends one chunk, ordered after every prior send; `await` is backpressure.
    let send: @Sendable (Data) async throws -> Void
    /// Half-closes the send direction (TCP FIN / end-of-stream); receive stays open.
    let finishSend: @Sendable () async throws -> Void
    /// One read: `.bytes` with data, `.end` at EOF. Issued serially.
    let receive: @Sendable () async throws -> TransportChunk
    /// Abortive teardown; safe from any task.
    let cancel: @Sendable () -> Void
}

// MARK: - Transport adapters

extension AsyncTransportClosures {

    /// Over an async-native byte transport — the common case.
    init(_ transport: any AsyncByteTransport) {
        self.init(
            send: { try await transport.send($0) },
            finishSend: { try await transport.finishSend() },
            receive: { try await transport.receive() },
            cancel: { transport.cancel() }
        )
    }

    /// Over a ``TLSRecordConnection``'s async surface, for framing that rides a TLS record
    /// layer. `receive()` returns `nil`/empty at a clean close, which maps to ``TransportChunk/end``.
    init(tls tlsConnection: TLSRecordConnection) {
        self.init(
            send: { try await tlsConnection.send($0) },
            finishSend: { try await tlsConnection.closeWrite() },
            receive: {
                if let data = try await tlsConnection.receive(), !data.isEmpty {
                    return .bytes(data)
                }
                return .end
            },
            cancel: { tlsConnection.cancel() }
        )
    }

    /// Over a ``ProxyConnection``'s async surface (for framing that rides another proxy
    /// hop). `receiveRaw()` returns `nil`/empty at EOF, which maps to ``TransportChunk/end``.
    init(proxyConnection connection: ProxyConnection) {
        self.init(
            send: { try await connection.sendRaw($0) },
            finishSend: { try await connection.closeWrite() },
            receive: {
                if let data = try await connection.receiveRaw(), !data.isEmpty {
                    return .bytes(data)
                }
                return .end
            },
            cancel: { connection.cancel() }
        )
    }

    /// For framing multiplexed over another carrier (e.g. XHTTP-over-HTTP/3, which rides
    /// QUIC streams): the byte-transport seam is never touched, so every closure is inert.
    static var unused: AsyncTransportClosures {
        AsyncTransportClosures(
            send: { _ in },
            finishSend: {},
            receive: { .end },
            cancel: {}
        )
    }
}
