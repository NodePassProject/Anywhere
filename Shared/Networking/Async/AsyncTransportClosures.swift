//
//  AsyncTransportClosures.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

// MARK: - AsyncTransportClosures

/// The async-native counterpart of ``TransportClosures`` — a struct of closures over
/// whatever byte transport a framing layer (gRPC, WebSocket, HTTP-Upgrade, XHTTP)
/// rides, so the framing logic depends on this seam rather than a concrete transport.
///
/// Where ``TransportClosures`` exposes completion-handler `send`/`receive`, this exposes
/// `async` ones, plus an explicit ``finishSend`` (half-close) that the legacy struct
/// lacked. Migrating a framing layer means switching its stored `TransportClosures` to
/// this and turning its recursive receive callbacks into an `await` loop.
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

    /// Bridges a legacy ``TransportClosures`` into the async surface, so a framing layer
    /// can move to this seam before its underlying transport is async-native. The legacy
    /// struct has no half-close, so ``finishSend`` is a no-op.
    init(bridging closures: TransportClosures) {
        self.init(
            send: { data in
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    closures.send(data) { error in
                        if let error { continuation.resume(throwing: error) } else { continuation.resume() }
                    }
                }
            },
            finishSend: {},
            receive: {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<TransportChunk, Error>) in
                    closures.receive { data, isComplete, error in
                        if let error {
                            continuation.resume(throwing: error)
                        } else if let data, !data.isEmpty {
                            continuation.resume(returning: .bytes(data))
                        } else if isComplete {
                            continuation.resume(returning: .end)
                        } else {
                            // Empty, not end-of-stream: treat as EOF to match the
                            // three-way signal's collapse in `TransportClosures`.
                            continuation.resume(returning: .end)
                        }
                    }
                }
            },
            cancel: { closures.cancel() }
        )
    }
}
