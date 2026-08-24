//
//  QUICDatagramTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 5/19/26.
//

import Foundation

nonisolated protocol QUICDatagramTransport: AnyObject, Sendable {
    /// Submits one outgoing datagram in order; drops are recovered by ngtcp2, so there is no result.
    func sendDatagram(_ data: Data)

    /// Pulls the next inbound datagram. Returns `nil` on a clean end-of-stream and throws on terminal
    /// failure — the QUIC connection tears down on either. Single-consumer.
    func receiveDatagram() async throws -> Data?

    /// Tears down the transport. Idempotent.
    func cancel()
}

nonisolated final class ProxyConnectionDatagramTransport: QUICDatagramTransport, Sendable {
    private let connection: ProxyConnection

    /// Outgoing datagrams reach the wire in submission order via a single owned writer task
    /// draining this stream. The one consumer *is* the ordering — no lock, no queue. The
    /// stream is `.unbounded`; the QUIC layer already bounds its own datagram backlog.
    private let outbound: AsyncStream<Data>.Continuation

    init(connection: ProxyConnection) {
        self.connection = connection
        let (stream, continuation) = AsyncStream.makeStream(of: Data.self)
        self.outbound = continuation
        // The writer task owns the connection strongly for its lifetime and drives ordered sends.
        // `cancel()` finishes `outbound` (ending the drain) and cancels the connection; a dropped
        // transport finishes `outbound` via its continuation's deinit — either way the loop ends and
        // ARC reclaims the captured connection.
        Task { [connection] in
            for await data in stream {
                do {
                    try await connection.send(data)
                } catch {
                    // Transient errors (PMTU shrink, fragmentation refusal, queue overflow) are
                    // not terminal — outer QUIC loss recovery treats the drop as ordinary loss.
                    if Self.isTransientDatagramError(error) { continue }
                    // A terminal send failure cancels the connection so the paired `receiveDatagram`
                    // pull unblocks and the QUIC owner tears down.
                    connection.cancel()
                    break
                }
            }
        }
    }

    func sendDatagram(_ data: Data) {
        outbound.yield(data)
    }

    func receiveDatagram() async throws -> Data? {
        try await connection.receive()
    }

    func cancel() {
        outbound.finish()   // ends the writer task's drain loop
        connection.cancel()
    }

    /// True for per-datagram errors (packet didn't fit), false for terminal ones; the outer
    /// QUIC must not close on transient errors.
    private static func isTransientDatagramError(_ error: Error) -> Bool {
        if case AnywhereError.quic(let quicError) = error {
            switch quicError {
            case .handshakeFailed, .streamReset, .streamClosedWithError, .closed:
                return false
            case .datagramTooLarge, .datagramQueueFull, .connectionFailed, .streamFailed, .timedOut:
                return true
            }
        }
        if case AnywhereError.proxy(.hysteria, let failure) = error {
            switch failure {
            case .authenticationRejected, .unsupported, .datagramTooLarge, .streamClosed:
                return false
            case .notReady, .connectionClosed, .tunnelRejected:
                // connectionClosed covers per-packet outcomes; notReady is a
                // transient session-state window.
                return true
            default:
                return false
            }
        }
        if case AnywhereError.proxy(.nowhere, let failure) = error {
            if case .notReady = failure { return true }
            if case .connectionClosed = failure { return true }
            return false
        }
        return false
    }
}
