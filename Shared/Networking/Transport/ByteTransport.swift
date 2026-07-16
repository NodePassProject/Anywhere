//
//  ByteTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation

nonisolated enum TransportChunk: Sendable {
    case bytes(Data)
    /// End-of-stream (remote FIN / half-close). Further reads also return `.end`.
    case end
}

/// An ordered, backpressured byte pipe: the seam between raw carriers
/// (`TCPTransport`, a TLS record layer, a previous proxy hop) and the framings
/// that ride them.
nonisolated protocol ByteTransport: AnyObject, Sendable {
    nonisolated var isReady: Bool { get }

    /// Sends one chunk, ordered after every prior send; `await` is backpressure.
    nonisolated func send(_ data: Data) async throws

    /// One read: `.bytes` with data, `.end` at EOF. Reads are issued serially.
    nonisolated func receive() async throws -> TransportChunk

    /// Abortive teardown. Idempotent and safe from any task/thread.
    nonisolated func cancel()
}

nonisolated protocol DatagramTransport: AnyObject, Sendable {
    nonisolated var isReady: Bool { get }

    nonisolated func send(_ datagram: Data) async throws

    /// One datagram; throws on terminal failure.
    nonisolated func receive() async throws -> Data

    nonisolated func cancel()
}
