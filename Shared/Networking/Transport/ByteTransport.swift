//
//  ByteTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation

nonisolated enum TransportChunk: Sendable {
    case bytes(Data)
    case end
}

nonisolated protocol ByteTransport: AnyObject, Sendable {
    nonisolated var isReady: Bool { get }

    nonisolated func send(_ data: Data) async throws
    nonisolated func receive() async throws -> TransportChunk
    nonisolated func cancel()
}

nonisolated protocol DatagramTransport: AnyObject, Sendable {
    nonisolated var isReady: Bool { get }

    nonisolated func send(_ datagram: Data) async throws
    nonisolated func receive() async throws -> Data
    nonisolated func cancel()
}
