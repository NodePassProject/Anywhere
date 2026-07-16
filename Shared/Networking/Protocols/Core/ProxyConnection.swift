//
//  ProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation
import Synchronization

nonisolated class ProxyConnection: @unchecked Sendable {

    /// The negotiated TLS version of the outer transport; `nil` for non-TLS transports.
    var outerTLSVersion: TLSVersion? { nil }

    /// Whether each `send`/`receive` call preserves one UDP datagram boundary.
    var deliversDatagrams: Bool { false }

    // MARK: Traffic Statistics

    private let _bytesSent = Atomic<Int64>(0)
    private let _bytesReceived = Atomic<Int64>(0)

    var bytesSent: Int64 { _bytesSent.load(ordering: .relaxed) }
    var bytesReceived: Int64 { _bytesReceived.load(ordering: .relaxed) }

    var isConnected: Bool {
        fatalError("Subclass must override isConnected")
    }

    // MARK: Send / Receive

    /// Sends `data`, tracking traffic stats.
    func send(_ data: Data) async throws {
        _bytesSent.wrappingAdd(Int64(data.count), ordering: .relaxed)
        try await sendRaw(data)
    }

    /// Receives once; `nil` signals EOF.
    func receive() async throws -> Data? {
        let data = try await receiveRaw()
        if let data, !data.isEmpty {
            _bytesReceived.wrappingAdd(Int64(data.count), ordering: .relaxed)
        }
        return data
    }

    // MARK: Raw Contract (subclasses override)

    /// Sends `data` on the wire with no stats tracking. Abstract.
    func sendRaw(_ data: Data) async throws {
        fatalError("Subclass must override sendRaw(_:)")
    }

    /// Receives one chunk; `nil` (or empty) signals EOF. Abstract.
    func receiveRaw() async throws -> Data? {
        fatalError("Subclass must override receiveRaw()")
    }

    /// Bypasses transport encryption; used for Vision direct-copy mode. Defaults to `sendRaw`.
    func sendDirectRaw(_ data: Data) async throws {
        try await sendRaw(data)
    }

    /// Bypasses transport decryption; used for Vision direct-copy mode. Defaults to `receiveRaw`.
    func receiveDirectRaw() async throws -> Data? {
        try await receiveRaw()
    }

    // MARK: Half-Close

    /// Finishes the send direction — the streaming analogue of `shutdown(SHUT_WR)`: signals
    /// end-of-stream to the remote while receive stays open. Ordered after every issued send;
    /// called at most once, with no sends afterwards. The default does nothing for protocols
    /// that can't express end-of-stream short of a full close.
    func closeWrite() async throws {}

    // MARK: Cancel

    /// Abortive teardown of the underlying transport. Subclasses override.
    func cancel() {
        fatalError("Subclass must override cancel")
    }

    /// Abortive teardown for error paths. Defaults to `cancel()`; subclasses
    /// owning a raw socket override to close with RST.
    func abort() {
        cancel()
    }
}
