//
//  ProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

nonisolated protocol ProxyConnection: AnyObject, Sendable {

    /// The negotiated TLS version of the outer transport; `nil` for non-TLS transports.
    nonisolated var outerTLSVersion: TLSVersion? { get }

    /// Whether each `send`/`receive` call preserves one UDP datagram boundary.
    nonisolated var deliversDatagrams: Bool { get }

    nonisolated var isConnected: Bool { get }

    // MARK: Send / Receive

    /// Sends `data`.
    func send(_ data: Data) async throws

    /// Receives once; `nil` signals EOF.
    func receive() async throws -> Data?

    // MARK: Raw Contract

    /// Sends `data` on the wire. Required.
    func sendRaw(_ data: Data) async throws

    /// Receives one chunk; only `nil` signals EOF. A datagram transport may return
    /// `Data()` for a legal zero-length UDP packet. Required.
    func receiveRaw() async throws -> Data?

    /// Bypasses transport encryption; used for Vision direct-copy mode. Defaults to `sendRaw`.
    func sendDirectRaw(_ data: Data) async throws

    /// Bypasses transport decryption; used for Vision direct-copy mode. Defaults to `receiveRaw`.
    func receiveDirectRaw() async throws -> Data?

    // MARK: Cancel

    /// Abortive teardown of the underlying transport.
    nonisolated func cancel()

    /// Abortive teardown for error paths. Defaults to `cancel()`; conformers owning a raw
    /// socket override to close with RST.
    nonisolated func abort()
}

// MARK: - Defaults

nonisolated extension ProxyConnection {

    var outerTLSVersion: TLSVersion? { nil }

    var deliversDatagrams: Bool { false }
    
    func send(_ data: Data) async throws {
        try await sendRaw(data)
    }

    func receive() async throws -> Data? {
        try await receiveRaw()
    }

    func sendDirectRaw(_ data: Data) async throws {
        try await sendRaw(data)
    }

    func receiveDirectRaw() async throws -> Data? {
        try await receiveRaw()
    }

    func abort() {
        cancel()
    }
}
