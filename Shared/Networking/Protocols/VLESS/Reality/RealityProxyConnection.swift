//
//  RealityProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

nonisolated final class RealityProxyConnection: ProxyConnection {
    private let realityConnection: TLSRecordConnection

    init(realityConnection: TLSRecordConnection) {
        self.realityConnection = realityConnection
    }

    /// Reality always negotiates TLS 1.3.
    var outerTLSVersion: TLSVersion? { .tls13 }

    var isConnected: Bool {
        realityConnection.connection?.isReady ?? false
    }

    func sendRaw(_ data: Data) async throws {
        try await realityConnection.send(data)
    }

    func receiveRaw() async throws -> Data? {
        do {
            return try await realityConnection.receive()
        } catch AnywhereError.tls(.record(.authenticationFailed)) {
            // AEAD auth failure means the record no longer decrypts with the derived
            // keys — the server may have switched to Vision direct-copy. Only that
            // case maps to the Reality-specific error; everything else propagates.
            throw AnywhereError.tls(.reality(.decryptionFailed))
        }
    }

    func cancel() {
        realityConnection.cancel()
    }

    // MARK: - Vision direct (unencrypted) passthroughs

    func receiveDirectRaw() async throws -> Data? {
        try await realityConnection.receiveRaw()
    }

    func sendDirectRaw(_ data: Data) async throws {
        try await realityConnection.sendRaw(data)
    }
}
