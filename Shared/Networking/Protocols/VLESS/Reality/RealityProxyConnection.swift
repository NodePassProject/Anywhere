//
//  RealityProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

nonisolated class RealityProxyConnection: AsyncProxyConnection {
    private let realityConnection: TLSRecordConnection

    init(realityConnection: TLSRecordConnection) {
        self.realityConnection = realityConnection
        super.init()
    }

    /// Reality always negotiates TLS 1.3.
    override var outerTLSVersion: TLSVersion? { .tls13 }

    override var isConnected: Bool {
        realityConnection.connection?.isReady ?? false
    }

    override func sendRaw(_ data: Data) async throws {
        try await realityConnection.send(data)
    }

    override func receiveRaw() async throws -> Data? {
        do {
            return try await realityConnection.receive()
        } catch TLSRecordError.recordAuthenticationFailed {
            // AEAD auth failure means the record no longer decrypts with the derived
            // keys — the server may have switched to Vision direct-copy. Only that
            // case maps to the Reality-specific error; everything else propagates.
            throw RealityError.decryptionFailed
        }
    }

    override func performCancel() {
        realityConnection.cancel()
    }

    // MARK: - Vision direct (unencrypted) passthroughs

    override func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        realityConnection.receiveRaw(completion: completion)
    }

    override func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        realityConnection.sendRaw(data: data, completion: completion)
    }

    override func sendDirectRaw(data: Data) {
        realityConnection.sendRaw(data: data)
    }
}
