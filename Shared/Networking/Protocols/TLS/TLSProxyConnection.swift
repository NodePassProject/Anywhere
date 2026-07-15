//
//  TLSProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

nonisolated class TLSProxyConnection: AsyncProxyConnection {
    private let tlsConnection: TLSRecordConnection

    init(tlsConnection: TLSRecordConnection) {
        self.tlsConnection = tlsConnection
        super.init()
    }

    override var outerTLSVersion: TLSVersion? { TLSVersion(rawValue: tlsConnection.tlsVersion) }

    override var isConnected: Bool {
        tlsConnection.connection?.isReady ?? false
    }

    override func sendRaw(_ data: Data) async throws {
        try await tlsConnection.send(data)
    }

    override func receiveRaw() async throws -> Data? {
        try await tlsConnection.receive()
    }

    override func closeWrite() async throws {
        try await tlsConnection.closeWrite()
    }

    override func performCancel() {
        tlsConnection.cancel()
    }

    // MARK: - Vision direct (unencrypted) passthroughs

    // Bypass the record crypto for Vision direct-copy mode, over `tlsConnection`'s async raw surface.

    override func receiveDirectRaw() async throws -> Data? {
        try await tlsConnection.receiveRaw()
    }

    override func sendDirectRaw(_ data: Data) async throws {
        try await tlsConnection.sendRaw(data)
    }
}
