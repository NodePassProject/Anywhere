//
//  TLSProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

nonisolated class TLSProxyConnection: ProxyConnection {
    private let tlsConnection: TLSRecordConnection

    init(tlsConnection: TLSRecordConnection) {
        self.tlsConnection = tlsConnection
    }

    var outerTLSVersion: TLSVersion? { TLSVersion(rawValue: tlsConnection.tlsVersion) }

    var isConnected: Bool {
        tlsConnection.connection?.isReady ?? false
    }

    func sendRaw(_ data: Data) async throws {
        try await tlsConnection.send(data)
    }

    func receiveRaw() async throws -> Data? {
        try await tlsConnection.receive()
    }

    func cancel() {
        tlsConnection.cancel()
    }

    // MARK: - Vision direct (unencrypted) passthroughs

    // Bypass the record crypto for Vision direct-copy mode, over `tlsConnection`'s async raw surface.

    func receiveDirectRaw() async throws -> Data? {
        try await tlsConnection.receiveRaw()
    }

    func sendDirectRaw(_ data: Data) async throws {
        try await tlsConnection.sendRaw(data)
    }
}
