//
//  TrojanConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/22/26.
//

import Foundation

private let logger = AnywhereLogger(category: "Trojan")

// MARK: - TrojanConnection

/// Wraps a TLS-backed ProxyConnection with the Trojan TCP request header.
///
/// The header — `hex(sha224(password)) + CRLF + cmd + addr:port + CRLF` — is
/// prepended to the first `sendRaw` payload and travels inside the same TLS
/// record, matching Xray-core's `ConnWriter.Write`. The receive path is a
/// pass-through because Trojan servers reply without any framing of their own.
final class TrojanConnection: ProxyConnection {
    private let inner: ProxyConnection
    private var pendingHeader: Data?

    init(inner: ProxyConnection, password: String, destinationHost: String, destinationPort: UInt16) {
        self.inner = inner
        self.pendingHeader = TrojanProtocol.buildRequestHeader(
            passwordKey: TrojanProtocol.passwordKey(password),
            command: TrojanProtocol.commandTCP,
            host: destinationHost,
            port: destinationPort
        )
        super.init()
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        inner.sendRaw(data: consumeHeader().map { $0 + data } ?? data, completion: completion)
    }

    override func sendRaw(data: Data) {
        inner.sendRaw(data: consumeHeader().map { $0 + data } ?? data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        inner.receiveRaw(completion: completion)
    }

    override func cancel() {
        inner.cancel()
    }

    /// Returns the request header on the first call and `nil` thereafter.
    private func consumeHeader() -> Data? {
        lock.lock()
        defer { lock.unlock() }
        let header = pendingHeader
        pendingHeader = nil
        return header
    }
}
