//
//  ProxyTunnel.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Foundation
@testable import Anywhere

// MARK: - Byte stream abstraction

protocol ByteStream: AnyObject {
    func sendBytes(_ data: Data) async throws
    func receiveBytes() async throws -> Data?
    func closeStream()
}

final class ProxyConnectionStream: ByteStream {
    private let connection: ProxyConnection
    init(_ connection: ProxyConnection) { self.connection = connection }

    func sendBytes(_ data: Data) async throws {
        try await connection.send(data)
    }

    func receiveBytes() async throws -> Data? {
        let data = try await connection.receive()
        return (data?.isEmpty == false) ? data : nil
    }

    func closeStream() { connection.cancel() }
}

final class TLSTransportStream: ByteStream {
    private let transport: TLSStreamTransport
    init(_ transport: TLSStreamTransport) { self.transport = transport }

    func sendBytes(_ data: Data) async throws {
        try await transport.send(data)
    }

    func receiveBytes() async throws -> Data? {
        let data = try await transport.receive()
        return (data?.isEmpty == false) ? data : nil
    }

    func closeStream() { transport.cancel() }
}

// MARK: - ProxyTunnel

final class ProxyTunnel {
    private let client: ProxyClient
    let connection: ProxyConnection

    private init(client: ProxyClient, connection: ProxyConnection) {
        self.client = client
        self.connection = connection
    }
    
    static func open(configuration: ProxyConfiguration, host: String, port: UInt16) async throws -> ProxyTunnel {
        let client = ProxyClient(configuration: configuration)
        let connection = try await client.connect(to: host, port: port)
        return ProxyTunnel(client: client, connection: connection)
    }

    /// Like `open`, but opens a UDP association (for QUIC / HTTP/3 targets). The
    /// returned tunnel's `connection` delivers datagrams; wrap it in a
    /// `ProxyConnectionDatagramTransport` to run QUIC over the relay.
    static func openUDP(configuration: ProxyConfiguration, host: String, port: UInt16) async throws -> ProxyTunnel {
        let client = ProxyClient(configuration: configuration)
        let connection = try await client.connectUDP(to: host, port: port)
        return ProxyTunnel(client: client, connection: connection)
    }

    var rawStream: ByteStream { ProxyConnectionStream(connection) }
    
    func tlsStream(serverName: String, port: UInt16, alpn: [String]) async throws -> ByteStream {
        let transport = TLSStreamTransport(
            host: serverName,
            port: port,
            sni: serverName,
            alpn: alpn,
            tunnel: connection
        )
        try await transport.connect()
        return TLSTransportStream(transport)
    }
    
    func close() async {
        await client.cancel()
    }
}

// MARK: - Timeout

struct TimeoutError: Error, CustomStringConvertible {
    let seconds: Double
    var description: String { "Operation timed out after \(seconds)s" }
}

func withTimeout<T: Sendable>(
    _ seconds: Double,
    _ operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw TimeoutError(seconds: seconds)
        }
        defer { group.cancelAll() }
        return try await group.next()!
    }
}
