//
//  SOCKS5Connection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/26/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "SOCKS5Connection")

// MARK: - SOCKS5 Protocol Constants

nonisolated private enum SOCKS5 {
    static let version: UInt8 = 0x05
    static let authNone: UInt8 = 0x00
    static let authPassword: UInt8 = 0x02
    static let authNoMatch: UInt8 = 0xFF
    static let cmdConnect: UInt8 = 0x01
    static let cmdUDPAssociate: UInt8 = 0x03
    static let addrIPv4: UInt8 = 0x01
    static let addrDomain: UInt8 = 0x03
    static let addrIPv6: UInt8 = 0x04
    static let statusSuccess: UInt8 = 0x00
}

// MARK: - SOCKS5AsyncBuffer

/// Reads framed handshake responses off an ``ByteTransport``, buffering any
/// bytes that arrive past the requested length so the tunneled stream keeps them.
/// Confined to the single dialing task, so it needs no locking.
nonisolated final class SOCKS5AsyncBuffer {
    private var data = Data()
    private let transport: any ByteTransport

    init(transport: any ByteTransport) {
        self.transport = transport
    }

    /// Reads exactly `count` bytes; returns `nil` if the peer closes first.
    func readExact(count: Int) async throws -> Data? {
        while data.count < count {
            switch try await transport.receive() {
            case .bytes(let newData):
                data.append(newData)
            case .end:
                return nil
            }
        }
        let result = data.subdata(in: data.startIndex..<data.startIndex + count)
        data.removeFirst(count)
        if data.isEmpty { data = Data() } else { data = Data(data) }
        return result
    }

    /// Data remaining in the buffer after the handshake; belongs to the tunneled stream and must not be discarded.
    var remaining: Data? {
        data.isEmpty ? nil : data
    }
}

// MARK: - SOCKS5ReplayTransport

/// Replays handshake-leftover bytes (e.g. the start of a TLS ServerHello) on the
/// first `receive` before falling through to the underlying transport.
nonisolated final class SOCKS5ReplayTransport: ByteTransport, Sendable {
    private let inner: any ByteTransport
    private let pending: Mutex<Data?>

    init(inner: any ByteTransport, initialData: Data) {
        self.inner = inner
        self.pending = Mutex(initialData)
    }

    var isReady: Bool { inner.isReady }

    func send(_ data: Data) async throws {
        try await inner.send(data)
    }

    func receive() async throws -> TransportChunk {
        let replay = pending.withLock { pending -> Data? in
            let snapshot = pending
            pending = nil
            return snapshot
        }
        if let replay { return .bytes(replay) }
        return try await inner.receive()
    }

    func cancel() {
        inner.cancel()
    }
}

// MARK: - SOCKS5Handshake

nonisolated enum SOCKS5Handshake {

    struct UDPRelayInfo {
        let host: String
        let port: UInt16
    }

    static func perform(
        buffer: SOCKS5AsyncBuffer,
        transport: any ByteTransport,
        destinationHost: String,
        destinationPort: UInt16,
        username: String?,
        password: String?
    ) async throws {
        try await performAuth(buffer: buffer, transport: transport, username: username, password: password)
        _ = try await sendCommand(
            buffer: buffer,
            transport: transport,
            command: SOCKS5.cmdConnect,
            host: destinationHost,
            port: destinationPort
        )
    }

    /// UDP ASSOCIATE: per RFC 1928 the client sends 0.0.0.0:0 and the server replies with the relay endpoint.
    static func performUDPAssociate(
        buffer: SOCKS5AsyncBuffer,
        transport: any ByteTransport,
        username: String?,
        password: String?,
        serverAddress: String
    ) async throws -> UDPRelayInfo {
        try await performAuth(buffer: buffer, transport: transport, username: username, password: password)
        let info = try await sendCommand(
            buffer: buffer,
            transport: transport,
            command: SOCKS5.cmdUDPAssociate,
            host: "0.0.0.0",
            port: 0
        )
        // Servers often return an unreachable private IP for the relay host; use
        // the server's public address (the port is still valid).
        return UDPRelayInfo(host: serverAddress, port: info.port)
    }

    // MARK: - Authentication

    private static func performAuth(
        buffer: SOCKS5AsyncBuffer,
        transport: any ByteTransport,
        username: String?,
        password: String?
    ) async throws {
        let hasAuth = username != nil && password != nil
        let authMethod = hasAuth ? SOCKS5.authPassword : SOCKS5.authNone
        let greeting = Data([SOCKS5.version, 0x01, authMethod])

        try await transport.send(greeting)
        guard let data = try await buffer.readExact(count: 2) else {
            throw ProxyError.protocolError("SOCKS5 server closed during greeting")
        }
        guard data[0] == SOCKS5.version else {
            throw ProxyError.protocolError("SOCKS5 unexpected server version: \(data[0])")
        }
        let expectedMethod = hasAuth ? SOCKS5.authPassword : SOCKS5.authNone
        guard data[1] == expectedMethod else {
            if data[1] == SOCKS5.authNoMatch {
                throw ProxyError.protocolError("SOCKS5 server: no matching auth method")
            }
            throw ProxyError.protocolError("SOCKS5 auth method mismatch: expected \(expectedMethod), got \(data[1])")
        }
        if hasAuth {
            try await sendAuth(buffer: buffer, transport: transport, username: username!, password: password!)
        }
    }

    // MARK: - Authentication (RFC 1929)

    private static func sendAuth(
        buffer: SOCKS5AsyncBuffer,
        transport: any ByteTransport,
        username: String,
        password: String
    ) async throws {
        let usernameBytes = Data(username.utf8)
        let passwordBytes = Data(password.utf8)
        var authData = Data(capacity: 3 + usernameBytes.count + passwordBytes.count)
        authData.append(0x01) // sub-negotiation version
        authData.append(UInt8(min(usernameBytes.count, 255)))
        authData.append(usernameBytes.prefix(255))
        authData.append(UInt8(min(passwordBytes.count, 255)))
        authData.append(passwordBytes.prefix(255))

        try await transport.send(authData)
        guard let data = try await buffer.readExact(count: 2) else {
            throw ProxyError.protocolError("SOCKS5 server closed during auth")
        }
        guard data[1] == 0x00 else {
            throw ProxyError.protocolError("SOCKS5 authentication failed (status \(data[1]))")
        }
    }

    // MARK: - Command (CONNECT / UDP ASSOCIATE)

    @discardableResult
    private static func sendCommand(
        buffer: SOCKS5AsyncBuffer,
        transport: any ByteTransport,
        command: UInt8,
        host: String,
        port: UInt16
    ) async throws -> UDPRelayInfo {
        var request = Data([SOCKS5.version, command, 0x00])
        request.append(encodeAddress(host: host))
        request.append(UInt8(port >> 8))
        request.append(UInt8(port & 0xFF))

        try await transport.send(request)
        return try await readCommandResponse(buffer: buffer)
    }

    /// Reads the command response: [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
    private static func readCommandResponse(
        buffer: SOCKS5AsyncBuffer
    ) async throws -> UDPRelayInfo {
        guard let data = try await buffer.readExact(count: 4) else {
            throw ProxyError.protocolError("SOCKS5 server closed during command")
        }
        guard data[1] == SOCKS5.statusSuccess else {
            throw ProxyError.protocolError("SOCKS5 command failed (reply \(data[1]))")
        }

        switch data[3] {
        case SOCKS5.addrIPv4:
            guard let addrData = try await buffer.readExact(count: 4 + 2) else {
                throw ProxyError.protocolError("SOCKS5 server closed reading bound address")
            }
            let ip = "\(addrData[0]).\(addrData[1]).\(addrData[2]).\(addrData[3])"
            let port = UInt16(addrData[4]) << 8 | UInt16(addrData[5])
            return UDPRelayInfo(host: ip, port: port)

        case SOCKS5.addrIPv6:
            guard let addrData = try await buffer.readExact(count: 16 + 2) else {
                throw ProxyError.protocolError("SOCKS5 server closed reading bound address")
            }
            var parts: [String] = []
            for i in stride(from: 0, to: 16, by: 2) {
                parts.append(String(format: "%x", UInt16(addrData[i]) << 8 | UInt16(addrData[i + 1])))
            }
            let ip = parts.joined(separator: ":")
            let port = UInt16(addrData[16]) << 8 | UInt16(addrData[17])
            return UDPRelayInfo(host: ip, port: port)

        case SOCKS5.addrDomain:
            guard let lenData = try await buffer.readExact(count: 1) else {
                throw ProxyError.protocolError("SOCKS5 server closed reading bound address")
            }
            let domainLen = Int(lenData[0])
            guard let domainData = try await buffer.readExact(count: domainLen + 2) else {
                throw ProxyError.protocolError("SOCKS5 server closed reading bound address")
            }
            let domain = String(data: domainData.prefix(domainLen), encoding: .utf8) ?? ""
            let port = UInt16(domainData[domainLen]) << 8 | UInt16(domainData[domainLen + 1])
            return UDPRelayInfo(host: domain, port: port)

        default:
            throw ProxyError.protocolError("SOCKS5 unknown address type: \(data[3])")
        }
    }

    // MARK: - Address Encoding

    /// Encodes a host as a SOCKS5 address: [ATYP, ADDR...]
    static func encodeAddress(host: String) -> Data {
        if let ipv4 = parseIPv4(host) {
            var data = Data([SOCKS5.addrIPv4])
            data.append(ipv4)
            return data
        }
        if let ipv6 = parseIPv6(host) {
            var data = Data([SOCKS5.addrIPv6])
            data.append(ipv6)
            return data
        }
        let domainBytes = Data(host.utf8)
        var data = Data([SOCKS5.addrDomain, UInt8(min(domainBytes.count, 255))])
        data.append(domainBytes.prefix(255))
        return data
    }

    private static func parseIPv4(_ string: String) -> Data? {
        let parts = string.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var bytes = Data(capacity: 4)
        for part in parts {
            guard let byte = UInt8(part) else { return nil }
            bytes.append(byte)
        }
        return bytes
    }

    private static func parseIPv6(_ string: String) -> Data? {
        var buffer = Data(count: 16)
        let host = string.hasPrefix("[") && string.hasSuffix("]")
            ? String(string.dropFirst().dropLast()) : string
        guard host.contains(":") else { return nil }
        var result = in6_addr()
        guard inet_pton(AF_INET6, host, &result) == 1 else { return nil }
        buffer.withUnsafeMutableBytes { pointer in
            withUnsafeBytes(of: &result) { source in
                pointer.copyBytes(from: source)
            }
        }
        return buffer
    }
}

// MARK: - SOCKS5UDPProxyConnection

/// SOCKS5 UDP ASSOCIATE relay: prepends/strips the SOCKS5 UDP header per datagram.
/// The TCP control connection is retained because closing it ends the UDP session.
nonisolated final class SOCKS5UDPProxyConnection: ProxyConnection, Sendable {
    private let tcpTransport: any ByteTransport
    private let relay: ProxyConnection
    private let udpHeader: Data
    private let cancelled = Atomic<Bool>(false)

    init(
        tcpTransport: any ByteTransport,
        relay: ProxyConnection,
        destinationHost: String,
        destinationPort: UInt16
    ) {
        self.tcpTransport = tcpTransport
        self.relay = relay

        // Pre-build the SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP + DST.ADDR + DST.PORT
        var header = Data([0x00, 0x00, 0x00])
        header.append(SOCKS5Handshake.encodeAddress(host: destinationHost))
        header.append(UInt8(destinationPort >> 8))
        header.append(UInt8(destinationPort & 0xFF))
        self.udpHeader = header

    }

    var isConnected: Bool { relay.isConnected }
    var deliversDatagrams: Bool { true }

    func sendRaw(_ data: Data) async throws {
        guard !cancelled.load(ordering: .relaxed) else {
            throw ProxyError.connectionFailed("SOCKS5 UDP not connected")
        }
        var packet = udpHeader
        packet.append(data)
        // `relay.send` so any chain-level framing wraps each datagram.
        try await relay.send(packet)
    }

    func receiveRaw() async throws -> Data? {
        while true {
            guard !cancelled.load(ordering: .relaxed) else {
                throw ProxyError.connectionFailed("SOCKS5 UDP not connected")
            }
            guard let data = try await relay.receive(), !data.isEmpty else {
                return nil
            }
            if let payload = stripUDPHeader(data) {
                return payload
            }
            // Header-only / malformed datagram: loop to read the next one.
        }
    }

    func cancel() {
        guard !cancelled.exchange(true, ordering: .relaxed) else { return }
        relay.cancel()
        tcpTransport.cancel()
    }

    private func stripUDPHeader(_ data: Data) -> Data? {
        guard data.count >= 4 else { return nil }
        guard data[2] == 0x00 else { return nil } // reject fragments

        let headerEnd: Int
        switch data[3] {
        case SOCKS5.addrIPv4:   headerEnd = 4 + 4 + 2
        case SOCKS5.addrIPv6:   headerEnd = 4 + 16 + 2
        case SOCKS5.addrDomain:
            guard data.count >= 5 else { return nil }
            headerEnd = 4 + 1 + Int(data[4]) + 2
        default: return nil
        }

        guard data.count > headerEnd else { return nil }
        return Data(data[headerEnd...])
    }
}
