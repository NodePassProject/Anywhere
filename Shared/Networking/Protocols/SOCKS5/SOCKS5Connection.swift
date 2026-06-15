//
//  SOCKS5Connection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/26/26.
//

import Foundation

private let logger = AnywhereLogger(category: "SOCKS5Connection")

// MARK: - SOCKS5 Protocol Constants

private enum SOCKS5 {
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

// MARK: - SOCKS5Buffer

/// Shared read buffer for the SOCKS5 handshake.
nonisolated class SOCKS5Buffer {
    private var data = Data()
    private let transport: any RawTransport

    init(transport: any RawTransport) {
        self.transport = transport
    }

    func readExact(count: Int, completion: @escaping (Data?, Error?) -> Void) {
        if data.count >= count {
            let result = data.subdata(in: data.startIndex..<data.startIndex + count)
            data.removeFirst(count)
            if data.isEmpty { data = Data() } else { data = Data(data) }
            completion(result, nil)
            return
        }
        transport.receive() { [self] newData, _, error in
            if let error {
                completion(nil, error)
                return
            }
            guard let newData, !newData.isEmpty else {
                completion(nil, nil)
                return
            }
            data.append(newData)
            readExact(count: count, completion: completion)
        }
    }

    /// Data remaining in the buffer after the handshake; belongs to the tunneled stream and must not be discarded.
    var remaining: Data? {
        data.isEmpty ? nil : data
    }
}

// MARK: - SOCKS5Transport

/// Replays handshake-leftover bytes (e.g. the start of a TLS ServerHello) on the
/// first `receive` before falling through to the underlying transport.
nonisolated class SOCKS5Transport: RawTransport {
    private var initialData: Data?
    private let inner: any RawTransport

    init(inner: any RawTransport, initialData: Data?) {
        self.inner = inner
        self.initialData = initialData
    }

    var isTransportReady: Bool { inner.isTransportReady }

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        inner.send(data: data, completion: completion)
    }

    func send(data: Data) {
        inner.send(data: data)
    }

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        if let data = initialData {
            initialData = nil
            completion(data, false, nil)
            return
        }
        inner.receive(completion: completion)
    }

    func forceCancel() {
        inner.forceCancel()
    }
}

// MARK: - SOCKS5Handshake

/// SOCKS5 client handshake (greeting, optional auth, CONNECT or UDP ASSOCIATE).
enum SOCKS5Handshake {

    struct UDPRelayInfo {
        let host: String
        let port: UInt16
    }

    static func perform(
        buffer: SOCKS5Buffer,
        transport: any RawTransport,
        destinationHost: String,
        destinationPort: UInt16,
        username: String?,
        password: String?,
        completion: @escaping (Error?) -> Void
    ) {
        performAuth(buffer: buffer, transport: transport, username: username, password: password) { error in
            if let error {
                completion(error)
                return
            }
            sendCommand(
                buffer: buffer,
                transport: transport,
                command: SOCKS5.cmdConnect,
                host: destinationHost,
                port: destinationPort
            ) { result in
                switch result {
                case .success:
                    completion(nil)
                case .failure(let error):
                    completion(error)
                }
            }
        }
    }

    /// UDP ASSOCIATE: per RFC 1928 the client sends 0.0.0.0:0 and the server replies with the relay endpoint.
    static func performUDPAssociate(
        buffer: SOCKS5Buffer,
        transport: any RawTransport,
        username: String?,
        password: String?,
        serverAddress: String,
        completion: @escaping (Result<UDPRelayInfo, Error>) -> Void
    ) {
        performAuth(buffer: buffer, transport: transport, username: username, password: password) { error in
            if let error {
                completion(.failure(error))
                return
            }
            sendCommand(
                buffer: buffer,
                transport: transport,
                command: SOCKS5.cmdUDPAssociate,
                host: "0.0.0.0",
                port: 0
            ) { result in
                switch result {
                case .success(let info):
                    // Servers often return an unreachable private IP for the relay
                    // host; use the server's public address (the port is still valid).
                    completion(.success(UDPRelayInfo(host: serverAddress, port: info.port)))
                case .failure(let error):
                    completion(.failure(error))
                }
            }
        }
    }

    // MARK: - Authentication

    private static func performAuth(
        buffer: SOCKS5Buffer,
        transport: any RawTransport,
        username: String?,
        password: String?,
        completion: @escaping (Error?) -> Void
    ) {
        let hasAuth = username != nil && password != nil
        let authMethod = hasAuth ? SOCKS5.authPassword : SOCKS5.authNone
        let greeting = Data([SOCKS5.version, 0x01, authMethod])

        transport.send(data: greeting) { error in
            if let error { completion(error); return }
            buffer.readExact(count: 2) { data, error in
                if let error { completion(error); return }
                guard let data else {
                    completion(ProxyError.protocolError("SOCKS5 server closed during greeting"))
                    return
                }
                guard data[0] == SOCKS5.version else {
                    completion(ProxyError.protocolError("SOCKS5 unexpected server version: \(data[0])"))
                    return
                }
                let expectedMethod = hasAuth ? SOCKS5.authPassword : SOCKS5.authNone
                guard data[1] == expectedMethod else {
                    if data[1] == SOCKS5.authNoMatch {
                        completion(ProxyError.protocolError("SOCKS5 server: no matching auth method"))
                    } else {
                        completion(ProxyError.protocolError("SOCKS5 auth method mismatch: expected \(expectedMethod), got \(data[1])"))
                    }
                    return
                }
                if hasAuth {
                    sendAuth(buffer: buffer, transport: transport, username: username!, password: password!, completion: completion)
                } else {
                    completion(nil)
                }
            }
        }
    }

    // MARK: - Authentication (RFC 1929)

    private static func sendAuth(
        buffer: SOCKS5Buffer,
        transport: any RawTransport,
        username: String,
        password: String,
        completion: @escaping (Error?) -> Void
    ) {
        let usernameBytes = Data(username.utf8)
        let passwordBytes = Data(password.utf8)
        var authData = Data(capacity: 3 + usernameBytes.count + passwordBytes.count)
        authData.append(0x01) // sub-negotiation version
        authData.append(UInt8(min(usernameBytes.count, 255)))
        authData.append(usernameBytes.prefix(255))
        authData.append(UInt8(min(passwordBytes.count, 255)))
        authData.append(passwordBytes.prefix(255))

        transport.send(data: authData) { error in
            if let error { completion(error); return }
            buffer.readExact(count: 2) { data, error in
                if let error { completion(error); return }
                guard let data else {
                    completion(ProxyError.protocolError("SOCKS5 server closed during auth"))
                    return
                }
                guard data[1] == 0x00 else {
                    completion(ProxyError.protocolError("SOCKS5 authentication failed (status \(data[1]))"))
                    return
                }
                completion(nil)
            }
        }
    }

    // MARK: - Command (CONNECT / UDP ASSOCIATE)

    private static func sendCommand(
        buffer: SOCKS5Buffer,
        transport: any RawTransport,
        command: UInt8,
        host: String,
        port: UInt16,
        completion: @escaping (Result<UDPRelayInfo, Error>) -> Void
    ) {
        var request = Data([SOCKS5.version, command, 0x00])
        request.append(encodeAddress(host: host))
        request.append(UInt8(port >> 8))
        request.append(UInt8(port & 0xFF))

        transport.send(data: request) { error in
            if let error { completion(.failure(error)); return }
            readCommandResponse(buffer: buffer, completion: completion)
        }
    }

    /// Reads the command response: [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
    private static func readCommandResponse(
        buffer: SOCKS5Buffer,
        completion: @escaping (Result<UDPRelayInfo, Error>) -> Void
    ) {
        buffer.readExact(count: 4) { data, error in
            if let error { completion(.failure(error)); return }
            guard let data else {
                completion(.failure(ProxyError.protocolError("SOCKS5 server closed during command")))
                return
            }
            guard data[1] == SOCKS5.statusSuccess else {
                completion(.failure(ProxyError.protocolError("SOCKS5 command failed (reply \(data[1]))")))
                return
            }

            switch data[3] {
            case SOCKS5.addrIPv4:
                buffer.readExact(count: 4 + 2) { addrData, error in
                    if let error { completion(.failure(error)); return }
                    guard let addrData else {
                        completion(.failure(ProxyError.protocolError("SOCKS5 server closed reading bound address")))
                        return
                    }
                    let ip = "\(addrData[0]).\(addrData[1]).\(addrData[2]).\(addrData[3])"
                    let port = UInt16(addrData[4]) << 8 | UInt16(addrData[5])
                    completion(.success(UDPRelayInfo(host: ip, port: port)))
                }

            case SOCKS5.addrIPv6:
                buffer.readExact(count: 16 + 2) { addrData, error in
                    if let error { completion(.failure(error)); return }
                    guard let addrData else {
                        completion(.failure(ProxyError.protocolError("SOCKS5 server closed reading bound address")))
                        return
                    }
                    var parts: [String] = []
                    for i in stride(from: 0, to: 16, by: 2) {
                        parts.append(String(format: "%x", UInt16(addrData[i]) << 8 | UInt16(addrData[i + 1])))
                    }
                    let ip = parts.joined(separator: ":")
                    let port = UInt16(addrData[16]) << 8 | UInt16(addrData[17])
                    completion(.success(UDPRelayInfo(host: ip, port: port)))
                }

            case SOCKS5.addrDomain:
                buffer.readExact(count: 1) { lenData, error in
                    if let error { completion(.failure(error)); return }
                    guard let lenData else {
                        completion(.failure(ProxyError.protocolError("SOCKS5 server closed reading bound address")))
                        return
                    }
                    let domainLen = Int(lenData[0])
                    buffer.readExact(count: domainLen + 2) { domainData, error in
                        if let error { completion(.failure(error)); return }
                        guard let domainData else {
                            completion(.failure(ProxyError.protocolError("SOCKS5 server closed reading bound address")))
                            return
                        }
                        let domain = String(data: domainData.prefix(domainLen), encoding: .utf8) ?? ""
                        let port = UInt16(domainData[domainLen]) << 8 | UInt16(domainData[domainLen + 1])
                        completion(.success(UDPRelayInfo(host: domain, port: port)))
                    }
                }

            default:
                completion(.failure(ProxyError.protocolError("SOCKS5 unknown address type: \(data[3])")))
            }
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
        var buf = Data(count: 16)
        let host = string.hasPrefix("[") && string.hasSuffix("]")
            ? String(string.dropFirst().dropLast()) : string
        guard host.contains(":") else { return nil }
        var result = in6_addr()
        guard inet_pton(AF_INET6, host, &result) == 1 else { return nil }
        buf.withUnsafeMutableBytes { ptr in
            withUnsafeBytes(of: &result) { src in
                ptr.copyBytes(from: src)
            }
        }
        return buf
    }
}

// MARK: - TLSRecordTransport

/// Adapts a ``TLSRecordConnection`` to ``RawTransport`` so the SOCKS5 handshake can run over TLS.
nonisolated class TLSRecordTransport: RawTransport {
    private let tlsConnection: TLSRecordConnection

    init(tlsConnection: TLSRecordConnection) {
        self.tlsConnection = tlsConnection
    }

    var isTransportReady: Bool {
        tlsConnection.connection?.isTransportReady ?? false
    }

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        tlsConnection.send(data: data, completion: completion)
    }

    func send(data: Data) {
        tlsConnection.send(data: data)
    }

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        tlsConnection.receive { data, error in
            if let error {
                completion(nil, true, error)
            } else if let data, !data.isEmpty {
                completion(data, false, nil)
            } else {
                completion(nil, true, nil)
            }
        }
    }

    func forceCancel() {
        tlsConnection.cancel()
    }
}

// MARK: - SOCKS5UDPProxyConnection

/// SOCKS5 UDP ASSOCIATE relay: prepends/strips the SOCKS5 UDP header per datagram.
/// The TCP control connection is retained because closing it ends the UDP session.
nonisolated class SOCKS5UDPProxyConnection: ProxyConnection {
    private let tcpTransport: any RawTransport
    private let tlsClient: TLSClient?
    private let tlsConnection: TLSRecordConnection?
    private let relay: ProxyConnection
    private let udpHeader: Data
    private var cancelled = false

    init(
        tcpTransport: any RawTransport,
        tlsClient: TLSClient?,
        tlsConnection: TLSRecordConnection?,
        relay: ProxyConnection,
        destinationHost: String,
        destinationPort: UInt16
    ) {
        self.tcpTransport = tcpTransport
        self.tlsClient = tlsClient
        self.tlsConnection = tlsConnection
        self.relay = relay

        // Pre-build the SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP + DST.ADDR + DST.PORT
        var header = Data([0x00, 0x00, 0x00])
        header.append(SOCKS5Handshake.encodeAddress(host: destinationHost))
        header.append(UInt8(destinationPort >> 8))
        header.append(UInt8(destinationPort & 0xFF))
        self.udpHeader = header

        super.init()
    }

    override var isConnected: Bool { relay.isConnected }
    override var deliversDatagrams: Bool { true }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        guard !cancelled else {
            completion(ProxyError.connectionFailed("SOCKS5 UDP not connected"))
            return
        }
        var packet = udpHeader
        packet.append(data)
        // `relay.send` so any chain-level framing wraps each datagram.
        relay.send(data: packet, completion: completion)
    }

    override func sendRaw(data: Data) {
        guard !cancelled else { return }
        var packet = udpHeader
        packet.append(data)
        relay.send(data: packet)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        guard !cancelled else {
            completion(nil, ProxyError.connectionFailed("SOCKS5 UDP not connected"))
            return
        }
        relay.receive { [weak self] data, error in
            if let error {
                completion(nil, error)
                return
            }
            guard let self, let data, !data.isEmpty else {
                completion(nil, nil)
                return
            }
            if let payload = self.stripUDPHeader(data) {
                completion(payload, nil)
            } else {
                // Re-issue async: `relay.receive` can deliver inline, so direct
                // recursion would grow the stack under a malformed burst.
                DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                    self?.receiveRaw(completion: completion)
                }
            }
        }
    }

    override func cancel() {
        guard !cancelled else { return }
        cancelled = true
        relay.cancel()
        tcpTransport.forceCancel()
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
