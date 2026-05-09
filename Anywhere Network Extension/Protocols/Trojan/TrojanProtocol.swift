//
//  TrojanProtocol.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/22/26.
//

import Foundation
import CommonCrypto

/// Trojan wire format utilities.
///
/// TCP request header: `hex(sha224(password))` (56 ASCII bytes) + CRLF
///                   + cmd(1) + ATYP(1) + address(var) + port(2 BE) + CRLF
/// UDP packet format: ATYP(1) + address(var) + port(2 BE) + length(2 BE) + CRLF + payload
/// Address encoding matches SOCKS5 / Shadowsocks: ATYP 0x01 IPv4, 0x03 domain, 0x04 IPv6.
///
/// Cross-ref: Xray-core/proxy/trojan/protocol.go
enum TrojanProtocol {

    /// Command byte values on the wire.
    static let commandTCP: UInt8 = 0x01
    static let commandUDP: UInt8 = 0x03

    /// Max per-packet payload size accepted by upstream Trojan servers.
    /// Matches Xray-core's `maxLength = 8192`.
    static let maxUDPPayloadLength: Int = 8192

    /// SHA224(password) rendered as 56 lowercase-hex ASCII bytes — the exact
    /// byte sequence Trojan servers compare against.
    static func passwordKey(_ password: String) -> Data {
        let bytes = Array(password.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
        _ = bytes.withUnsafeBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress else { return 0 }
            CC_SHA224(base, CC_LONG(bytes.count), &digest)
            return 0
        }
        let hexChars: [UInt8] = Array("0123456789abcdef".utf8)
        var out = Data(count: 56)
        out.withUnsafeMutableBytes { (buf: UnsafeMutableRawBufferPointer) in
            let p = buf.bindMemory(to: UInt8.self).baseAddress!
            for i in 0..<digest.count {
                p[i * 2]     = hexChars[Int(digest[i] >> 4)]
                p[i * 2 + 1] = hexChars[Int(digest[i] & 0x0F)]
            }
        }
        return out
    }

    /// Builds the Trojan TCP/UDP request header that precedes the first payload.
    static func buildRequestHeader(
        passwordKey: Data,
        command: UInt8,
        host: String,
        port: UInt16
    ) -> Data {
        var data = Data(capacity: passwordKey.count + 4 + host.utf8.count + 4)
        data.append(passwordKey)
        data.append(0x0D); data.append(0x0A)
        data.append(command)
        data.append(encodeAddressPort(host: host, port: port))
        data.append(0x0D); data.append(0x0A)
        return data
    }

    /// Encodes ATYP + address + 2-byte big-endian port.
    static func encodeAddressPort(host: String, port: UInt16) -> Data {
        var data = Data()
        if let ipv4 = parseIPv4(host) {
            data.append(0x01)
            data.append(contentsOf: ipv4)
        } else if let ipv6 = parseIPv6(host) {
            data.append(0x04)
            data.append(contentsOf: ipv6)
        } else {
            let domainBytes = Array(host.utf8)
            data.append(0x03)
            data.append(UInt8(min(domainBytes.count, 255)))
            data.append(contentsOf: domainBytes.prefix(255))
        }
        data.append(UInt8(port >> 8))
        data.append(UInt8(port & 0xFF))
        return data
    }

    /// Wraps a single UDP datagram: ATYP/addr/port + length + CRLF + payload.
    static func encodeUDPPacket(host: String, port: UInt16, payload: Data) -> Data {
        let addr = encodeAddressPort(host: host, port: port)
        var out = Data(capacity: addr.count + 4 + payload.count)
        out.append(addr)
        let length = UInt16(min(payload.count, maxUDPPayloadLength))
        out.append(UInt8(length >> 8))
        out.append(UInt8(length & 0xFF))
        out.append(0x0D); out.append(0x0A)
        out.append(payload.prefix(Int(length)))
        return out
    }

    /// Attempts to parse one UDP packet out of a buffered stream.
    /// Returns the payload and the total consumed byte count, or `nil` when
    /// the buffer is short. Throws on malformed framing so the caller can
    /// tear down the connection rather than desynchronize the stream.
    static func tryDecodeUDPPacket(buffer: Data) throws -> (payload: Data, consumed: Int)? {
        guard !buffer.isEmpty else { return nil }
        var offset = buffer.startIndex

        let atyp = buffer[offset]
        offset += 1

        let addrLen: Int
        switch atyp {
        case 0x01: addrLen = 4
        case 0x04: addrLen = 16
        case 0x03:
            guard offset < buffer.endIndex else { return nil }
            let domainLen = Int(buffer[offset])
            offset += 1
            addrLen = domainLen
        default:
            throw ProxyError.protocolError("Trojan: unknown ATYP \(atyp)")
        }

        // Need address + port (2) + length (2) + CRLF (2) before the payload.
        guard buffer.endIndex - offset >= addrLen + 2 + 2 + 2 else { return nil }
        offset += addrLen + 2

        let length = (Int(buffer[offset]) << 8) | Int(buffer[offset + 1])
        offset += 2

        // CRLF
        offset += 2

        guard length <= maxUDPPayloadLength else {
            throw ProxyError.protocolError("Trojan: oversize UDP payload (\(length))")
        }

        guard buffer.endIndex - offset >= length else { return nil }
        let payload = Data(buffer[offset..<(offset + length)])
        let consumed = offset + length - buffer.startIndex
        return (payload, consumed)
    }

    // MARK: - IP Parsing

    private static func parseIPv4(_ address: String) -> [UInt8]? {
        var addr = in_addr()
        guard inet_pton(AF_INET, address, &addr) == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0) }
    }

    private static func parseIPv6(_ address: String) -> [UInt8]? {
        var clean = address
        if clean.hasPrefix("[") && clean.hasSuffix("]") {
            clean = String(clean.dropFirst().dropLast())
        }
        var addr = in6_addr()
        guard inet_pton(AF_INET6, clean, &addr) == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0) }
    }
}
