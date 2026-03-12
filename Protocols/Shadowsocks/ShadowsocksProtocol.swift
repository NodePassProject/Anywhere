//
//  ShadowsocksProtocol.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/6/26.
//

import Foundation

/// Shadowsocks wire format utilities.
///
/// Address format: ATYP(1) + Address(var) + Port(2, big-endian)
/// - ATYP 0x01: IPv4 (4 bytes)
/// - ATYP 0x03: Domain (1-byte length + string)
/// - ATYP 0x04: IPv6 (16 bytes)
///
/// Cross-ref: Xray-core/proxy/shadowsocks/protocol.go
enum ShadowsocksProtocol {

    /// Builds a Shadowsocks address header for the given host and port.
    /// Matches `WriteTCPRequest()` address encoding in Xray-core.
    static func buildAddressHeader(host: String, port: UInt16) -> Data {
        var data = Data()

        if let ipv4 = parseIPv4(host) {
            data.append(0x01)
            data.append(contentsOf: ipv4)
        } else if let ipv6 = parseIPv6(host) {
            data.append(0x04)
            data.append(contentsOf: ipv6)
        } else {
            // Domain
            let domainBytes = Array(host.utf8)
            data.append(0x03)
            data.append(UInt8(domainBytes.count))
            data.append(contentsOf: domainBytes)
        }

        // Port (big-endian)
        data.append(UInt8(port >> 8))
        data.append(UInt8(port & 0xFF))

        return data
    }

    /// Encodes a UDP packet: address header + raw payload.
    /// Matches `EncodeUDPPacket()` in Xray-core.
    static func encodeUDPPacket(host: String, port: UInt16, payload: Data) -> Data {
        var data = buildAddressHeader(host: host, port: port)
        data.append(payload)
        return data
    }

    /// Decodes a UDP packet: parses address header, returns (host, port, payload).
    /// Matches `DecodeUDPPacket()` in Xray-core.
    static func decodeUDPPacket(data: Data) -> (host: String, port: UInt16, payload: Data)? {
        guard !data.isEmpty else { return nil }
        var offset = data.startIndex

        let atyp = data[offset]
        offset += 1

        let host: String
        switch atyp {
        case 0x01: // IPv4
            guard data.endIndex - offset >= 4 + 2 else { return nil }
            host = "\(data[offset]).\(data[offset+1]).\(data[offset+2]).\(data[offset+3])"
            offset += 4

        case 0x03: // Domain
            guard data.endIndex - offset >= 1 else { return nil }
            let domainLen = Int(data[offset])
            offset += 1
            guard data.endIndex - offset >= domainLen + 2 else { return nil }
            guard let domain = String(data: data[offset..<(offset + domainLen)], encoding: .utf8) else { return nil }
            host = domain
            offset += domainLen

        case 0x04: // IPv6
            guard data.endIndex - offset >= 16 + 2 else { return nil }
            let bytes = Array(data[offset..<(offset + 16)])
            var parts: [String] = []
            for i in stride(from: 0, to: 16, by: 2) {
                parts.append(String(format: "%x", UInt16(bytes[i]) << 8 | UInt16(bytes[i+1])))
            }
            host = parts.joined(separator: ":")
            offset += 16

        default:
            return nil
        }

        guard data.endIndex - offset >= 2 else { return nil }
        let port = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        offset += 2

        let payload = Data(data[offset...])
        return (host, port, payload)
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
