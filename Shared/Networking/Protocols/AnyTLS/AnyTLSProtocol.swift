//
//  AnyTLSProtocol.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import CommonCrypto

/// AnyTLS wire-format constants and pure-data helpers.
///
/// The AnyTLS protocol layers a small framing on top of a normal TLS connection
/// so a single TLS session can multiplex several logical streams. The first
/// bytes after the TLS handshake are
///
///     [SHA256(password) (32 B)] [paddingLen (BE u16)] [paddingLen × 0x00]
///
/// followed by a stream of length-prefixed control/data frames whose header is
///
///     [cmd (1 B)] [sid (BE u32)] [length (BE u16)] [length B payload]
///
/// Cross-ref: github.com/anytls/sing-anytls@0.0.11 — `client.go`,
/// `session/{frame,session,stream}.go`, `padding/padding.go`.
enum AnyTLSProtocol {

    // MARK: - Frame commands

    static let cmdWaste:               UInt8 = 0   // padding
    static let cmdSYN:                 UInt8 = 1   // open stream
    static let cmdPSH:                 UInt8 = 2   // data on stream
    static let cmdFIN:                 UInt8 = 3   // close stream
    static let cmdSettings:            UInt8 = 4   // client→server StringMap
    static let cmdAlert:               UInt8 = 5   // UTF-8 error string
    static let cmdUpdatePaddingScheme: UInt8 = 6   // server→client raw scheme
    static let cmdSYNACK:              UInt8 = 7   // server confirms stream open (v2+)
    static let cmdHeartRequest:        UInt8 = 8   // keepalive ping
    static let cmdHeartResponse:       UInt8 = 9   // keepalive pong
    static let cmdServerSettings:      UInt8 = 10  // server→client StringMap (v2+)

    /// 1 (cmd) + 4 (sid) + 2 (length).
    static let headerSize: Int = 7

    // MARK: - Client identity

    /// Mirrors `util.Verison` in sing-anytls — the literal sent in cmdSettings.
    static let clientVersion: String = "sing-anytls/0.0.11"

    // MARK: - UoT

    /// UDP-over-TCP magic destination for v2 (sing's `uot.MagicAddress`).
    /// The client opens a stream to this FQDN, then writes the UoT request
    /// `[isConnect][SocksaddrSerializer(realDest)]` before sending datagrams.
    static let uotMagicAddress: String = "sp.v2.udp-over-tcp.arpa"

    // MARK: - Password

    /// SHA256(password) — the 32 bytes the server uses to look up the user.
    static func passwordHash(_ password: String) -> Data {
        let bytes = Array(password.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        bytes.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                CC_SHA256(base, CC_LONG(bytes.count), &digest)
            }
        }
        return Data(digest)
    }

    // MARK: - Address (SocksaddrSerializer: 0x01 IPv4, 0x03 FQDN, 0x04 IPv6)

    /// Encodes an address+port as the standard sing SocksaddrSerializer expects:
    /// `atyp(1) + addr + port(BE u16)`. Used both for the per-stream destination
    /// (written into the cmdPSH that follows cmdSYN) and inside the UoT request.
    static func encodeAddrPort(host: String, port: UInt16) -> Data {
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

    // MARK: - Frame header

    /// Builds a 7-byte frame header. Big-endian per sing-anytls.
    static func encodeFrameHeader(cmd: UInt8, sid: UInt32, length: UInt16) -> Data {
        var data = Data(count: headerSize)
        data[0] = cmd
        data[1] = UInt8((sid >> 24) & 0xFF)
        data[2] = UInt8((sid >> 16) & 0xFF)
        data[3] = UInt8((sid >>  8) & 0xFF)
        data[4] = UInt8( sid        & 0xFF)
        data[5] = UInt8((length >> 8) & 0xFF)
        data[6] = UInt8( length       & 0xFF)
        return data
    }

    /// Parses a 7-byte header from `bytes` starting at `offset`. Returns
    /// `nil` if the buffer is too short.
    static func decodeFrameHeader(_ bytes: Data, at offset: Int = 0) -> (cmd: UInt8, sid: UInt32, length: UInt16)? {
        guard bytes.count - offset >= headerSize else { return nil }
        let i = bytes.startIndex + offset
        let cmd = bytes[i]
        let sid = (UInt32(bytes[i + 1]) << 24)
                | (UInt32(bytes[i + 2]) << 16)
                | (UInt32(bytes[i + 3]) <<  8)
                |  UInt32(bytes[i + 4])
        let length = (UInt16(bytes[i + 5]) << 8) | UInt16(bytes[i + 6])
        return (cmd, sid, length)
    }

    /// Builds a complete frame (header + payload). Use for control frames and
    /// when assembling a cmdWaste filler within the padding algorithm.
    static func encodeFrame(cmd: UInt8, sid: UInt32, payload: Data) -> Data {
        let length = UInt16(min(payload.count, Int(UInt16.max)))
        var frame = encodeFrameHeader(cmd: cmd, sid: sid, length: length)
        frame.append(payload.prefix(Int(length)))
        return frame
    }

    // MARK: - StringMap (cmdSettings / cmdServerSettings payload)

    /// Encodes `key=value` lines joined with `\n` (sing-anytls's StringMap
    /// `ToBytes`). Sorted so the byte sequence is deterministic — useful
    /// for tests; the server doesn't care about ordering.
    static func encodeStringMap(_ map: [String: String]) -> Data {
        let lines = map
            .sorted { $0.key < $1.key }
            .map { "\($0.key)=\($0.value)" }
        return Data(lines.joined(separator: "\n").utf8)
    }

    /// Decodes `key=value\nkey=value...` lines. Lines without `=` are skipped.
    static func decodeStringMap(_ data: Data) -> [String: String] {
        guard let text = String(data: data, encoding: .utf8) else { return [:] }
        var map: [String: String] = [:]
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if let eq = line.firstIndex(of: "=") {
                let key = String(line[..<eq])
                let value = String(line[line.index(after: eq)...])
                map[key] = value
            }
        }
        return map
    }

    // MARK: - IP parsing

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
