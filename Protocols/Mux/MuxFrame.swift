//
//  MuxFrame.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

// MARK: - Enums & Types

/// Session status values matching Xray-core SessionStatusNew/Keep/End/KeepAlive.
enum MuxSessionStatus: UInt8 {
    case new       = 0x01
    case keep      = 0x02
    case end       = 0x03
    case keepAlive = 0x04
}

/// Frame option flags (bitmask).
struct MuxOption: OptionSet {
    let rawValue: UInt8
    static let data  = MuxOption(rawValue: 0x01)
    static let error = MuxOption(rawValue: 0x02)
}

/// Network type for mux sessions.
enum MuxNetwork: UInt8 {
    case tcp = 0x01
    case udp = 0x02
}

/// Mux address type (port-first format, matching Xray-core).
private enum MuxAddressType: UInt8 {
    case ipv4   = 0x01
    case domain = 0x02
    case ipv6   = 0x03
}

// MARK: - MuxFrameMetadata

/// Metadata portion of a mux frame.
struct MuxFrameMetadata {
    var sessionID: UInt16
    var status: MuxSessionStatus
    var option: MuxOption
    var network: MuxNetwork?
    var targetHost: String?
    var targetPort: UInt16?
    var globalID: Data?  // 8 bytes, zeros for now (XUDP #16)

    /// Encodes metadata into wire bytes (not including the 2-byte metadata_length prefix).
    func encode() -> Data {
        var buf = Data()

        // Session ID (2B big-endian)
        buf.append(UInt8(sessionID >> 8))
        buf.append(UInt8(sessionID & 0xFF))

        // Status (1B)
        buf.append(status.rawValue)

        // Option (1B)
        buf.append(option.rawValue)

        // Address block for New frames
        if status == .new, let network, let host = targetHost, let port = targetPort {
            // Network (1B)
            buf.append(network.rawValue)

            // Port (2B big-endian) — port-first format
            buf.append(UInt8(port >> 8))
            buf.append(UInt8(port & 0xFF))

            // Address
            encodeAddress(host, into: &buf)

            // GlobalID (8B) for UDP New frames — only when XUDP is active
            // Without XUDP, omit GlobalID (matching Xray-core: only written when b.UDP != nil)
            if network == .udp, let gid = globalID, gid.count == 8 {
                buf.append(gid)
            }
        }

        return buf
    }

    /// Decodes metadata from raw bytes.
    /// Returns `(metadata, bytesConsumed)` or `nil` if insufficient data.
    static func decode(from data: Data) -> (MuxFrameMetadata, Int)? {
        guard data.count >= 4 else { return nil }  // minimum: 2B id + 1B status + 1B option

        var offset = 0
        let sessionID = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        offset += 2

        guard let status = MuxSessionStatus(rawValue: data[offset]) else { return nil }
        offset += 1

        let option = MuxOption(rawValue: data[offset])
        offset += 1

        var metadata = MuxFrameMetadata(
            sessionID: sessionID,
            status: status,
            option: option
        )

        // New frames carry address info
        if status == .new {
            guard data.count >= offset + 1 else { return nil }
            guard let network = MuxNetwork(rawValue: data[offset]) else { return nil }
            metadata.network = network
            offset += 1

            // Port (2B big-endian)
            guard data.count >= offset + 2 else { return nil }
            metadata.targetPort = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
            offset += 2

            // Address
            guard let (host, addrLen) = decodeAddress(from: data, offset: offset) else { return nil }
            metadata.targetHost = host
            offset += addrLen

            // GlobalID for UDP (optional — only present with XUDP)
            if network == .udp && data.count >= offset + 8 {
                metadata.globalID = data[offset..<(offset + 8)]
                offset += 8
            }
        }

        return (metadata, offset)
    }

    // MARK: - Address Encoding (port-first)

    private func encodeAddress(_ host: String, into buf: inout Data) {
        if let ipv4Bytes = parseIPv4(host) {
            buf.append(MuxAddressType.ipv4.rawValue)
            buf.append(contentsOf: ipv4Bytes)
        } else if let ipv6Bytes = parseIPv6(host) {
            buf.append(MuxAddressType.ipv6.rawValue)
            buf.append(contentsOf: ipv6Bytes)
        } else {
            // Domain
            let domainData = host.data(using: .utf8) ?? Data()
            buf.append(MuxAddressType.domain.rawValue)
            buf.append(UInt8(domainData.count))
            buf.append(domainData)
        }
    }

    private static func decodeAddress(from data: Data, offset: Int) -> (String, Int)? {
        guard data.count > offset else { return nil }
        guard let addrType = MuxAddressType(rawValue: data[offset]) else { return nil }
        var pos = 1  // consumed addr_type byte

        switch addrType {
        case .ipv4:
            guard data.count >= offset + pos + 4 else { return nil }
            let a = data[offset + pos]
            let b = data[offset + pos + 1]
            let c = data[offset + pos + 2]
            let d = data[offset + pos + 3]
            return ("\(a).\(b).\(c).\(d)", pos + 4)

        case .domain:
            guard data.count >= offset + pos + 1 else { return nil }
            let domainLen = Int(data[offset + pos])
            pos += 1
            guard data.count >= offset + pos + domainLen else { return nil }
            let domain = String(data: data[(offset + pos)..<(offset + pos + domainLen)], encoding: .utf8) ?? ""
            return (domain, pos + domainLen)

        case .ipv6:
            guard data.count >= offset + pos + 16 else { return nil }
            var parts = [String]()
            for i in stride(from: 0, to: 16, by: 2) {
                let val = UInt16(data[offset + pos + i]) << 8 | UInt16(data[offset + pos + i + 1])
                parts.append(String(val, radix: 16))
            }
            return (parts.joined(separator: ":"), pos + 16)
        }
    }

    // MARK: - IP Parsing Helpers

    private func parseIPv4(_ address: String) -> [UInt8]? {
        let parts = address.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var bytes = [UInt8]()
        for part in parts {
            guard let byte = UInt8(part) else { return nil }
            bytes.append(byte)
        }
        return bytes
    }

    private func parseIPv6(_ address: String) -> [UInt8]? {
        var addr = address
        if addr.hasPrefix("[") && addr.hasSuffix("]") {
            addr = String(addr.dropFirst().dropLast())
        }

        var parts = addr.split(separator: ":", omittingEmptySubsequences: false).map(String.init)

        if let emptyIndex = parts.firstIndex(of: "") {
            let before = Array(parts[..<emptyIndex])
            let after = Array(parts[(emptyIndex + 1)...]).filter { !$0.isEmpty }
            let missing = 8 - before.count - after.count
            if missing < 0 { return nil }
            parts = before + Array(repeating: "0", count: missing) + after
        }

        guard parts.count == 8 else { return nil }

        var bytes = [UInt8]()
        for part in parts {
            guard let value = UInt16(part, radix: 16) else { return nil }
            bytes.append(UInt8(value >> 8))
            bytes.append(UInt8(value & 0xFF))
        }
        return bytes
    }
}

// MARK: - Frame Encoding

/// Encodes a complete mux frame (metadata length + metadata + optional payload).
func encodeMuxFrame(metadata: MuxFrameMetadata, payload: Data?) -> Data {
    let metaBytes = metadata.encode()
    let metaLen = UInt16(metaBytes.count)

    var frame = Data(capacity: 2 + metaBytes.count + (payload != nil ? 2 + payload!.count : 0))

    // Metadata length (2B big-endian)
    frame.append(UInt8(metaLen >> 8))
    frame.append(UInt8(metaLen & 0xFF))

    // Metadata
    frame.append(metaBytes)

    // Payload (if HasData flag set)
    if let payload, metadata.option.contains(.data) {
        let payloadLen = UInt16(payload.count)
        frame.append(UInt8(payloadLen >> 8))
        frame.append(UInt8(payloadLen & 0xFF))
        frame.append(payload)
    }

    return frame
}

// MARK: - Streaming Frame Parser

/// Streaming parser that buffers partial reads and emits complete frames.
class MuxFrameParser {
    private var buffer = Data()

    /// Feeds raw bytes into the parser and returns any complete frames.
    func feed(_ data: Data) -> [(metadata: MuxFrameMetadata, payload: Data?)] {
        buffer.append(data)
        var results: [(MuxFrameMetadata, Data?)] = []

        while true {
            // Need at least 2 bytes for metadata length
            guard buffer.count >= 2 else { break }

            let metaLen = Int(UInt16(buffer[0]) << 8 | UInt16(buffer[1]))

            // Need full metadata
            guard buffer.count >= 2 + metaLen else { break }

            let metaData = buffer[2..<(2 + metaLen)]
            guard let (metadata, _) = MuxFrameMetadata.decode(from: Data(metaData)) else {
                // Corrupt frame — discard buffer
                buffer.removeAll()
                break
            }

            var consumed = 2 + metaLen
            var payload: Data?

            if metadata.option.contains(.data) {
                // Need 2 bytes for payload length
                guard buffer.count >= consumed + 2 else { break }

                let payloadLen = Int(UInt16(buffer[consumed]) << 8 | UInt16(buffer[consumed + 1]))
                consumed += 2

                // Need full payload
                guard buffer.count >= consumed + payloadLen else {
                    // Revert — not enough payload data yet
                    break
                }

                if payloadLen > 0 {
                    payload = Data(buffer[consumed..<(consumed + payloadLen)])
                }
                consumed += payloadLen
            }

            results.append((metadata, payload))
            buffer.removeSubrange(0..<consumed)
        }

        return results
    }

    /// Resets the parser state.
    func reset() {
        buffer.removeAll()
    }
}
