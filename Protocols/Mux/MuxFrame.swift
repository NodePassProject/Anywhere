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

        let base = data.startIndex
        var offset = 0
        let sessionID = UInt16(data[base + offset]) << 8 | UInt16(data[base + offset + 1])
        offset += 2

        guard let status = MuxSessionStatus(rawValue: data[base + offset]) else { return nil }
        offset += 1

        let option = MuxOption(rawValue: data[base + offset])
        offset += 1

        var metadata = MuxFrameMetadata(
            sessionID: sessionID,
            status: status,
            option: option
        )

        // New frames carry address info
        if status == .new {
            guard data.count >= offset + 1 else { return nil }
            guard let network = MuxNetwork(rawValue: data[base + offset]) else { return nil }
            metadata.network = network
            offset += 1

            // Port (2B big-endian)
            guard data.count >= offset + 2 else { return nil }
            metadata.targetPort = UInt16(data[base + offset]) << 8 | UInt16(data[base + offset + 1])
            offset += 2

            // Address
            guard let (host, addrLen) = decodeAddress(from: data, offset: offset) else { return nil }
            metadata.targetHost = host
            offset += addrLen

            // GlobalID for UDP (optional — only present with XUDP)
            if network == .udp && data.count >= offset + 8 {
                metadata.globalID = data[(base + offset)..<(base + offset + 8)]
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
        let base = data.startIndex
        guard data.count > offset else { return nil }
        guard let addrType = MuxAddressType(rawValue: data[base + offset]) else { return nil }
        var pos = 1  // consumed addr_type byte

        switch addrType {
        case .ipv4:
            guard data.count >= offset + pos + 4 else { return nil }
            let a = data[base + offset + pos]
            let b = data[base + offset + pos + 1]
            let c = data[base + offset + pos + 2]
            let d = data[base + offset + pos + 3]
            return ("\(a).\(b).\(c).\(d)", pos + 4)

        case .domain:
            guard data.count >= offset + pos + 1 else { return nil }
            let domainLen = Int(data[base + offset + pos])
            pos += 1
            guard data.count >= offset + pos + domainLen else { return nil }
            let domain = String(data: data[(base + offset + pos)..<(base + offset + pos + domainLen)], encoding: .utf8) ?? ""
            return (domain, pos + domainLen)

        case .ipv6:
            guard data.count >= offset + pos + 16 else { return nil }
            var addr = in6_addr()
            withUnsafeMutableBytes(of: &addr) { ptr in
                for i in 0..<16 { ptr[i] = data[base + offset + pos + i] }
            }
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &addr, &buf, socklen_t(buf.count))
            return (String(cString: buf), pos + 16)
        }
    }

    // MARK: - IP Parsing Helpers

    private func parseIPv4(_ address: String) -> [UInt8]? {
        var addr = in_addr()
        guard inet_pton(AF_INET, address, &addr) == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0) }
    }

    private func parseIPv6(_ address: String) -> [UInt8]? {
        var clean = address
        if clean.hasPrefix("[") && clean.hasSuffix("]") {
            clean = String(clean.dropFirst().dropLast())
        }
        var addr = in6_addr()
        guard inet_pton(AF_INET6, clean, &addr) == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0) }
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
    private var bufferOffset = 0

    /// Compaction threshold — avoid O(n) shifts until dead space is significant.
    private static let compactThreshold = 4096

    /// Feeds raw bytes into the parser and returns any complete frames.
    func feed(_ data: Data) -> [(metadata: MuxFrameMetadata, payload: Data?)] {
        buffer.append(data)
        var results: [(MuxFrameMetadata, Data?)] = []

        while true {
            let remaining = buffer.count - bufferOffset
            // Need at least 2 bytes for metadata length
            guard remaining >= 2 else { break }

            let metaLen = Int(UInt16(buffer[bufferOffset]) << 8 | UInt16(buffer[bufferOffset + 1]))

            // Need full metadata
            guard remaining >= 2 + metaLen else { break }

            let metaStart = bufferOffset + 2
            let metaSlice = buffer[metaStart..<(metaStart + metaLen)]
            guard let (metadata, _) = MuxFrameMetadata.decode(from: metaSlice) else {
                // Corrupt frame — discard buffer
                buffer.removeAll()
                bufferOffset = 0
                break
            }

            var consumed = 2 + metaLen
            var payload: Data?

            if metadata.option.contains(.data) {
                // Need 2 bytes for payload length
                guard remaining >= consumed + 2 else { break }

                let payloadLen = Int(UInt16(buffer[bufferOffset + consumed]) << 8 | UInt16(buffer[bufferOffset + consumed + 1]))
                consumed += 2

                // Need full payload
                guard remaining >= consumed + payloadLen else {
                    // Revert — not enough payload data yet
                    break
                }

                if payloadLen > 0 {
                    payload = buffer[(bufferOffset + consumed)..<(bufferOffset + consumed + payloadLen)]
                }
                consumed += payloadLen
            }

            results.append((metadata, payload))
            bufferOffset += consumed
        }

        // Compact buffer only when dead space exceeds threshold
        if bufferOffset > Self.compactThreshold {
            buffer.removeSubrange(0..<bufferOffset)
            bufferOffset = 0
        } else if bufferOffset > 0 && bufferOffset == buffer.count {
            // Fully consumed — reset cheaply
            buffer.removeAll(keepingCapacity: true)
            bufferOffset = 0
        }

        return results
    }

    /// Resets the parser state.
    func reset() {
        buffer.removeAll()
        bufferOffset = 0
    }
}
