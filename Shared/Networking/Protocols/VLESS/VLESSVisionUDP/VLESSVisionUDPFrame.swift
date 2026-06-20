//
//  VLESSVisionUDPFrame.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

// MARK: - Enums & Types

enum VLESSVisionUDPFrameStatus: UInt8 {
    case new       = 0x01
    case keep      = 0x02
    case end       = 0x03
    case keepAlive = 0x04
}

struct VLESSVisionUDPFrameOption: OptionSet {
    let rawValue: UInt8
    static let data  = VLESSVisionUDPFrameOption(rawValue: 0x01)
    static let error = VLESSVisionUDPFrameOption(rawValue: 0x02)
}

enum VLESSVisionUDPNetwork: UInt8 {
    case tcp = 0x01
    case udp = 0x02
}

private enum MuxAddressType: UInt8 {
    case ipv4   = 0x01
    case domain = 0x02
    case ipv6   = 0x03
}

// MARK: - VLESSVisionUDPFrameMetadata

struct VLESSVisionUDPFrameMetadata {
    var sessionID: UInt16
    var status: VLESSVisionUDPFrameStatus
    var option: VLESSVisionUDPFrameOption
    var network: VLESSVisionUDPNetwork?
    var targetHost: String?
    var targetPort: UInt16?
    var globalID: Data?  // 8 bytes

    /// Wire bytes excluding the 2-byte metadata_length prefix.
    func encode() -> Data {
        var buffer = Data()

        buffer.append(UInt8(sessionID >> 8))
        buffer.append(UInt8(sessionID & 0xFF))

        buffer.append(status.rawValue)
        buffer.append(option.rawValue)

        if status == .new, let network, let host = targetHost, let port = targetPort {
            buffer.append(network.rawValue)

            // Port precedes address (port-first wire format)
            buffer.append(UInt8(port >> 8))
            buffer.append(UInt8(port & 0xFF))

            encodeAddress(host, into: &buffer)

            // GlobalID: 8B, UDP only
            if network == .udp, let gid = globalID, gid.count == 8 {
                buffer.append(gid)
            }
        }

        return buffer
    }

    /// Returns `(metadata, bytesConsumed)`, or `nil` if insufficient data.
    static func decode(from data: Data) -> (VLESSVisionUDPFrameMetadata, Int)? {
        guard data.count >= 4 else { return nil }  // minimum: 2B id + 1B status + 1B option

        let base = data.startIndex
        var offset = 0
        let sessionID = UInt16(data[base + offset]) << 8 | UInt16(data[base + offset + 1])
        offset += 2

        guard let status = VLESSVisionUDPFrameStatus(rawValue: data[base + offset]) else { return nil }
        offset += 1

        let option = VLESSVisionUDPFrameOption(rawValue: data[base + offset])
        offset += 1

        var metadata = VLESSVisionUDPFrameMetadata(
            sessionID: sessionID,
            status: status,
            option: option
        )

        if status == .new {
            guard data.count >= offset + 1 else { return nil }
            guard let network = VLESSVisionUDPNetwork(rawValue: data[base + offset]) else { return nil }
            metadata.network = network
            offset += 1

            guard data.count >= offset + 2 else { return nil }
            metadata.targetPort = UInt16(data[base + offset]) << 8 | UInt16(data[base + offset + 1])
            offset += 2

            guard let (host, addrLen) = decodeAddress(from: data, offset: offset) else { return nil }
            metadata.targetHost = host
            offset += addrLen

            // GlobalID: optional 8B trailer, UDP only
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
        var position = 1

        switch addrType {
        case .ipv4:
            guard data.count >= offset + position + 4 else { return nil }
            let a = data[base + offset + position]
            let b = data[base + offset + position + 1]
            let c = data[base + offset + position + 2]
            let d = data[base + offset + position + 3]
            return ("\(a).\(b).\(c).\(d)", position + 4)

        case .domain:
            guard data.count >= offset + position + 1 else { return nil }
            let domainLen = Int(data[base + offset + position])
            position += 1
            guard data.count >= offset + position + domainLen else { return nil }
            let domain = String(data: data[(base + offset + position)..<(base + offset + position + domainLen)], encoding: .utf8) ?? ""
            return (domain, position + domainLen)

        case .ipv6:
            guard data.count >= offset + position + 16 else { return nil }
            var address = in6_addr()
            withUnsafeMutableBytes(of: &address) { pointer in
                for i in 0..<16 { pointer[i] = data[base + offset + position + i] }
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count))
            return (String(cString: buffer), position + 16)
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

enum VLESSVisionUDPFrame {
    static func encode(metadata: VLESSVisionUDPFrameMetadata, payload: Data?) -> Data {
        let metaBytes = metadata.encode()
        let metaLen = UInt16(metaBytes.count)

        var frame = Data(capacity: 2 + metaBytes.count + (payload != nil ? 2 + payload!.count : 0))

        frame.append(UInt8(metaLen >> 8))
        frame.append(UInt8(metaLen & 0xFF))

        frame.append(metaBytes)

        if let payload, metadata.option.contains(.data) {
            let payloadLen = UInt16(payload.count)
            frame.append(UInt8(payloadLen >> 8))
            frame.append(UInt8(payloadLen & 0xFF))
            frame.append(payload)
        }

        return frame
    }
}

// MARK: - Streaming Frame Parser

nonisolated class VLESSVisionUDPFrameParser {
    private var buffer = Data()
    private var bufferOffset = 0

    /// Compaction threshold — avoid O(n) shifts until dead space is significant.
    private static let compactThreshold = 4096

    func feed(_ data: Data) -> [(metadata: VLESSVisionUDPFrameMetadata, payload: Data?)] {
        buffer.append(data)
        var results: [(VLESSVisionUDPFrameMetadata, Data?)] = []

        while true {
            let remaining = buffer.count - bufferOffset
            guard remaining >= 2 else { break }

            let metaLen = Int(UInt16(buffer[bufferOffset]) << 8 | UInt16(buffer[bufferOffset + 1]))

            guard remaining >= 2 + metaLen else { break }

            let metaStart = bufferOffset + 2
            let metaSlice = buffer[metaStart..<(metaStart + metaLen)]
            guard let (metadata, _) = VLESSVisionUDPFrameMetadata.decode(from: metaSlice) else {
                // Corrupt frame — discard buffer
                buffer.removeAll()
                bufferOffset = 0
                break
            }

            var consumed = 2 + metaLen
            var payload: Data?

            if metadata.option.contains(.data) {
                guard remaining >= consumed + 2 else { break }

                let payloadLen = Int(UInt16(buffer[bufferOffset + consumed]) << 8 | UInt16(buffer[bufferOffset + consumed + 1]))
                consumed += 2

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

        if bufferOffset > Self.compactThreshold {
            buffer.removeSubrange(0..<bufferOffset)
            bufferOffset = 0
        } else if bufferOffset > 0 && bufferOffset == buffer.count {
            buffer.removeAll(keepingCapacity: true)
            bufferOffset = 0
        }

        return results
    }

    func reset() {
        buffer.removeAll()
        bufferOffset = 0
    }
}
