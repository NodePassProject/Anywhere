//
//  HysteriaProtocol.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation

// MARK: - Constants

enum HysteriaConstants {
    static let urlHost = "hysteria"
    static let urlPath = "/auth"

    static let headerAuth = "Hysteria-Auth"
    static let headerUDPEnabled = "Hysteria-UDP"
    static let headerCCRX = "Hysteria-CC-RX"
    static let headerPadding = "Hysteria-Padding"

    static let statusAuthOK = 233

    /// HTTP/3 frame type used by Hysteria to identify a TCP proxy request stream.
    static let frameTypeTCPRequest: UInt64 = 0x401

    /// Maximum QUIC DATAGRAM frame payload for UDP messages.
    static let maxDatagramFrameSize = 1200

    /// QUIC close error codes (HTTP/3 compatible).
    static let closeErrCodeOK: UInt64 = 0x100
    static let closeErrCodeProtocolError: UInt64 = 0x101

    /// Random padding range for auth request (bytes).
    static let authPaddingMin = 256
    static let authPaddingMax = 2048

    /// Random padding range for TCP request (bytes).
    static let tcpRequestPaddingMin = 64
    static let tcpRequestPaddingMax = 512

    /// Random padding range for TCP response (bytes).
    static let tcpResponsePaddingMin = 128
    static let tcpResponsePaddingMax = 1024
}

// MARK: - QUIC Variable-Length Integer Codec

/// Encodes and decodes QUIC variable-length integers (RFC 9000 §16).
enum QUICVarint {

    /// Encodes a value into a QUIC variable-length integer. Returns the encoded bytes.
    static func encode(_ value: UInt64) -> Data {
        if value <= 63 {
            return Data([UInt8(value)])
        }
        if value <= 16383 {
            var d = Data(count: 2)
            d[0] = UInt8(value >> 8) | 0x40
            d[1] = UInt8(value & 0xFF)
            return d
        }
        if value <= 1_073_741_823 {
            var d = Data(count: 4)
            d[0] = UInt8(value >> 24) | 0x80
            d[1] = UInt8((value >> 16) & 0xFF)
            d[2] = UInt8((value >> 8) & 0xFF)
            d[3] = UInt8(value & 0xFF)
            return d
        }
        var d = Data(count: 8)
        d[0] = UInt8(value >> 56) | 0xC0
        d[1] = UInt8((value >> 48) & 0xFF)
        d[2] = UInt8((value >> 40) & 0xFF)
        d[3] = UInt8((value >> 32) & 0xFF)
        d[4] = UInt8((value >> 24) & 0xFF)
        d[5] = UInt8((value >> 16) & 0xFF)
        d[6] = UInt8((value >> 8) & 0xFF)
        d[7] = UInt8(value & 0xFF)
        return d
    }

    /// Writes a QUIC varint directly into a buffer at the given offset.
    /// Returns the number of bytes written.
    static func put(_ buf: inout Data, at offset: Int, value: UInt64) -> Int {
        let encoded = encode(value)
        buf.replaceSubrange(offset..<(offset + encoded.count), with: encoded)
        return encoded.count
    }

    /// Returns the encoded length of a QUIC varint for the given value.
    static func encodedLength(_ value: UInt64) -> Int {
        if value <= 63 { return 1 }
        if value <= 16383 { return 2 }
        if value <= 1_073_741_823 { return 4 }
        return 8
    }

    /// Decodes a QUIC variable-length integer from a Data buffer starting at `offset`.
    /// Returns `(value, bytesConsumed)` or `nil` if the buffer is too short.
    static func decode(_ data: Data, at offset: Int = 0) -> (value: UInt64, length: Int)? {
        guard offset < data.count else { return nil }
        let first = data[data.startIndex + offset]
        let prefix = first >> 6

        switch prefix {
        case 0:
            return (UInt64(first), 1)
        case 1:
            guard offset + 2 <= data.count else { return nil }
            let v = (UInt64(first & 0x3F) << 8) | UInt64(data[data.startIndex + offset + 1])
            return (v, 2)
        case 2:
            guard offset + 4 <= data.count else { return nil }
            let si = data.startIndex + offset
            let v = (UInt64(first & 0x3F) << 24)
                  | (UInt64(data[si + 1]) << 16)
                  | (UInt64(data[si + 2]) << 8)
                  |  UInt64(data[si + 3])
            return (v, 4)
        case 3:
            guard offset + 8 <= data.count else { return nil }
            let si = data.startIndex + offset
            let v = (UInt64(first & 0x3F) << 56)
                  | (UInt64(data[si + 1]) << 48)
                  | (UInt64(data[si + 2]) << 40)
                  | (UInt64(data[si + 3]) << 32)
                  | (UInt64(data[si + 4]) << 24)
                  | (UInt64(data[si + 5]) << 16)
                  | (UInt64(data[si + 6]) << 8)
                  |  UInt64(data[si + 7])
            return (v, 8)
        default:
            return nil
        }
    }
}

// MARK: - Random Padding

enum HysteriaPadding {
    private static let chars = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".utf8)

    /// Generates a random alphanumeric padding string of length in `[min, max)`.
    static func generate(min: Int, max: Int) -> Data {
        let length = min + Int.random(in: 0..<(max - min))
        var buf = Data(count: length)
        for i in 0..<length {
            buf[i] = chars[Int.random(in: 0..<chars.count)]
        }
        return buf
    }
}

// MARK: - TCP Request / Response

enum HysteriaTCPFraming {

    /// Builds a Hysteria TCP request payload.
    ///
    /// Format: `[addr_len (varint)][addr][padding_len (varint)][padding]`
    static func buildTCPRequest(address: String) -> Data {
        let addrData = Data(address.utf8)
        let padding = HysteriaPadding.generate(
            min: HysteriaConstants.tcpRequestPaddingMin,
            max: HysteriaConstants.tcpRequestPaddingMax
        )

        let addrLenSize = QUICVarint.encodedLength(UInt64(addrData.count))
        let padLenSize = QUICVarint.encodedLength(UInt64(padding.count))
        let totalSize = addrLenSize + addrData.count + padLenSize + padding.count

        var buf = Data(count: totalSize)
        var offset = 0
        offset += QUICVarint.put(&buf, at: offset, value: UInt64(addrData.count))
        buf.replaceSubrange(offset..<(offset + addrData.count), with: addrData)
        offset += addrData.count
        offset += QUICVarint.put(&buf, at: offset, value: UInt64(padding.count))
        buf.replaceSubrange(offset..<(offset + padding.count), with: padding)
        return buf
    }

    /// Parses a Hysteria TCP response from the beginning of a data buffer.
    ///
    /// Format: `[status (1 byte, 0=ok)][msg_len (varint)][msg][padding_len (varint)][padding]`
    ///
    /// Returns `(ok, message, bytesConsumed)` or `nil` if incomplete.
    static func parseTCPResponse(_ data: Data) -> (ok: Bool, message: String, consumed: Int)? {
        guard data.count >= 1 else { return nil }
        let status = data[data.startIndex]
        var offset = 1

        guard let (msgLen, msgLenSize) = QUICVarint.decode(data, at: offset) else { return nil }
        offset += msgLenSize

        guard offset + Int(msgLen) <= data.count else { return nil }
        let message: String
        if msgLen > 0 {
            message = String(data: Data(data[(data.startIndex + offset)..<(data.startIndex + offset + Int(msgLen))]), encoding: .utf8) ?? ""
            offset += Int(msgLen)
        } else {
            message = ""
        }

        guard let (padLen, padLenSize) = QUICVarint.decode(data, at: offset) else { return nil }
        offset += padLenSize + Int(padLen)

        return (status == 0, message, offset)
    }
}

// MARK: - UDP Message

/// Hysteria UDP message framing over QUIC datagrams.
///
/// Format:
/// ```
/// [Session ID (4 bytes BE)]
/// [Packet ID  (2 bytes BE)]
/// [Fragment ID   (1 byte)]
/// [Fragment Count(1 byte)]
/// [Address length (varint)]
/// [Address (bytes)]
/// [Data...]
/// ```
struct HysteriaUDPMessage {
    var sessionID: UInt32
    var packetID: UInt16
    var fragID: UInt8
    var fragCount: UInt8
    var address: String
    var data: Data

    /// Size of the header (everything except `data`).
    var headerSize: Int {
        4 + 2 + 1 + 1 + QUICVarint.encodedLength(UInt64(address.utf8.count)) + address.utf8.count
    }

    /// Total serialized size.
    var totalSize: Int { headerSize + data.count }

    /// Serializes the message into a new Data buffer.
    func serialize() -> Data {
        var buf = Data(count: totalSize)
        buf[0] = UInt8((sessionID >> 24) & 0xFF)
        buf[1] = UInt8((sessionID >> 16) & 0xFF)
        buf[2] = UInt8((sessionID >> 8) & 0xFF)
        buf[3] = UInt8(sessionID & 0xFF)
        buf[4] = UInt8((packetID >> 8) & 0xFF)
        buf[5] = UInt8(packetID & 0xFF)
        buf[6] = fragID
        buf[7] = fragCount

        let addrBytes = Data(address.utf8)
        var offset = 8
        offset += QUICVarint.put(&buf, at: offset, value: UInt64(addrBytes.count))
        buf.replaceSubrange(offset..<(offset + addrBytes.count), with: addrBytes)
        offset += addrBytes.count
        buf.replaceSubrange(offset..<(offset + data.count), with: data)
        return buf
    }

    /// Parses a UDP message from raw datagram bytes.
    static func parse(_ raw: Data) -> HysteriaUDPMessage? {
        guard raw.count >= 8 else { return nil }
        let si = raw.startIndex
        let sessionID = (UInt32(raw[si]) << 24) | (UInt32(raw[si + 1]) << 16)
                      | (UInt32(raw[si + 2]) << 8) | UInt32(raw[si + 3])
        let packetID = (UInt16(raw[si + 4]) << 8) | UInt16(raw[si + 5])
        let fragID = raw[si + 6]
        let fragCount = raw[si + 7]

        guard let (addrLen, addrLenSize) = QUICVarint.decode(raw, at: 8) else { return nil }
        let addrStart = 8 + addrLenSize
        guard addrLen > 0, addrStart + Int(addrLen) < raw.count else { return nil }

        let address = String(data: Data(raw[(si + addrStart)..<(si + addrStart + Int(addrLen))]), encoding: .utf8) ?? ""
        let dataStart = addrStart + Int(addrLen)
        let payload = Data(raw[(si + dataStart)...])

        return HysteriaUDPMessage(
            sessionID: sessionID, packetID: packetID,
            fragID: fragID, fragCount: fragCount,
            address: address, data: payload
        )
    }
}

// MARK: - UDP Fragmentation

enum HysteriaUDPFragmentation {

    /// Fragments a UDP message if it exceeds `maxSize`.
    static func fragment(_ msg: HysteriaUDPMessage, maxSize: Int) -> [HysteriaUDPMessage] {
        if msg.totalSize <= maxSize {
            return [msg]
        }
        let maxPayload = maxSize - msg.headerSize
        guard maxPayload > 0 else { return [msg] }

        let fragCount = (msg.data.count + maxPayload - 1) / maxPayload
        var frags: [HysteriaUDPMessage] = []
        frags.reserveCapacity(fragCount)

        var offset = 0
        for i in 0..<fragCount {
            let end = min(offset + maxPayload, msg.data.count)
            var frag = msg
            frag.fragID = UInt8(i)
            frag.fragCount = UInt8(fragCount)
            frag.data = Data(msg.data[offset..<end])
            frags.append(frag)
            offset = end
        }
        return frags
    }
}

/// Reassembles fragmented UDP messages. Handles one packet ID at a time;
/// a new packet ID discards any previous incomplete state.
class HysteriaDefragger {
    private var packetID: UInt16 = 0
    private var fragments: [HysteriaUDPMessage?] = []
    private var receivedCount: Int = 0
    private var dataSize: Int = 0

    /// Feeds a received message. Returns the reassembled message when all
    /// fragments have been received, or `nil` if still waiting.
    func feed(_ msg: HysteriaUDPMessage) -> HysteriaUDPMessage? {
        if msg.fragCount <= 1 { return msg }
        guard msg.fragID < msg.fragCount else { return nil }

        if msg.packetID != packetID || Int(msg.fragCount) != fragments.count {
            // New packet — reset state
            packetID = msg.packetID
            fragments = [HysteriaUDPMessage?](repeating: nil, count: Int(msg.fragCount))
            receivedCount = 0
            dataSize = 0
        }

        guard fragments[Int(msg.fragID)] == nil else { return nil }
        fragments[Int(msg.fragID)] = msg
        receivedCount += 1
        dataSize += msg.data.count

        if receivedCount == fragments.count {
            // All fragments received — reassemble
            var assembled = Data(capacity: dataSize)
            for frag in fragments {
                assembled.append(frag!.data)
            }
            var result = msg
            result.data = assembled
            result.fragID = 0
            result.fragCount = 1
            return result
        }
        return nil
    }
}
