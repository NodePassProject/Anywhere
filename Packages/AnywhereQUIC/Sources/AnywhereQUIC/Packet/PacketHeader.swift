//
//  PacketHeader.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

enum PacketType: Hashable, Sendable {
    case initial
    case zeroRTT
    case handshake
    case retry
    case versionNegotiation
    case oneRTT

    var isLong: Bool { self != .oneRTT }

    var longHeaderTypeBits: UInt8 {
        switch self {
        case .initial:
            return 0x00
        case .zeroRTT:
            return 0x01
        case .handshake:
            return 0x02
        case .retry:
            return 0x03
        case .versionNegotiation, .oneRTT:
            return 0x00
        }
    }

    static func longType(fromFirstByte byte: UInt8) -> PacketType {
        switch (byte >> 4) & 0x03 {
        case 0x00:
            return .initial
        case 0x01:
            return .zeroRTT
        case 0x02:
            return .handshake
        default:
            return .retry
        }
    }
}

struct QUICVersion: RawRepresentable, Sendable {
    var rawValue: UInt32

    init(rawValue: UInt32) {
        self.rawValue = rawValue
    }
}

extension QUICVersion: Hashable {
    static let negotiation = QUICVersion(rawValue: 0x0000_0000)
    static let v1 = QUICVersion(rawValue: 0x0000_0001)
}

extension QUICVersion: CustomStringConvertible {
    var description: String {
        switch self {
        case .negotiation:
            return "negotiation"
        case .v1:
            return "v1"
        default:
            return "QUICVersion(rawValue: 0x\(String(self.rawValue, radix: 16, uppercase: true)))"
        }
    }
}

extension InputBuffer {
    mutating func readQUICVersion() throws(DecodeError) -> QUICVersion {
        return QUICVersion(rawValue: try self.readInteger(as: UInt32.self))
    }
}

extension OutputBuffer {
    @discardableResult
    mutating func writeQUICVersion(_ version: QUICVersion) -> Bool {
        return self.writeInteger(version.rawValue)
    }
}

struct PacketHeader {
    static let formBit: UInt8 = 0x80
    static let fixedBit: UInt8 = 0x40
    static let keyPhaseBit: UInt8 = 0x04
    static let longReservedBits: UInt8 = 0x0C
    static let shortReservedBits: UInt8 = 0x18
    static let packetNumberLengthMask: UInt8 = 0x03
    static let minimumInitialDestinationIDLength = 8

    var type: PacketType
    var version: QUICVersion
    var destinationID: QUICConnectionID
    var sourceID: QUICConnectionID
    var tokenRange: Range<Int>
    var payloadLength: Int
    var packetNumberOffset: Int
    var firstByte: UInt8

    var hasFixedBit: Bool { self.firstByte & PacketHeader.fixedBit != 0 }
    var keyPhase: Bool { self.firstByte & PacketHeader.keyPhaseBit != 0 }

    var packetEnd: Int {
        return self.packetNumberOffset + self.payloadLength
    }

    static func parse(
        _ bytes: UnsafeRawBufferPointer,
        shortHeaderDestinationIDLength: Int
    ) throws(DiscardedPacketError) -> PacketHeader {
        guard let first = bytes.first else {
            throw DiscardedPacketError()
        }
        if first & Self.formBit == 0 {
            let offset = 1 + shortHeaderDestinationIDLength
            guard bytes.count >= offset else {
                throw DiscardedPacketError()
            }
            let destination = QUICConnectionID(UnsafeRawBufferPointer(rebasing: bytes[1..<offset]))
            return PacketHeader(
                type: .oneRTT,
                version: QUICVersion(rawValue: 0),
                destinationID: destination,
                sourceID: QUICConnectionID(),
                tokenRange: 0..<0,
                payloadLength: 0,
                packetNumberOffset: offset,
                firstByte: first
            )
        }
        var reader = InputBuffer(storage: bytes)
        do {
            _ = try reader.readInteger(as: UInt8.self)
            let version = try reader.readQUICVersion()
            let destinationLength = Int(try reader.readInteger(as: UInt8.self))
            guard destinationLength <= QUICConnectionID.maxLength else {
                throw DiscardedPacketError()
            }
            let destinationBytes = try reader.read(length: destinationLength)
            let sourceLength = Int(try reader.readInteger(as: UInt8.self))
            guard sourceLength <= QUICConnectionID.maxLength else {
                throw DiscardedPacketError()
            }
            let sourceBytes = try reader.read(length: sourceLength)
            if version == .negotiation {
                return PacketHeader(
                    type: .versionNegotiation,
                    version: version,
                    destinationID: QUICConnectionID(destinationBytes),
                    sourceID: QUICConnectionID(sourceBytes),
                    tokenRange: 0..<0,
                    payloadLength: reader.byteCount,
                    packetNumberOffset: reader.position,
                    firstByte: first
                )
            }
            let type = PacketType.longType(fromFirstByte: first)
            var tokenRange = 0..<0
            switch type {
            case .initial:
                let tokenLength = try reader.readVarInt()
                guard tokenLength <= UInt64(reader.byteCount) else {
                    throw DiscardedPacketError()
                }
                let start = reader.position
                _ = try reader.read(length: Int(tokenLength))
                tokenRange = start..<reader.position
            case .retry:
                return PacketHeader(
                    type: .retry,
                    version: version,
                    destinationID: QUICConnectionID(destinationBytes),
                    sourceID: QUICConnectionID(sourceBytes),
                    tokenRange: reader.position..<bytes.count,
                    payloadLength: reader.byteCount,
                    packetNumberOffset: reader.position,
                    firstByte: first
                )
            default:
                break
            }
            let length = try reader.readVarInt()
            guard length <= UInt64(reader.byteCount), length >= 1 else {
                throw DiscardedPacketError()
            }
            return PacketHeader(
                type: type,
                version: version,
                destinationID: QUICConnectionID(destinationBytes),
                sourceID: QUICConnectionID(sourceBytes),
                tokenRange: tokenRange,
                payloadLength: Int(length),
                packetNumberOffset: reader.position,
                firstByte: first
            )
        } catch {
            throw DiscardedPacketError()
        }
    }
}

enum PacketNumber {
    static let max: UInt64 = (1 << 62) - 1

    static func encodedLength(_ packetNumber: UInt64, largestAcknowledged: UInt64?) -> Int {
        let unacknowledged: UInt64
        if let largestAcknowledged {
            unacknowledged = packetNumber - largestAcknowledged
        } else {
            unacknowledged = packetNumber + 1
        }
        let range = unacknowledged * 2
        if range <= 0xFF {
            return 1
        }
        if range <= 0xFFFF {
            return 2
        }
        if range <= 0xFF_FFFF {
            return 3
        }
        return 4
    }

    static func truncate(_ packetNumber: UInt64, length: Int) -> UInt32 {
        return UInt32(truncatingIfNeeded: packetNumber & ((1 << (UInt64(length) * 8)) - 1))
    }

    static func decode(truncated: UInt32, length: Int, largestReceived: UInt64?) -> UInt64 {
        guard let largestReceived else {
            return UInt64(truncated)
        }
        let bits = UInt64(length) * 8
        let expected = largestReceived + 1
        let window = UInt64(1) << bits
        let halfWindow = window / 2
        let mask = window - 1
        let candidate = (expected & ~mask) | UInt64(truncated)
        if candidate + halfWindow <= expected, candidate + window <= Self.max {
            return candidate + window
        }
        if candidate > expected + halfWindow, candidate >= window {
            return candidate - window
        }
        return candidate
    }
}
