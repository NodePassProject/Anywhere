//
//  NowhereMultiplexerProtocol.swift
//  Anywhere
//
//  Created by NodePassProject on 8/24/26.
//

import Foundation

nonisolated enum NowhereMultiplexerConstants {
    static let marker: UInt8 = 0xff

    static let headerSize = 8
    static let maximumFramePayload = 32 * 1024
    static let streamWindowBytes = 512 * 1024
    static let connectionWindowBytes = 512 * 1024
    static let maximumStreams = 256
    static let maximumActiveFlowsPerMultiplexer = 4
    static let outboundFrameLimit = 512
    static let inboundFrameLimit = 512
    static let windowUpdateThreshold = 4 * 1024
    static let minimumFairCreditBytes = 256 * 1024
    static let idleTimeout: TimeInterval = 30
}

nonisolated enum NowhereMultiplexerFrameKind: UInt8, Sendable {
    case stream = 0x01
    case window = 0x02
    case datagram = 0x03
}

nonisolated struct NowhereMultiplexerFrameFlags: OptionSet, Sendable {
    let rawValue: UInt8

    static let syn = Self(rawValue: 0x01)
    static let fin = Self(rawValue: 0x02)
    static let rst = Self(rawValue: 0x04)

    static let known: Self = [.syn, .fin, .rst]
}

nonisolated enum NowhereMultiplexerWireError: Error, Equatable, Sendable {
    case invalidHeaderLength(Int)
    case unknownKind(UInt8)
    case valueTooLarge
    case reservedFlags
    case invalidFlowID
    case invalidWindow
    case invalidReset
}

extension NowhereMultiplexerWireError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .invalidHeaderLength(let length):
            "invalid multiplexer header length: \(length)"
        case .unknownKind(let kind):
            "unknown multiplexer frame kind: \(kind)"
        case .valueTooLarge:
            "multiplexer frame value exceeds u16"
        case .reservedFlags:
            "reserved multiplexer frame flags are non-zero"
        case .invalidFlowID:
            "invalid zero multiplexer flow ID"
        case .invalidWindow:
            "multiplexer window credit must be non-zero"
        case .invalidReset:
            "multiplexer RST must be the only flag and carry no data"
        }
    }
}

nonisolated struct NowhereMultiplexerFrameHeader: Equatable, Sendable {
    let kind: NowhereMultiplexerFrameKind
    let flags: NowhereMultiplexerFrameFlags
    let value: UInt16
    let flowID: UInt32

    static func stream(
        flowID: UInt32,
        flags: NowhereMultiplexerFrameFlags = [],
        payloadLength: Int
    ) throws -> Self {
        guard let value = UInt16(exactly: payloadLength) else {
            throw NowhereMultiplexerWireError.valueTooLarge
        }
        let header = Self(kind: .stream, flags: flags, value: value, flowID: flowID)
        try header.validate()
        return header
    }

    static func window(flowID: UInt32, credit: Int) throws -> Self {
        guard let value = UInt16(exactly: credit) else {
            throw NowhereMultiplexerWireError.valueTooLarge
        }
        let header = Self(kind: .window, flags: [], value: value, flowID: flowID)
        try header.validate()
        return header
    }

    func validate() throws {
        switch kind {
        case .stream:
            guard flowID != 0 else { throw NowhereMultiplexerWireError.invalidFlowID }
            guard flags.subtracting(.known).isEmpty else {
                throw NowhereMultiplexerWireError.reservedFlags
            }
            if flags.contains(.rst), flags != .rst || value != 0 {
                throw NowhereMultiplexerWireError.invalidReset
            }

        case .window:
            guard flags.isEmpty else { throw NowhereMultiplexerWireError.reservedFlags }
            guard value != 0 else { throw NowhereMultiplexerWireError.invalidWindow }

        case .datagram:
            guard flowID != 0 else { throw NowhereMultiplexerWireError.invalidFlowID }
            guard flags.isEmpty else { throw NowhereMultiplexerWireError.reservedFlags }
        }
    }

    func encode() throws -> Data {
        try validate()
        return Data([
            kind.rawValue,
            flags.rawValue,
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value),
            UInt8(truncatingIfNeeded: flowID >> 24),
            UInt8(truncatingIfNeeded: flowID >> 16),
            UInt8(truncatingIfNeeded: flowID >> 8),
            UInt8(truncatingIfNeeded: flowID),
        ])
    }

    static func decode(_ input: Data) throws -> Self {
        guard input.count == NowhereMultiplexerConstants.headerSize else {
            throw NowhereMultiplexerWireError.invalidHeaderLength(input.count)
        }
        let bytes = [UInt8](input)
        guard let kind = NowhereMultiplexerFrameKind(rawValue: bytes[0]) else {
            throw NowhereMultiplexerWireError.unknownKind(bytes[0])
        }
        let header = Self(
            kind: kind,
            flags: NowhereMultiplexerFrameFlags(rawValue: bytes[1]),
            value: UInt16(bytes[2]) << 8 | UInt16(bytes[3]),
            flowID: UInt32(bytes[4]) << 24
                | UInt32(bytes[5]) << 16
                | UInt32(bytes[6]) << 8
                | UInt32(bytes[7])
        )
        try header.validate()
        return header
    }
}
