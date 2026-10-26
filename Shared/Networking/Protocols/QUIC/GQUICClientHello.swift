//
//  GQUICClientHello.swift
//  Anywhere
//
//  Created by NodePassProject on 10/26/26.
//

import Foundation

nonisolated enum GQUICClientHello {
    enum Lookup: Equatable {
        case needMore
        case unavailable
        case found(serverName: String)
    }

    static let minimumDatagramSize = 1024

    private static let versionFlag: UInt8 = 0x01
    private static let resetFlag: UInt8 = 0x02
    private static let connectionIDFlag: UInt8 = 0x08
    private static let reservedFlags: UInt8 = 0xC0
    private static let connectionIDLength = 8
    private static let packetNumberLengths = [1, 2, 4, 6]
    private static let nullHashLength = 12
    private static let supportedVersions = 39...43
    private static let cryptoStreamID: UInt64 = 1
    private static let streamFrameFlag: UInt8 = 0x80
    private static let streamDataLengthFlag: UInt8 = 0x20
    private static let paddingFrame: UInt8 = 0x00
    private static let pingFrame: UInt8 = 0x07
    private static let messageTag: [UInt8] = Array("CHLO".utf8)
    private static let serverNameTag: [UInt8] = [0x53, 0x4E, 0x49, 0x00]
    private static let messageHeaderLength = 8
    private static let entryLength = 8

    static func looksLikeClientHello(_ datagram: Data) -> Bool {
        datagram.count >= minimumDatagramSize && hasPublicHeader(datagram)
    }

    static func hasPublicHeader(_ datagram: Data) -> Bool {
        headerLength([UInt8](datagram.prefix(1 + connectionIDLength + 4))) != nil
    }

    static func cryptoStreamFragments(_ datagram: Data) -> [(offset: Int, data: Data)]? {
        let bytes = [UInt8](datagram)
        guard let header = headerLength(bytes) else { return nil }
        var position = header + nullHashLength
        var fragments: [(offset: Int, data: Data)] = []
        while position < bytes.count {
            let type = bytes[position]
            position += 1
            if type & streamFrameFlag != 0 {
                let idLength = Int(type & 0x03) + 1
                var offsetLength = Int(type >> 2) & 0x07
                if offsetLength > 0 { offsetLength += 1 }
                guard let streamID = readBigEndian(bytes, at: &position, length: idLength),
                      let offset = readBigEndian(bytes, at: &position, length: offsetLength),
                      offset <= UInt64(Int32.max) else { return nil }
                let dataLength: Int
                if type & streamDataLengthFlag != 0 {
                    guard let length = readBigEndian(bytes, at: &position, length: 2) else { return nil }
                    dataLength = Int(length)
                } else {
                    dataLength = bytes.count - position
                }
                guard dataLength <= bytes.count - position else { return nil }
                if streamID == cryptoStreamID, dataLength > 0 {
                    fragments.append((offset: Int(offset), data: Data(bytes[position..<position + dataLength])))
                }
                position += dataLength
            } else if type == paddingFrame || type == pingFrame {
                continue
            } else {
                break
            }
        }
        return fragments.isEmpty ? nil : fragments
    }

    static func isMessageStart(_ buffer: [UInt8]) -> Bool {
        buffer.count >= messageTag.count && buffer[0..<messageTag.count].elementsEqual(messageTag)
    }

    static func serverName(in buffer: [UInt8], available: Int, limit: Int) -> Lookup {
        guard available >= messageHeaderLength else { return .needMore }
        let entryCount = Int(buffer[4]) | Int(buffer[5]) << 8
        let valuesStart = messageHeaderLength + entryCount * entryLength
        guard valuesStart <= limit else { return .unavailable }
        guard available >= valuesStart else { return .needMore }
        var valueStart = 0
        for entry in 0..<entryCount {
            let base = messageHeaderLength + entry * entryLength
            let valueEnd = Int(buffer[base + 4])
                | Int(buffer[base + 5]) << 8
                | Int(buffer[base + 6]) << 16
                | Int(buffer[base + 7]) << 24
            guard valueEnd >= valueStart else { return .unavailable }
            if buffer[base..<base + 4].elementsEqual(serverNameTag) {
                let start = valuesStart + valueStart
                let end = valuesStart + valueEnd
                guard end <= limit else { return .unavailable }
                guard available >= end else { return .needMore }
                guard end > start, end - start <= 253,
                      let serverName = String(bytes: buffer[start..<end], encoding: .utf8) else {
                    return .unavailable
                }
                return .found(serverName: serverName)
            }
            valueStart = valueEnd
        }
        return .unavailable
    }

    private static func headerLength(_ bytes: [UInt8]) -> Int? {
        let versionOffset = 1 + connectionIDLength
        guard bytes.count >= versionOffset + 4 else { return nil }
        let flags = bytes[0]
        guard flags & versionFlag != 0,
              flags & connectionIDFlag != 0,
              flags & (resetFlag | reservedFlags) == 0,
              bytes[versionOffset] == UInt8(ascii: "Q") else { return nil }
        let digits = bytes[(versionOffset + 1)..<(versionOffset + 4)]
        guard digits.allSatisfy({ (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) }) else { return nil }
        let version = digits.reduce(0) { $0 * 10 + Int($1 - UInt8(ascii: "0")) }
        guard supportedVersions.contains(version) else { return nil }
        return versionOffset + 4 + packetNumberLengths[Int(flags >> 4) & 0x03]
    }

    private static func readBigEndian(_ bytes: [UInt8], at position: inout Int, length: Int) -> UInt64? {
        guard length <= bytes.count - position else { return nil }
        var value: UInt64 = 0
        for byte in bytes[position..<position + length] {
            value = value << 8 | UInt64(byte)
        }
        position += length
        return value
    }
}
