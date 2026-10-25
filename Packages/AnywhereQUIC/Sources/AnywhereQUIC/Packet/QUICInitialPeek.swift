//
//  QUICInitialPeek.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/25/26.
//

import Foundation

public struct QUICInitialPeek: Sendable {
    public struct CryptoFragment: Sendable, Equatable {
        public let offset: Int
        public let data: Data
    }

    public enum Failure: Error, Equatable {
        case notInitial
        case unexpectedPacketType
        case malformed
        case protectionFailed
    }

    public let version: UInt32
    public let destinationID: QUICConnectionID
    public let cryptoFragments: [CryptoFragment]

    public static func hasSupportedLongHeader(_ datagram: Data) -> Bool {
        return datagram.withUnsafeBytes { Self.hasSupportedLongHeader($0) }
    }

    public static func parse(_ datagram: Data) throws(Failure) -> QUICInitialPeek {
        var packet = [UInt8](datagram)
        let result: Result<QUICInitialPeek, Failure> = packet.withUnsafeMutableBytes { bytes in
            Result { () throws(Failure) in try Self.parse(bytes) }
        }
        return try result.get()
    }

    // MARK: - Internals

    private static func isSupported(_ version: QUICVersion) -> Bool {
        return version == .v1 || version == .v2
    }

    private static func hasSupportedLongHeader(_ bytes: UnsafeRawBufferPointer) -> Bool {
        guard bytes.count >= 5, bytes[0] & PacketHeader.formBit != 0 else {
            return false
        }
        let version = UInt32(bytes[1]) << 24
            | UInt32(bytes[2]) << 16
            | UInt32(bytes[3]) << 8
            | UInt32(bytes[4])
        return Self.isSupported(QUICVersion(rawValue: version))
    }

    private static func parse(_ packet: UnsafeMutableRawBufferPointer) throws(Failure) -> QUICInitialPeek {
        guard Self.hasSupportedLongHeader(UnsafeRawBufferPointer(packet)) else {
            throw .notInitial
        }
        let first = try LongHeader.parse(UnsafeRawBufferPointer(packet))
        guard first.isInitial else {
            throw .unexpectedPacketType
        }
        let keys = PacketKeys.initial(destinationID: first.destinationID, isClient: false, version: first.version).read

        var fragments: [CryptoFragment] = []
        var header = first
        var start = 0
        while true {
            if header.isInitial {
                let packetBytes = UnsafeMutableRawBufferPointer(rebasing: packet[start..<start + header.packetEnd])
                do {
                    try Self.collectCryptoFrames(of: packetBytes, header: header, keys: keys, into: &fragments)
                } catch {
                    if start == 0 {
                        throw error
                    }
                    break
                }
            }
            start += header.packetEnd
            guard start < packet.count,
                  packet[start] & PacketHeader.formBit != 0,
                  let next = try? LongHeader.parse(UnsafeRawBufferPointer(rebasing: packet[start...])),
                  next.version == first.version else {
                break
            }
            header = next
        }
        return QUICInitialPeek(
            version: first.version.rawValue,
            destinationID: first.destinationID,
            cryptoFragments: fragments
        )
    }

    private static func collectCryptoFrames(
        of packet: UnsafeMutableRawBufferPointer,
        header: LongHeader,
        keys: PacketKeys,
        into fragments: inout [CryptoFragment]
    ) throws(Failure) {
        guard let unprotected = keys.unprotectHeader(packet, packetNumberOffset: header.packetNumberOffset) else {
            throw .malformed
        }
        let payloadStart = header.packetNumberOffset + unprotected.packetNumberLength
        guard payloadStart + AEADAlgorithm.tagLength <= packet.count else {
            throw .malformed
        }
        let packetNumber = PacketNumber.decode(
            truncated: unprotected.truncatedPacketNumber,
            length: unprotected.packetNumberLength,
            largestReceived: nil
        )
        let associatedData = UnsafeRawBufferPointer(rebasing: packet[0..<payloadStart])
        let payload = UnsafeRawBufferPointer(rebasing: packet[payloadStart...])
        var plaintext = [UInt8](repeating: 0, count: payload.count - AEADAlgorithm.tagLength)
        let opened = plaintext.withUnsafeMutableBytes { output in
            try? keys.open(packetNumber: packetNumber, header: associatedData, payload: payload, into: output)
        }
        guard let plaintextLength = opened else {
            throw .protectionFailed
        }
        plaintext.withUnsafeBytes { bytes in
            var reader = InputBuffer(storage: UnsafeRawBufferPointer(rebasing: bytes[0..<plaintextLength]))
            while reader.byteCount > 0 {
                guard let frame = try? reader.readFrame() else {
                    return
                }
                if case .crypto(let offset, let data) = frame, offset <= UInt64(Int32.max) {
                    fragments.append(CryptoFragment(offset: Int(offset), data: Data(data)))
                }
            }
        }
    }

    private struct LongHeader {
        let version: QUICVersion
        let isInitial: Bool
        let destinationID: QUICConnectionID
        let packetNumberOffset: Int
        let packetEnd: Int

        static func parse(_ bytes: UnsafeRawBufferPointer) throws(Failure) -> LongHeader {
            var reader = InputBuffer(storage: bytes)
            do {
                let first = try reader.readInteger(as: UInt8.self)
                let version = try reader.readQUICVersion()
                let destinationLength = Int(try reader.readInteger(as: UInt8.self))
                guard destinationLength <= QUICConnectionID.maxLength else {
                    throw DecodeError.malformed
                }
                let destinationID = QUICConnectionID(try reader.read(length: destinationLength))
                let sourceLength = Int(try reader.readInteger(as: UInt8.self))
                guard sourceLength <= QUICConnectionID.maxLength else {
                    throw DecodeError.malformed
                }
                _ = try reader.read(length: sourceLength)

                let typeBits = (first >> 4) & 0x03
                let (initialBits, retryBits): (UInt8, UInt8) = version == .v2 ? (0x01, 0x00) : (0x00, 0x03)
                guard typeBits != retryBits else {
                    throw DecodeError.malformed
                }
                let isInitial = typeBits == initialBits
                if isInitial {
                    let tokenLength = try reader.readVarInt()
                    guard tokenLength <= UInt64(reader.byteCount) else {
                        throw DecodeError.malformed
                    }
                    _ = try reader.read(length: Int(tokenLength))
                }
                let length = try reader.readVarInt()
                guard length >= 1, length <= UInt64(reader.byteCount) else {
                    throw DecodeError.malformed
                }
                return LongHeader(
                    version: version,
                    isInitial: isInitial,
                    destinationID: destinationID,
                    packetNumberOffset: reader.position,
                    packetEnd: reader.position + Int(length)
                )
            } catch {
                throw .malformed
            }
        }
    }
}
