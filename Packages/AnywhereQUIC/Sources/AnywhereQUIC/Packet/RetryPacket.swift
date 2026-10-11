//
//  RetryPacket.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct RetryPacket {
    static let integrityTagLength = 16

    var header: PacketHeader
    var token: [UInt8]
    var integrityTag: [UInt8]

    static func parse(_ bytes: UnsafeRawBufferPointer, header: PacketHeader) -> RetryPacket? {
        guard header.type == .retry, header.version != QUICVersion.negotiation else {
            return nil
        }
        let tokenStart = header.tokenRange.lowerBound
        guard bytes.count - tokenStart > Self.integrityTagLength else {
            return nil
        }
        let tagStart = bytes.count - Self.integrityTagLength
        return RetryPacket(
            header: header,
            token: Array(bytes[tokenStart..<tagStart]),
            integrityTag: Array(bytes[tagStart...])
        )
    }

    static func pseudoPacket(originalDestinationID: QUICConnectionID, retryPacket: UnsafeRawBufferPointer) -> [UInt8] {
        var pseudo: [UInt8] = []
        pseudo.reserveCapacity(1 + originalDestinationID.count + retryPacket.count)
        pseudo.append(UInt8(originalDestinationID.count))
        pseudo.append(contentsOf: originalDestinationID.bytes)
        pseudo.append(contentsOf: retryPacket[..<(retryPacket.count - Self.integrityTagLength)])
        return pseudo
    }
}

enum VersionNegotiationPacket {
    static func versions(in bytes: UnsafeRawBufferPointer, header: PacketHeader) -> [UInt32]? {
        guard header.type == .versionNegotiation else {
            return nil
        }
        let payload = UnsafeRawBufferPointer(rebasing: bytes[header.packetNumberOffset...])
        guard payload.count % 4 == 0 else {
            return nil
        }
        var versions: [UInt32] = []
        versions.reserveCapacity(payload.count / 4)
        var reader = InputBuffer(storage: payload)
        while reader.byteCount > 0 {
            guard let version = try? reader.readInteger(as: UInt32.self) else {
                return nil
            }
            versions.append(version)
        }
        return versions
    }
}

enum StatelessResetPacket {
    static let minimumLength = 21

    static func token(in datagram: UnsafeRawBufferPointer) -> QUICStatelessResetToken? {
        guard datagram.count >= Self.minimumLength, datagram[0] & PacketHeader.formBit == 0 else {
            return nil
        }
        return QUICStatelessResetToken(
            UnsafeRawBufferPointer(rebasing: datagram[(datagram.count - QUICStatelessResetToken.length)...])
        )
    }
}
