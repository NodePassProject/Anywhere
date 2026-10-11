//
//  FrameWriter.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

extension OutputBuffer {
    mutating func writeDatagram(_ data: UnsafeRawBufferPointer) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(.datagramWithLength)
                && buffer.writeVarInt(UInt64(data.count))
                && buffer.writeBytes(data)
        }
    }

    mutating func writePadding(_ count: Int) -> Bool {
        return self.writeRepeatingByte(0, count: count)
    }

    mutating func writePing() -> Bool {
        return self.writeFrameType(.ping)
    }

    mutating func writeHandshakeDone() -> Bool {
        return self.writeFrameType(.handshakeDone)
    }

    mutating func writeACK(_ ack: ACKFrame) -> Bool {
        return self.rewindOnFailure { buffer in
            var isWritten = buffer.writeFrameType(ack.ecnCounts == nil ? .ack : .ackECN)
                && buffer.writeVarInt(ack.largestAcknowledged)
                && buffer.writeVarInt(ack.ackDelay)
                && buffer.writeVarInt(UInt64(ack.additionalRanges.count))
                && buffer.writeVarInt(ack.firstRange)
            for range in ack.additionalRanges where isWritten {
                isWritten = buffer.writeVarInt(range.gap) && buffer.writeVarInt(range.length)
            }
            if let ecn = ack.ecnCounts, isWritten {
                isWritten = buffer.writeVarInt(ecn.ect0) && buffer.writeVarInt(ecn.ect1) && buffer.writeVarInt(ecn.ce)
            }
            return isWritten
        }
    }

    mutating func writeResetStream(streamID: UInt64, errorCode: UInt64, finalSize: UInt64) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(.resetStream)
                && buffer.writeVarInt(streamID)
                && buffer.writeVarInt(errorCode)
                && buffer.writeVarInt(finalSize)
        }
    }

    mutating func writeStopSending(streamID: UInt64, errorCode: UInt64) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(.stopSending)
                && buffer.writeVarInt(streamID)
                && buffer.writeVarInt(errorCode)
        }
    }

    static func cryptoFrameOverhead(offset: UInt64, length: Int) -> Int {
        return 1 + VarInt.encodedLength(offset) + VarInt.encodedLength(UInt64(length))
    }

    static func cryptoDataCapacity(offset: UInt64, available: Int, wanted: Int) -> Int? {
        let fixed = 1 + VarInt.encodedLength(offset)
        guard available > fixed else {
            return nil
        }
        var length = Swift.min(wanted, available - fixed)
        while length > 0 {
            if fixed + VarInt.encodedLength(UInt64(length)) + length <= available {
                return length
            }
            length -= 1
        }
        return nil
    }

    mutating func writeCrypto(offset: UInt64, data: UnsafeRawBufferPointer) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(.crypto)
                && buffer.writeVarInt(offset)
                && buffer.writeVarInt(UInt64(data.count))
                && buffer.writeBytes(data)
        }
    }

    static func streamDataCapacity(streamID: UInt64, offset: UInt64, available: Int, wanted: Int) -> Int? {
        var fixed = 1 + VarInt.encodedLength(streamID)
        if offset > 0 {
            fixed += VarInt.encodedLength(offset)
        }
        guard available > fixed else {
            return nil
        }
        var length = Swift.min(wanted, available - fixed)
        while true {
            if fixed + VarInt.encodedLength(UInt64(length)) + length <= available {
                return length
            }
            if length == 0 {
                return nil
            }
            length -= 1
        }
    }

    mutating func writeStream(streamID: UInt64, offset: UInt64, data: UnsafeRawBufferPointer, fin: Bool) -> Bool {
        var type = FrameType.stream.rawValue | FrameType.streamLengthBit
        if offset > 0 {
            type |= FrameType.streamOffsetBit
        }
        if fin {
            type |= FrameType.streamFINBit
        }
        return self.rewindOnFailure { buffer in
            var isWritten = buffer.writeFrameType(FrameType(rawValue: type)) && buffer.writeVarInt(streamID)
            if offset > 0 {
                isWritten = isWritten && buffer.writeVarInt(offset)
            }
            return isWritten
                && buffer.writeVarInt(UInt64(data.count))
                && buffer.writeBytes(data)
        }
    }

    mutating func writeMaxData(_ maximum: UInt64) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(.maxData) && buffer.writeVarInt(maximum)
        }
    }

    mutating func writeMaxStreamData(streamID: UInt64, maximum: UInt64) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(.maxStreamData)
                && buffer.writeVarInt(streamID)
                && buffer.writeVarInt(maximum)
        }
    }

    mutating func writeMaxStreams(bidirectional: Bool, maximum: UInt64) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(bidirectional ? .maxStreamsBidirectional : .maxStreamsUnidirectional)
                && buffer.writeVarInt(maximum)
        }
    }

    mutating func writeDataBlocked(_ limit: UInt64) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(.dataBlocked) && buffer.writeVarInt(limit)
        }
    }

    mutating func writeStreamDataBlocked(streamID: UInt64, limit: UInt64) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(.streamDataBlocked)
                && buffer.writeVarInt(streamID)
                && buffer.writeVarInt(limit)
        }
    }

    mutating func writeStreamsBlocked(bidirectional: Bool, limit: UInt64) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(bidirectional ? .streamsBlockedBidirectional : .streamsBlockedUnidirectional)
                && buffer.writeVarInt(limit)
        }
    }

    mutating func writeNewConnectionID(
        sequence: UInt64,
        retirePriorTo: UInt64,
        id: QUICConnectionID,
        token: QUICStatelessResetToken
    ) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(.newConnectionID)
                && buffer.writeVarInt(sequence)
                && buffer.writeVarInt(retirePriorTo)
                && buffer.writeInteger(UInt8(id.count))
                && id.withUnsafeBytes { buffer.writeBytes($0) }
                && token.withUnsafeBytes { buffer.writeBytes($0) }
        }
    }

    mutating func writeRetireConnectionID(sequence: UInt64) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(.retireConnectionID) && buffer.writeVarInt(sequence)
        }
    }

    mutating func writePathChallenge(_ data: UInt64) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(.pathChallenge) && buffer.writeInteger(data)
        }
    }

    mutating func writePathResponse(_ data: UInt64) -> Bool {
        return self.rewindOnFailure { buffer in
            return buffer.writeFrameType(.pathResponse) && buffer.writeInteger(data)
        }
    }

    mutating func writeConnectionClose(
        isApplication: Bool,
        errorCode: UInt64,
        frameType: FrameType,
        reason: [UInt8]
    ) -> Bool {
        return self.rewindOnFailure { buffer in
            var isWritten = buffer.writeFrameType(isApplication ? .applicationClose : .connectionClose)
                && buffer.writeVarInt(errorCode)
            if !isApplication {
                isWritten = isWritten && buffer.writeFrameType(frameType)
            }
            return isWritten
                && buffer.writeVarInt(UInt64(reason.count))
                && buffer.writeBytes(reason)
        }
    }
}
