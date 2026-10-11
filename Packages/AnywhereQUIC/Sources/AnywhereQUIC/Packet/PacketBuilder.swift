//
//  PacketBuilder.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct PacketBuilder {
    static let lengthFieldSize = 2
    static let minimumSampleBytes = 4

    private(set) var writer: OutputBuffer
    let fullBuffer: UnsafeMutableBufferPointer<UInt8>
    let type: PacketType
    let packetNumber: UInt64
    let packetNumberLength: Int
    let packetNumberOffset: Int
    let lengthFieldOffset: Int
    let payloadOffset: Int

    init?(
        buffer: UnsafeMutableBufferPointer<UInt8>,
        type: PacketType,
        version: QUICVersion,
        destinationID: QUICConnectionID,
        sourceID: QUICConnectionID,
        token: [UInt8],
        packetNumber: UInt64,
        packetNumberLength: Int,
        keyPhase: Bool
    ) {
        precondition(packetNumberLength >= 1 && packetNumberLength <= 4)
        guard buffer.count > AEADAlgorithm.tagLength else {
            return nil
        }
        var writer = OutputBuffer(
            storage: UnsafeMutableBufferPointer(rebasing: buffer[0..<buffer.count - AEADAlgorithm.tagLength])
        )
        let packetNumberBits = UInt8(packetNumberLength - 1)
        var lengthFieldOffset = 0
        if type == .oneRTT {
            var first = PacketHeader.fixedBit | packetNumberBits
            if keyPhase {
                first |= PacketHeader.keyPhaseBit
            }
            guard writer.writeInteger(first), destinationID.withUnsafeBytes({ writer.writeBytes($0) }) else {
                return nil
            }
        } else {
            let first = PacketHeader.formBit | PacketHeader.fixedBit | type.longHeaderTypeBits << 4 | packetNumberBits
            var isWritten = writer.writeInteger(first)
                && writer.writeQUICVersion(version)
                && writer.writeInteger(UInt8(destinationID.count))
                && destinationID.withUnsafeBytes { writer.writeBytes($0) }
                && writer.writeInteger(UInt8(sourceID.count))
                && sourceID.withUnsafeBytes { writer.writeBytes($0) }
            if type == .initial {
                isWritten = isWritten && writer.writeVarInt(UInt64(token.count)) && writer.writeBytes(token)
            }
            guard isWritten else {
                return nil
            }
            lengthFieldOffset = writer.writerIndex
            guard writer.writeVarInt(0, length: Self.lengthFieldSize) else {
                return nil
            }
        }
        self.packetNumberOffset = writer.writerIndex
        let minimumRemaining = Swift.max(packetNumberLength + 1, Self.minimumSampleBytes)
        guard writer.writableBytes >= minimumRemaining else {
            return nil
        }
        let truncated = PacketNumber.truncate(packetNumber, length: packetNumberLength)
        for index in stride(from: packetNumberLength - 1, through: 0, by: -1) {
            writer.writeInteger(UInt8(truncatingIfNeeded: truncated >> UInt32(index * 8)))
        }
        self.writer = writer
        self.fullBuffer = buffer
        self.type = type
        self.packetNumber = packetNumber
        self.packetNumberLength = packetNumberLength
        self.lengthFieldOffset = lengthFieldOffset
        self.payloadOffset = writer.writerIndex
    }

    var writableBytes: Int {
        return self.writer.writableBytes
    }

    var frameLength: Int {
        return self.writer.writerIndex - self.payloadOffset
    }

    var isEmpty: Bool { self.frameLength == 0 }

    var packetLength: Int {
        return self.writer.writerIndex + AEADAlgorithm.tagLength
    }

    mutating func withWriter<Result>(_ body: (inout OutputBuffer) -> Result) -> Result {
        return body(&self.writer)
    }

    var minimumPadding: Int {
        return Swift.max(0, Self.minimumSampleBytes - self.packetNumberLength - self.frameLength)
    }

    @discardableResult
    mutating func pad(toPacketLength length: Int) -> Int {
        let padding = Swift.max(length - self.packetLength, self.minimumPadding)
        let count = Swift.min(padding, self.writableBytes)
        if count > 0 {
            _ = self.writer.writePadding(count)
        }
        return count
    }

    mutating func padToMinimum() {
        let count = self.minimumPadding
        if count > 0 {
            _ = self.writer.writePadding(count)
        }
    }

    mutating func finish(keys: PacketKeys) -> Int {
        self.padToMinimum()
        let total = self.packetLength
        let buffer = self.fullBuffer
        if self.type != .oneRTT {
            let length = UInt64(total - self.packetNumberOffset)
            VarInt.write(length, length: Self.lengthFieldSize, to: buffer.baseAddress! + self.lengthFieldOffset)
        }
        let raw = UnsafeMutableRawBufferPointer(rebasing: UnsafeMutableRawBufferPointer(buffer)[0..<total])
        let header = UnsafeRawBufferPointer(rebasing: raw[0..<self.payloadOffset])
        let payload = UnsafeMutableRawBufferPointer(rebasing: raw[self.payloadOffset..<total])
        do {
            try keys.seal(packetNumber: self.packetNumber, header: header, payload: payload)
        } catch {
            preconditionFailure("packet protection failed")
        }
        keys.protectHeader(raw, packetNumberOffset: self.packetNumberOffset, packetNumberLength: self.packetNumberLength)
        return total
    }
}
