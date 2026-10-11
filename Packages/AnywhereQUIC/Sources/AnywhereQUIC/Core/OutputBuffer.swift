//
//  OutputBuffer.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct OutputBuffer {
    let storage: UnsafeMutableBufferPointer<UInt8>

    private(set) var writerIndex: Int

    init(storage: UnsafeMutableBufferPointer<UInt8>) {
        self.storage = storage
        self.writerIndex = 0
    }

    var writableBytes: Int { self.storage.count - self.writerIndex }

    mutating func moveWriterIndex(forwardBy distance: Int) {
        precondition(distance >= 0 && distance <= self.writableBytes)
        self.writerIndex += distance
    }

    mutating func moveWriterIndex(to newIndex: Int) {
        precondition(newIndex >= 0 && newIndex <= self.storage.count)
        self.writerIndex = newIndex
    }

    mutating func rewindOnFailure(_ body: (inout OutputBuffer) -> Bool) -> Bool {
        let start = self.writerIndex
        guard body(&self) else {
            self.writerIndex = start
            return false
        }
        return true
    }
}

extension OutputBuffer {
    @discardableResult
    mutating func writeInteger<IntegerType: FixedWidthInteger>(
        _ integer: IntegerType,
        as: IntegerType.Type = IntegerType.self
    ) -> Bool {
        let byteWidth = IntegerType.bitWidth / 8
        guard self.writableBytes >= byteWidth else {
            return false
        }
        for shift in stride(from: (byteWidth - 1) * 8, through: 0, by: -8) {
            self.storage[self.writerIndex] = UInt8(truncatingIfNeeded: integer >> shift)
            self.writerIndex += 1
        }
        return true
    }

    @discardableResult
    mutating func writeVarInt(_ value: UInt64) -> Bool {
        return self.writeVarInt(value, length: VarInt.encodedLength(value))
    }

    @discardableResult
    mutating func writeVarInt(_ value: UInt64, length: Int) -> Bool {
        guard self.writableBytes >= length else {
            return false
        }
        VarInt.write(value, length: length, to: self.storage.baseAddress! + self.writerIndex)
        self.writerIndex += length
        return true
    }

    @discardableResult
    mutating func writeBytes(_ bytes: UnsafeRawBufferPointer) -> Bool {
        guard self.writableBytes >= bytes.count else {
            return false
        }
        if bytes.count > 0 {
            UnsafeMutableRawPointer(self.storage.baseAddress! + self.writerIndex).copyMemory(
                from: bytes.baseAddress!,
                byteCount: bytes.count
            )
        }
        self.writerIndex += bytes.count
        return true
    }

    @discardableResult
    mutating func writeBytes(_ bytes: [UInt8]) -> Bool {
        return bytes.withUnsafeBytes { self.writeBytes($0) }
    }

    @discardableResult
    mutating func writeRepeatingByte(_ byte: UInt8, count: Int) -> Bool {
        guard count >= 0, self.writableBytes >= count else {
            return false
        }
        if count > 0 {
            UnsafeMutableRawPointer(self.storage.baseAddress! + self.writerIndex).initializeMemory(
                as: UInt8.self,
                repeating: byte,
                count: count
            )
        }
        self.writerIndex += count
        return true
    }
}
