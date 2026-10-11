//
//  InputBuffer.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

enum DecodeError: Hashable, Error {
    case truncated
    case malformed
}

struct InputBuffer {
    let storage: UnsafeRawBufferPointer

    var position: Int

    init(storage: UnsafeRawBufferPointer, position: Int = 0) {
        precondition(position >= 0 && position <= storage.count)
        self.storage = storage
        self.position = position
    }

    var byteCount: Int { self.storage.count - self.position }

    var bytes: UnsafeRawBufferPointer {
        return UnsafeRawBufferPointer(rebasing: self.storage[self.position...])
    }
}

extension InputBuffer {
    mutating func read(length: Int) throws(DecodeError) -> UnsafeRawBufferPointer {
        guard length >= 0, self.byteCount >= length else {
            throw DecodeError.truncated
        }

        defer {
            self.position += length
        }

        return UnsafeRawBufferPointer(rebasing: self.storage[self.position..<(self.position + length)])
    }

    mutating func readBytes(length: Int) throws(DecodeError) -> [UInt8] {
        return Array(try self.read(length: length))
    }

    mutating func readInteger<IntegerType: FixedWidthInteger>(
        as: IntegerType.Type = IntegerType.self
    ) throws(DecodeError) -> IntegerType {
        let bytes = try self.read(length: IntegerType.bitWidth / 8)
        var value = IntegerType.zero
        for byte in bytes {
            value = value << 8 | IntegerType(byte)
        }
        return value
    }

    mutating func readVarInt() throws(DecodeError) -> UInt64 {
        guard let (value, length) = VarInt.read(from: self.bytes) else {
            throw DecodeError.truncated
        }
        self.position += length
        return value
    }
}
