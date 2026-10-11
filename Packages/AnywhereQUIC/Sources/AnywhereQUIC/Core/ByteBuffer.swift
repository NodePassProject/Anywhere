//
//  ByteBuffer.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct ByteBuffer {
    private(set) var readableBytesView: [UInt8]

    init(capacity: Int = 64) {
        self.readableBytesView = []
        self.readableBytesView.reserveCapacity(capacity)
    }

    var readableBytes: Int { self.readableBytesView.count }
}

extension ByteBuffer {
    @discardableResult
    mutating func writeInteger<IntegerType: FixedWidthInteger>(
        _ integer: IntegerType,
        as: IntegerType.Type = IntegerType.self
    ) -> Int {
        let byteWidth = IntegerType.bitWidth / 8
        for shift in stride(from: (byteWidth - 1) * 8, through: 0, by: -8) {
            self.readableBytesView.append(UInt8(truncatingIfNeeded: integer >> shift))
        }
        return byteWidth
    }

    @discardableResult
    mutating func writeVarInt(_ value: UInt64) -> Int {
        let length = VarInt.encodedLength(value)
        VarInt.encode(value, into: &self.readableBytesView)
        return length
    }

    @discardableResult
    mutating func writeBytes<Bytes: Collection>(_ bytes: Bytes) -> Int where Bytes.Element == UInt8 {
        self.readableBytesView.append(contentsOf: bytes)
        return bytes.count
    }
}
