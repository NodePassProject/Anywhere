//
//  InternetChecksum.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

struct InternetChecksum: Sendable {
    private var sum: UInt32 = 0
    private var isOddOffset = false

    init() {}

    mutating func update(bufferPointer bytes: UnsafeRawBufferPointer) {
        update(partialSum: Self.partialSum(of: bytes), byteCount: bytes.count)
    }

    mutating func update(partialSum: UInt16, byteCount: Int) {
        guard byteCount > 0 else { return }
        sum = UInt32(Self.fold(UInt64(sum) &+ UInt64(isOddOffset ? partialSum.byteSwapped : partialSum)))
        if byteCount & 1 == 1 {
            isOddOffset.toggle()
        }
    }

    func finalize() -> UInt16 {
        ~UInt16(truncatingIfNeeded: sum)
    }

    static func partialSum(of bytes: UnsafeRawBufferPointer) -> UInt16 {
        guard let base = bytes.baseAddress, !bytes.isEmpty else { return 0 }
        return foldedSum(of: base, count: bytes.count)
    }

    private static func foldedSum(of base: UnsafeRawPointer, count: Int) -> UInt16 {
        var accumulator: UInt64 = 0
        var offset = 0
        while count &- offset >= 64 {
            let blockEnd = offset &+ (min(count &- offset, 1 << 18) & ~63)
            var a = SIMD8<UInt32>.zero
            var b = SIMD8<UInt32>.zero
            var c = SIMD8<UInt32>.zero
            var d = SIMD8<UInt32>.zero
            repeat {
                a &+= SIMD8<UInt32>(truncatingIfNeeded: base.loadUnaligned(fromByteOffset: offset, as: SIMD8<UInt16>.self))
                b &+= SIMD8<UInt32>(truncatingIfNeeded: base.loadUnaligned(fromByteOffset: offset &+ 16, as: SIMD8<UInt16>.self))
                c &+= SIMD8<UInt32>(truncatingIfNeeded: base.loadUnaligned(fromByteOffset: offset &+ 32, as: SIMD8<UInt16>.self))
                d &+= SIMD8<UInt32>(truncatingIfNeeded: base.loadUnaligned(fromByteOffset: offset &+ 48, as: SIMD8<UInt16>.self))
                offset &+= 64
            } while offset < blockEnd
            accumulator &+= UInt64(a.wrappedSum()) &+ UInt64(b.wrappedSum()) &+ UInt64(c.wrappedSum()) &+ UInt64(d.wrappedSum())
        }
        while offset &+ 16 <= count {
            accumulator &+= UInt64(base.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
            accumulator &+= UInt64(base.loadUnaligned(fromByteOffset: offset &+ 4, as: UInt32.self))
            accumulator &+= UInt64(base.loadUnaligned(fromByteOffset: offset &+ 8, as: UInt32.self))
            accumulator &+= UInt64(base.loadUnaligned(fromByteOffset: offset &+ 12, as: UInt32.self))
            offset &+= 16
        }
        while offset &+ 4 <= count {
            accumulator &+= UInt64(base.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
            offset &+= 4
        }
        if offset &+ 2 <= count {
            accumulator &+= UInt64(base.loadUnaligned(fromByteOffset: offset, as: UInt16.self))
            offset &+= 2
        }
        if offset < count {
            accumulator &+= UInt64(UInt16(base.load(fromByteOffset: offset, as: UInt8.self)).littleEndian)
        }
        return fold(accumulator)
    }

    private static func fold(_ value: UInt64) -> UInt16 {
        var folded = (value & 0xFFFF_FFFF) &+ (value >> 32)
        while folded > 0xFFFF {
            folded = (folded & 0xFFFF) &+ (folded >> 16)
        }
        return UInt16(truncatingIfNeeded: folded)
    }
}

extension InternetChecksum {
    mutating func update(pseudoHeaderFor source: IPAddress, destination: IPAddress, protocol: UInt8, length: Int) {
        withUnsafeTemporaryAllocation(byteCount: 40, alignment: 8) { buffer in
            let base = buffer.baseAddress!
            source.write(to: base)
            destination.write(to: base + source.byteCount)
            let count: Int
            if source.isIPv6 {
                base.storeBytes(of: UInt32(length).bigEndian, toByteOffset: 32, as: UInt32.self)
                base.storeBytes(of: UInt32(`protocol`).bigEndian, toByteOffset: 36, as: UInt32.self)
                count = 40
            } else {
                base.storeBytes(of: UInt16(`protocol`).bigEndian, toByteOffset: 8, as: UInt16.self)
                base.storeBytes(of: UInt16(length).bigEndian, toByteOffset: 10, as: UInt16.self)
                count = 12
            }
            update(bufferPointer: UnsafeRawBufferPointer(start: base, count: count))
        }
    }
}
