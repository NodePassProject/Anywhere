//
//  BLAKE2b+Compression.swift
//  BLAKE
//
//  Created by NodePassProject on 10/23/26.
//

extension BLAKE2b {
    @inline(__always)
    static func compress(
        _ chainingValue: inout ChainingValue,
        block: UnsafeRawPointer,
        byteCount: UInt128,
        isLastBlock: Bool
    ) {
        let m0 = block.loadLittleEndian(fromByteOffset: 0, as: UInt64.self)
        let m1 = block.loadLittleEndian(fromByteOffset: 8, as: UInt64.self)
        let m2 = block.loadLittleEndian(fromByteOffset: 16, as: UInt64.self)
        let m3 = block.loadLittleEndian(fromByteOffset: 24, as: UInt64.self)
        let m4 = block.loadLittleEndian(fromByteOffset: 32, as: UInt64.self)
        let m5 = block.loadLittleEndian(fromByteOffset: 40, as: UInt64.self)
        let m6 = block.loadLittleEndian(fromByteOffset: 48, as: UInt64.self)
        let m7 = block.loadLittleEndian(fromByteOffset: 56, as: UInt64.self)
        let m8 = block.loadLittleEndian(fromByteOffset: 64, as: UInt64.self)
        let m9 = block.loadLittleEndian(fromByteOffset: 72, as: UInt64.self)
        let m10 = block.loadLittleEndian(fromByteOffset: 80, as: UInt64.self)
        let m11 = block.loadLittleEndian(fromByteOffset: 88, as: UInt64.self)
        let m12 = block.loadLittleEndian(fromByteOffset: 96, as: UInt64.self)
        let m13 = block.loadLittleEndian(fromByteOffset: 104, as: UInt64.self)
        let m14 = block.loadLittleEndian(fromByteOffset: 112, as: UInt64.self)
        let m15 = block.loadLittleEndian(fromByteOffset: 120, as: UInt64.self)

        let iv = ChainingValue.initializationVector
        var v = WorkVector(
            v0: chainingValue.h0, v1: chainingValue.h1, v2: chainingValue.h2, v3: chainingValue.h3,
            v4: chainingValue.h4, v5: chainingValue.h5, v6: chainingValue.h6, v7: chainingValue.h7,
            v8: iv.h0, v9: iv.h1, v10: iv.h2, v11: iv.h3,
            v12: iv.h4 ^ UInt64(truncatingIfNeeded: byteCount),
            v13: iv.h5 ^ UInt64(truncatingIfNeeded: byteCount &>> 64),
            v14: isLastBlock ? ~iv.h6 : iv.h6,
            v15: iv.h7
        )

        v.round(m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15)
        v.round(m14, m10, m4, m8, m9, m15, m13, m6, m1, m12, m0, m2, m11, m7, m5, m3)
        v.round(m11, m8, m12, m0, m5, m2, m15, m13, m10, m14, m3, m6, m7, m1, m9, m4)
        v.round(m7, m9, m3, m1, m13, m12, m11, m14, m2, m6, m5, m10, m4, m0, m15, m8)
        v.round(m9, m0, m5, m7, m2, m4, m10, m15, m14, m1, m11, m12, m6, m8, m3, m13)
        v.round(m2, m12, m6, m10, m0, m11, m8, m3, m4, m13, m7, m5, m15, m14, m1, m9)
        v.round(m12, m5, m1, m15, m14, m13, m4, m10, m0, m7, m6, m3, m9, m2, m8, m11)
        v.round(m13, m11, m7, m14, m12, m1, m3, m9, m5, m0, m15, m4, m8, m6, m2, m10)
        v.round(m6, m15, m14, m9, m11, m3, m0, m8, m12, m2, m13, m7, m1, m4, m10, m5)
        v.round(m10, m2, m8, m4, m7, m6, m1, m5, m15, m11, m9, m14, m3, m12, m13, m0)
        v.round(m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15)
        v.round(m14, m10, m4, m8, m9, m15, m13, m6, m1, m12, m0, m2, m11, m7, m5, m3)

        chainingValue.h0 ^= v.v0 ^ v.v8
        chainingValue.h1 ^= v.v1 ^ v.v9
        chainingValue.h2 ^= v.v2 ^ v.v10
        chainingValue.h3 ^= v.v3 ^ v.v11
        chainingValue.h4 ^= v.v4 ^ v.v12
        chainingValue.h5 ^= v.v5 ^ v.v13
        chainingValue.h6 ^= v.v6 ^ v.v14
        chainingValue.h7 ^= v.v7 ^ v.v15
    }
}

// MARK: - Work Vector

extension BLAKE2b {
    struct WorkVector {
        var v0, v1, v2, v3, v4, v5, v6, v7: UInt64
        var v8, v9, v10, v11, v12, v13, v14, v15: UInt64

        @inline(__always)
        mutating func round(
            _ m0: UInt64, _ m1: UInt64, _ m2: UInt64, _ m3: UInt64,
            _ m4: UInt64, _ m5: UInt64, _ m6: UInt64, _ m7: UInt64,
            _ m8: UInt64, _ m9: UInt64, _ m10: UInt64, _ m11: UInt64,
            _ m12: UInt64, _ m13: UInt64, _ m14: UInt64, _ m15: UInt64
        ) {
            Self.mix(&v0, &v4, &v8, &v12, m0, m1)
            Self.mix(&v1, &v5, &v9, &v13, m2, m3)
            Self.mix(&v2, &v6, &v10, &v14, m4, m5)
            Self.mix(&v3, &v7, &v11, &v15, m6, m7)
            Self.mix(&v0, &v5, &v10, &v15, m8, m9)
            Self.mix(&v1, &v6, &v11, &v12, m10, m11)
            Self.mix(&v2, &v7, &v8, &v13, m12, m13)
            Self.mix(&v3, &v4, &v9, &v14, m14, m15)
        }

        @inline(__always)
        private static func mix(
            _ a: inout UInt64, _ b: inout UInt64, _ c: inout UInt64, _ d: inout UInt64,
            _ x: UInt64, _ y: UInt64
        ) {
            a = a &+ b &+ x
            d = (d ^ a).rotatedRight(by: 32)
            c = c &+ d
            b = (b ^ c).rotatedRight(by: 24)
            a = a &+ b &+ y
            d = (d ^ a).rotatedRight(by: 16)
            c = c &+ d
            b = (b ^ c).rotatedRight(by: 63)
        }
    }
}
