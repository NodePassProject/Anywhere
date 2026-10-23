//
//  BLAKE3+Compression.swift
//  BLAKE
//
//  Created by NodePassProject on 10/23/26.
//

extension BLAKE3 {
    @inline(__always)
    static func compress(
        _ chainingValue: inout ChainingValue,
        block: UnsafeRawPointer,
        blockLength: Int,
        counter: UInt64,
        flags: Flags
    ) {
        let state = compressionState(chainingValue, block: block, blockLength: blockLength, counter: counter, flags: flags)
        chainingValue = ChainingValue(
            h0: state.v0 ^ state.v8, h1: state.v1 ^ state.v9, h2: state.v2 ^ state.v10, h3: state.v3 ^ state.v11,
            h4: state.v4 ^ state.v12, h5: state.v5 ^ state.v13, h6: state.v6 ^ state.v14, h7: state.v7 ^ state.v15
        )
    }

    static func compressXOF(
        _ chainingValue: ChainingValue,
        block: UnsafeRawPointer,
        blockLength: Int,
        counter: UInt64,
        flags: Flags,
        into output: UnsafeMutableRawPointer
    ) {
        let state = compressionState(chainingValue, block: block, blockLength: blockLength, counter: counter, flags: flags)
        output.storeLittleEndian(state.v0 ^ state.v8, toByteOffset: 0)
        output.storeLittleEndian(state.v1 ^ state.v9, toByteOffset: 4)
        output.storeLittleEndian(state.v2 ^ state.v10, toByteOffset: 8)
        output.storeLittleEndian(state.v3 ^ state.v11, toByteOffset: 12)
        output.storeLittleEndian(state.v4 ^ state.v12, toByteOffset: 16)
        output.storeLittleEndian(state.v5 ^ state.v13, toByteOffset: 20)
        output.storeLittleEndian(state.v6 ^ state.v14, toByteOffset: 24)
        output.storeLittleEndian(state.v7 ^ state.v15, toByteOffset: 28)
        output.storeLittleEndian(state.v8 ^ chainingValue.h0, toByteOffset: 32)
        output.storeLittleEndian(state.v9 ^ chainingValue.h1, toByteOffset: 36)
        output.storeLittleEndian(state.v10 ^ chainingValue.h2, toByteOffset: 40)
        output.storeLittleEndian(state.v11 ^ chainingValue.h3, toByteOffset: 44)
        output.storeLittleEndian(state.v12 ^ chainingValue.h4, toByteOffset: 48)
        output.storeLittleEndian(state.v13 ^ chainingValue.h5, toByteOffset: 52)
        output.storeLittleEndian(state.v14 ^ chainingValue.h6, toByteOffset: 56)
        output.storeLittleEndian(state.v15 ^ chainingValue.h7, toByteOffset: 60)
    }

    @inline(__always)
    private static func compressionState(
        _ chainingValue: ChainingValue,
        block: UnsafeRawPointer,
        blockLength: Int,
        counter: UInt64,
        flags: Flags
    ) -> State {
        let m0 = block.loadLittleEndian(fromByteOffset: 0, as: UInt32.self)
        let m1 = block.loadLittleEndian(fromByteOffset: 4, as: UInt32.self)
        let m2 = block.loadLittleEndian(fromByteOffset: 8, as: UInt32.self)
        let m3 = block.loadLittleEndian(fromByteOffset: 12, as: UInt32.self)
        let m4 = block.loadLittleEndian(fromByteOffset: 16, as: UInt32.self)
        let m5 = block.loadLittleEndian(fromByteOffset: 20, as: UInt32.self)
        let m6 = block.loadLittleEndian(fromByteOffset: 24, as: UInt32.self)
        let m7 = block.loadLittleEndian(fromByteOffset: 28, as: UInt32.self)
        let m8 = block.loadLittleEndian(fromByteOffset: 32, as: UInt32.self)
        let m9 = block.loadLittleEndian(fromByteOffset: 36, as: UInt32.self)
        let m10 = block.loadLittleEndian(fromByteOffset: 40, as: UInt32.self)
        let m11 = block.loadLittleEndian(fromByteOffset: 44, as: UInt32.self)
        let m12 = block.loadLittleEndian(fromByteOffset: 48, as: UInt32.self)
        let m13 = block.loadLittleEndian(fromByteOffset: 52, as: UInt32.self)
        let m14 = block.loadLittleEndian(fromByteOffset: 56, as: UInt32.self)
        let m15 = block.loadLittleEndian(fromByteOffset: 60, as: UInt32.self)

        let iv = ChainingValue.initializationVector
        var state = State(
            v0: chainingValue.h0, v1: chainingValue.h1, v2: chainingValue.h2, v3: chainingValue.h3,
            v4: chainingValue.h4, v5: chainingValue.h5, v6: chainingValue.h6, v7: chainingValue.h7,
            v8: iv.h0, v9: iv.h1, v10: iv.h2, v11: iv.h3,
            v12: UInt32(truncatingIfNeeded: counter),
            v13: UInt32(truncatingIfNeeded: counter &>> 32),
            v14: UInt32(truncatingIfNeeded: blockLength),
            v15: flags.rawValue
        )

        state.round(m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15)
        state.round(m2, m6, m3, m10, m7, m0, m4, m13, m1, m11, m12, m5, m9, m14, m15, m8)
        state.round(m3, m4, m10, m12, m13, m2, m7, m14, m6, m5, m9, m0, m11, m15, m8, m1)
        state.round(m10, m7, m12, m9, m14, m3, m13, m15, m4, m0, m11, m2, m5, m8, m1, m6)
        state.round(m12, m13, m9, m11, m15, m10, m14, m8, m7, m2, m5, m3, m0, m1, m6, m4)
        state.round(m9, m14, m11, m5, m8, m12, m15, m1, m13, m3, m0, m10, m2, m6, m4, m7)
        state.round(m11, m15, m5, m0, m1, m9, m8, m6, m14, m10, m2, m12, m3, m4, m7, m13)
        return state
    }
}

// MARK: - State

extension BLAKE3 {
    struct State {
        var v0, v1, v2, v3, v4, v5, v6, v7: UInt32
        var v8, v9, v10, v11, v12, v13, v14, v15: UInt32

        @inline(__always)
        mutating func round(
            _ m0: UInt32, _ m1: UInt32, _ m2: UInt32, _ m3: UInt32,
            _ m4: UInt32, _ m5: UInt32, _ m6: UInt32, _ m7: UInt32,
            _ m8: UInt32, _ m9: UInt32, _ m10: UInt32, _ m11: UInt32,
            _ m12: UInt32, _ m13: UInt32, _ m14: UInt32, _ m15: UInt32
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
            _ a: inout UInt32, _ b: inout UInt32, _ c: inout UInt32, _ d: inout UInt32,
            _ x: UInt32, _ y: UInt32
        ) {
            a = a &+ b &+ x
            d = (d ^ a).rotatedRight(by: 16)
            c = c &+ d
            b = (b ^ c).rotatedRight(by: 12)
            a = a &+ b &+ y
            d = (d ^ a).rotatedRight(by: 8)
            c = c &+ d
            b = (b ^ c).rotatedRight(by: 7)
        }
    }
}
