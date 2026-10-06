//
//  NowhereMorphCrypto.swift
//  Anywhere
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

nonisolated enum NowhereMorphCrypto {
    private typealias Lane = SIMD4<UInt32>

    private static let blockSize = 64
    private static let blocksPerRound = 4
    private static let roundSize = blockSize * blocksPerRound

    static func xor(
        destination: UnsafeMutableRawBufferPointer,
        input: UnsafeRawBufferPointer,
        key: UnsafeRawBufferPointer,
        nonce: UnsafeRawBufferPointer,
        offset: UInt64
    ) {
        precondition(destination.count == input.count && key.count == 32 && nonce.count == 12)
        guard !input.isEmpty else { return }
        withUnsafeTemporaryAllocation(of: UInt32.self, capacity: 16) { initial in
            withUnsafeTemporaryAllocation(byteCount: roundSize, alignment: 16) { keystream in
                initial[0] = 0x6170_7865
                initial[1] = 0x3320_646e
                initial[2] = 0x7962_2d32
                initial[3] = 0x6b20_6574
                for index in 0..<8 {
                    initial[4 + index] = loadWord(key, at: index * 4)
                }
                initial[12] = 0
                for index in 0..<3 {
                    initial[13 + index] = loadWord(nonce, at: index * 4)
                }
                var consumed = 0
                let total = input.count
                while consumed < total {
                    let position = offset + UInt64(consumed)
                    let counter = UInt32(position / UInt64(blockSize))
                    let skip = Int(position % UInt64(blockSize))
                    fourBlocks(initial, counter: counter, into: keystream)
                    let count = min(total - consumed, roundSize - skip)
                    apply(keystream, skip: skip, count: count, input: input, destination: destination, at: consumed)
                    consumed += count
                }
            }
        }
    }

    @inline(__always)
    private static func apply(
        _ keystream: UnsafeMutableRawBufferPointer,
        skip: Int,
        count: Int,
        input: UnsafeRawBufferPointer,
        destination: UnsafeMutableRawBufferPointer,
        at base: Int
    ) {
        var index = 0
        while index + 8 <= count {
            let mask = keystream.loadUnaligned(fromByteOffset: skip + index, as: UInt64.self)
            let value = input.loadUnaligned(fromByteOffset: base + index, as: UInt64.self) ^ mask
            destination.storeBytes(of: value, toByteOffset: base + index, as: UInt64.self)
            index += 8
        }
        while index < count {
            destination[base + index] = input[base + index] ^ keystream[skip + index]
            index += 1
        }
    }

    @inline(__always)
    private static func fourBlocks(
        _ initial: UnsafeMutableBufferPointer<UInt32>,
        counter: UInt32,
        into keystream: UnsafeMutableRawBufferPointer
    ) {
        let i0 = Lane(repeating: initial[0]), i1 = Lane(repeating: initial[1])
        let i2 = Lane(repeating: initial[2]), i3 = Lane(repeating: initial[3])
        let i4 = Lane(repeating: initial[4]), i5 = Lane(repeating: initial[5])
        let i6 = Lane(repeating: initial[6]), i7 = Lane(repeating: initial[7])
        let i8 = Lane(repeating: initial[8]), i9 = Lane(repeating: initial[9])
        let i10 = Lane(repeating: initial[10]), i11 = Lane(repeating: initial[11])
        let i12 = Lane(counter, counter &+ 1, counter &+ 2, counter &+ 3)
        let i13 = Lane(repeating: initial[13]), i14 = Lane(repeating: initial[14])
        let i15 = Lane(repeating: initial[15])
        var x0 = i0, x1 = i1, x2 = i2, x3 = i3
        var x4 = i4, x5 = i5, x6 = i6, x7 = i7
        var x8 = i8, x9 = i9, x10 = i10, x11 = i11
        var x12 = i12, x13 = i13, x14 = i14, x15 = i15
        for _ in 0..<10 {
            quarterRound(&x0, &x4, &x8, &x12)
            quarterRound(&x1, &x5, &x9, &x13)
            quarterRound(&x2, &x6, &x10, &x14)
            quarterRound(&x3, &x7, &x11, &x15)
            quarterRound(&x0, &x5, &x10, &x15)
            quarterRound(&x1, &x6, &x11, &x12)
            quarterRound(&x2, &x7, &x8, &x13)
            quarterRound(&x3, &x4, &x9, &x14)
        }
        store(x0 &+ i0, word: 0, into: keystream)
        store(x1 &+ i1, word: 1, into: keystream)
        store(x2 &+ i2, word: 2, into: keystream)
        store(x3 &+ i3, word: 3, into: keystream)
        store(x4 &+ i4, word: 4, into: keystream)
        store(x5 &+ i5, word: 5, into: keystream)
        store(x6 &+ i6, word: 6, into: keystream)
        store(x7 &+ i7, word: 7, into: keystream)
        store(x8 &+ i8, word: 8, into: keystream)
        store(x9 &+ i9, word: 9, into: keystream)
        store(x10 &+ i10, word: 10, into: keystream)
        store(x11 &+ i11, word: 11, into: keystream)
        store(x12 &+ i12, word: 12, into: keystream)
        store(x13 &+ i13, word: 13, into: keystream)
        store(x14 &+ i14, word: 14, into: keystream)
        store(x15 &+ i15, word: 15, into: keystream)
    }

    @inline(__always)
    private static func store(_ words: Lane, word: Int, into keystream: UnsafeMutableRawBufferPointer) {
        for block in 0..<blocksPerRound {
            keystream.storeBytes(of: words[block].littleEndian, toByteOffset: block * blockSize + word * 4, as: UInt32.self)
        }
    }

    @inline(__always)
    private static func quarterRound(_ a: inout Lane, _ b: inout Lane, _ c: inout Lane, _ d: inout Lane) {
        a &+= b
        d = rotateLeft(d ^ a, by: 16)
        c &+= d
        b = rotateLeft(b ^ c, by: 12)
        a &+= b
        d = rotateLeft(d ^ a, by: 8)
        c &+= d
        b = rotateLeft(b ^ c, by: 7)
    }

    @inline(__always)
    private static func rotateLeft(_ value: Lane, by bits: UInt32) -> Lane {
        value &<< bits | value &>> (32 - bits)
    }

    @inline(__always)
    private static func loadWord(_ bytes: UnsafeRawBufferPointer, at offset: Int) -> UInt32 {
        UInt32(littleEndian: bytes.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
    }
}
