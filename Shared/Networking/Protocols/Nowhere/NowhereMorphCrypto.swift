//
//  NowhereMorphCrypto.swift
//  Anywhere
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

nonisolated enum NowhereMorphCrypto {
    static func xor(
        destination: UnsafeMutableRawBufferPointer,
        input: UnsafeRawBufferPointer,
        key: UnsafeRawBufferPointer,
        nonce: UnsafeRawBufferPointer,
        offset: UInt64
    ) {
        precondition(destination.count == input.count && key.count == 32 && nonce.count == 12)
        withUnsafeTemporaryAllocation(of: UInt32.self, capacity: 16) { initial in
            withUnsafeTemporaryAllocation(of: UInt32.self, capacity: 16) { working in
                initial.initialize(repeating: 0)
                working.initialize(repeating: 0)
                initial[0] = 0x6170_7865
                initial[1] = 0x3320_646e
                initial[2] = 0x7962_2d32
                initial[3] = 0x6b20_6574
                for index in 0..<8 {
                    initial[4 + index] = loadWord(key, at: index * 4)
                }
                for index in 0..<3 {
                    initial[13 + index] = loadWord(nonce, at: index * 4)
                }

                var consumed = 0
                while consumed < input.count {
                    let position = offset + UInt64(consumed)
                    initial[12] = UInt32(position / 64)
                    for index in 0..<16 { working[index] = initial[index] }
                    for _ in 0..<10 {
                        quarterRound(working, 0, 4, 8, 12)
                        quarterRound(working, 1, 5, 9, 13)
                        quarterRound(working, 2, 6, 10, 14)
                        quarterRound(working, 3, 7, 11, 15)
                        quarterRound(working, 0, 5, 10, 15)
                        quarterRound(working, 1, 6, 11, 12)
                        quarterRound(working, 2, 7, 8, 13)
                        quarterRound(working, 3, 4, 9, 14)
                    }
                    for index in 0..<16 { working[index] &+= initial[index] }

                    let blockOffset = Int(position % 64)
                    let count = min(input.count - consumed, 64 - blockOffset)
                    for index in 0..<count {
                        let byte = blockOffset + index
                        let mask = UInt8(truncatingIfNeeded: working[byte / 4] >> ((byte % 4) * 8))
                        destination[consumed + index] = input[consumed + index] ^ mask
                    }
                    consumed += count
                }
            }
        }
    }

    @inline(__always)
    private static func loadWord(_ bytes: UnsafeRawBufferPointer, at offset: Int) -> UInt32 {
        UInt32(bytes[offset]) | UInt32(bytes[offset + 1]) << 8
            | UInt32(bytes[offset + 2]) << 16 | UInt32(bytes[offset + 3]) << 24
    }

    @inline(__always)
    private static func rotateLeft(_ value: UInt32, by bits: Int) -> UInt32 {
        value << bits | value >> (32 - bits)
    }

    @inline(__always)
    private static func quarterRound(
        _ state: UnsafeMutableBufferPointer<UInt32>, _ ai: Int, _ bi: Int, _ ci: Int, _ di: Int
    ) {
        var a = state[ai], b = state[bi], c = state[ci], d = state[di]
        a &+= b
        d = rotateLeft(d ^ a, by: 16)
        c &+= d
        b = rotateLeft(b ^ c, by: 12)
        a &+= b
        d = rotateLeft(d ^ a, by: 8)
        c &+= d
        b = rotateLeft(b ^ c, by: 7)
        state[ai] = a
        state[bi] = b
        state[ci] = c
        state[di] = d
    }
}
