//
//  DeterministicBytes.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Foundation

enum DeterministicBytes {
    static func generate(seed: UInt64, count: Int) -> Data {
        guard count > 0 else { return Data() }
        var out = Data(count: count)
        var state = seed
        out.withUnsafeMutableBytes { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            var i = 0
            while i < count {
                state = state &+ 0x9E37_79B9_7F4A_7C15
                var z = state
                z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
                z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
                z = z ^ (z >> 31)
                var b: UInt64 = 0
                while b < 8 && i < count {
                    bytes[i] = UInt8((z >> (8 * b)) & 0xFF)
                    i += 1
                    b += 1
                }
            }
        }
        return out
    }
}
