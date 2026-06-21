//
//  DeterministicBytesTests.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Testing
import Foundation

struct DeterministicBytesTests {
    @Test func matchesGoBackendKnownAnswer() {
        let data = DeterministicBytes.generate(seed: 42, count: 16)
        let hex = data.map { String(format: "%02x", $0) }.joined()
        #expect(hex == "956eeb2f2632d7bd03f166b233e3ef28")
    }

    @Test func lengthIsExactAndStreamIsPrefixStable() {
        #expect(DeterministicBytes.generate(seed: 7, count: 0).isEmpty)

        let short = DeterministicBytes.generate(seed: 7, count: 8)
        let long = DeterministicBytes.generate(seed: 7, count: 20)
        #expect(short.count == 8)
        #expect(long.count == 20)
        // A longer request must begin with the shorter one (same stream).
        #expect(Array(long.prefix(8)) == Array(short))
    }

    @Test func differentSeedsDiffer() {
        let a = DeterministicBytes.generate(seed: 1, count: 32)
        let b = DeterministicBytes.generate(seed: 2, count: 32)
        #expect(a != b)
    }
}
