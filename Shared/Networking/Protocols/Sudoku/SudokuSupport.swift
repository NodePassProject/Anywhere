//
//  SudokuSupport.swift
//  Anywhere
//
//  Created by saba-futai on 10/18/26.
//

import Foundation

nonisolated enum SudokuLifecycle: PhaseTransitionable {
    case open
    case closed

    static func canTransition(from old: SudokuLifecycle, to new: SudokuLifecycle) -> Bool {
        switch (old, new) {
        case (.open, .closed):
            return true
        default:
            return false
        }
    }
}

nonisolated extension Data {
    func zeroBasedData() -> Data { startIndex == 0 ? self : Data(self) }
    
    func uint8(at offset: Int) -> UInt8 { self[startIndex + offset] }

    func prefixData(_ count: Int) -> Data {
        let n = Swift.min(count, self.count)
        guard n > 0 else { return Data() }
        return prefix(n)
    }

    func rangeData(offset: Int, count: Int) -> Data {
        guard offset >= 0, count > 0, offset <= self.count, count <= self.count - offset else { return Data() }
        let start = startIndex + offset
        return self[start..<(start + count)]
    }

    func uint32BE(at offset: Int) -> UInt32 {
        withUnsafeBytes { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            return (UInt32(bytes[offset]) << 24) |
                (UInt32(bytes[offset + 1]) << 16) |
                (UInt32(bytes[offset + 2]) << 8) |
                UInt32(bytes[offset + 3])
        }
    }

    func uint64BE(at offset: Int) -> UInt64 {
        withUnsafeBytes { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            var value: UInt64 = 0
            for index in 0..<8 {
                value = (value << 8) | UInt64(bytes[offset + index])
            }
            return value
        }
    }
}
