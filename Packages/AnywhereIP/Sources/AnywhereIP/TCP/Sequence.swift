//
//  Sequence.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

enum Sequence {
    static func lessThan(_ a: UInt32, _ b: UInt32) -> Bool {
        (a &- b) & 0x8000_0000 != 0
    }

    static func lessThanOrEqual(_ a: UInt32, _ b: UInt32) -> Bool {
        !lessThan(b, a)
    }

    static func between(_ value: UInt32, _ low: UInt32, _ high: UInt32) -> Bool {
        lessThanOrEqual(low, value) && lessThanOrEqual(value, high)
    }
}
