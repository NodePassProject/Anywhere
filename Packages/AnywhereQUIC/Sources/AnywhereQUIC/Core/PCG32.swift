//
//  PCG32.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct PCG32 {
    private static let multiplier: UInt64 = 6_364_136_223_846_793_005
    private static let increment: UInt64 = 1_442_695_040_888_963_407

    private(set) var state: UInt64

    init(seed: UInt64) {
        self.state = 0
        self.step()
        self.state &+= seed
        self.step()
    }

    init() {
        var generator = SystemRandomNumberGenerator()
        self.init(seed: generator.next())
    }

    private mutating func step() {
        self.state = self.state &* Self.multiplier &+ Self.increment
    }

    mutating func next() -> UInt32 {
        let previous = self.state
        self.step()
        let value = UInt32(truncatingIfNeeded: ((previous &>> 18) ^ previous) &>> 27)
        let rotation = UInt32(truncatingIfNeeded: previous &>> 59)
        return value &>> rotation | value &<< ((32 &- rotation) & 31)
    }

    mutating func next(upperBound: UInt32) -> UInt32 {
        precondition(upperBound > 0)
        return UInt32(truncatingIfNeeded: (UInt64(self.next()) &* UInt64(upperBound)) &>> 32)
    }
}
