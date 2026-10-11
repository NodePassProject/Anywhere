//
//  TimerPrecision.swift
//  Anywhere
//
//  Created by NodePassProject on 10/11/26.
//

import Foundation

nonisolated enum TimerPrecision: Sendable, Hashable {
    case exact
    case prompt
    case relaxed
    case lazy

    func tolerance(forRemaining remaining: Duration) -> Duration {
        let remaining = max(remaining, .zero)
        switch self {
        case .exact:
            return .zero
        case .prompt:
            return Self.clamp(remaining / 10, lower: .milliseconds(1), upper: .milliseconds(25))
        case .relaxed:
            return Self.clamp(remaining / 10, lower: .milliseconds(100), upper: .seconds(2))
        case .lazy:
            return max(remaining / 4, .seconds(5))
        }
    }

    var grid: Duration? {
        switch self {
        case .exact, .prompt: nil
        case .relaxed: .seconds(1)
        case .lazy: .seconds(5)
        }
    }

    var isCoarse: Bool {
        switch self {
        case .exact, .prompt: false
        case .relaxed, .lazy: true
        }
    }

    func aligned(_ instant: MonotonicClock.Instant) -> MonotonicClock.Instant {
        guard let grid, grid > .zero else { return instant }
        let step = UInt64(grid.nanosecondsClamped)
        guard step > 0 else { return instant }
        let remainder = instant.nanoseconds % step
        guard remainder != 0 else { return instant }
        let (aligned, overflow) = instant.nanoseconds.addingReportingOverflow(step - remainder)
        return MonotonicClock.Instant(nanoseconds: overflow ? .max : aligned)
    }

    private static func clamp(_ value: Duration, lower: Duration, upper: Duration) -> Duration {
        min(max(value, lower), upper)
    }
}
