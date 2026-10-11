//
//  MonotonicClock.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import Foundation

nonisolated enum MonotonicClock {
    private static let timebase: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    /// Seconds per `mach_continuous_time()` tick; timebase is fixed for the process lifetime.
    private static let secondsPerTick: Double = {
        (Double(timebase.numer) / Double(timebase.denom)) / 1_000_000_000
    }()

    struct Instant: Hashable, Comparable, Sendable {
        var nanoseconds: UInt64

        init(nanoseconds: UInt64) {
            self.nanoseconds = nanoseconds
        }

        init(seconds: TimeInterval) {
            let scaled = seconds * 1_000_000_000
            if scaled <= 0 || scaled.isNaN {
                self.nanoseconds = 0
            } else if scaled >= 9_000_000_000_000_000_000 {
                self.nanoseconds = 9_000_000_000_000_000_000
            } else {
                self.nanoseconds = UInt64(scaled)
            }
        }

        var seconds: TimeInterval { Double(nanoseconds) / 1_000_000_000 }

        static func < (lhs: Instant, rhs: Instant) -> Bool { lhs.nanoseconds < rhs.nanoseconds }

        func advanced(by duration: Duration) -> Instant {
            let delta = duration.nanosecondsClamped
            if delta >= 0 {
                let (sum, overflow) = nanoseconds.addingReportingOverflow(UInt64(delta))
                return Instant(nanoseconds: overflow ? .max : sum)
            }
            let magnitude = delta.magnitude
            return Instant(nanoseconds: nanoseconds > magnitude ? nanoseconds - magnitude : 0)
        }

        func duration(to other: Instant) -> Duration {
            if other.nanoseconds >= nanoseconds {
                return .nanoseconds(Int64(clamping: other.nanoseconds - nanoseconds))
            }
            return .nanoseconds(-Int64(clamping: nanoseconds - other.nanoseconds))
        }

        static func - (lhs: Instant, rhs: Instant) -> Duration { rhs.duration(to: lhs) }
    }

    @inline(__always)
    static var nanoseconds: UInt64 {
        let ticks = mach_continuous_time()
        let numer = UInt64(timebase.numer)
        let denom = UInt64(timebase.denom)
        if numer == denom { return ticks }
        return (ticks / denom) * numer + ((ticks % denom) * numer) / denom
    }

    @inline(__always)
    static var instant: Instant { Instant(nanoseconds: nanoseconds) }

    /// Seconds on a monotonic, sleep-inclusive timeline.
    @inline(__always)
    static var now: TimeInterval {
        Double(mach_continuous_time()) * secondsPerTick
    }

    static func continuousInstant(for instant: Instant) -> ContinuousClock.Instant {
        let reference = ContinuousClock.now
        let current = Self.instant
        return reference.advanced(by: current.duration(to: instant))
    }
}

extension Duration {
    nonisolated var nanosecondsClamped: Int64 {
        let (seconds, attoseconds) = components
        let (scaled, overflow) = seconds.multipliedReportingOverflow(by: 1_000_000_000)
        if overflow { return seconds < 0 ? .min : .max }
        let (sum, sumOverflow) = scaled.addingReportingOverflow(attoseconds / 1_000_000_000)
        if sumOverflow { return seconds < 0 ? .min : .max }
        return sum
    }
}
