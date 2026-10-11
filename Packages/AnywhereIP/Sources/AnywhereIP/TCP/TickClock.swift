//
//  TickClock.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/25/26.
//

import Foundation

struct TickClock: Sendable {
    static let interval: Duration = .milliseconds(200)

    private let origin: UInt64 = 0
    private let timebase: mach_timebase_info_data_t
    private let unitsPerTick: UInt64

    init() {
        var timebase = mach_timebase_info_data_t()
        mach_timebase_info(&timebase)
        self.timebase = timebase
        unitsPerTick = 200_000_000 * UInt64(timebase.denom) / UInt64(timebase.numer)
    }

    var now: UInt32 { UInt32(truncatingIfNeeded: (mach_continuous_time() &- origin) / unitsPerTick) }

    func instant(of tick: UInt32) -> ContinuousClock.Instant {
        let now = ContinuousClock.now
        let elapsed = mach_continuous_time() &- origin
        let current = elapsed / unitsPerTick
        let target = Int64(current) &+ Int64(Int32(bitPattern: tick &- UInt32(truncatingIfNeeded: current)))
        let remaining = target &* Int64(unitsPerTick) &- Int64(elapsed)
        return now.advanced(by: .nanoseconds(remaining &* Int64(timebase.numer) / Int64(timebase.denom)))
    }

    static func align(_ start: UInt32, after interval: UInt32) -> UInt32 {
        let deadline = start &+ interval
        guard interval >= Constants.coarseTimerThreshold else { return deadline }
        let granularity = Constants.coarseTimerGranularity
        return (deadline &+ granularity &- 1) / granularity &* granularity
    }
}
