//
//  MonotonicClock.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import Foundation

enum MonotonicClock {
    /// Seconds per `mach_continuous_time()` tick. The timebase is fixed for the
    /// life of the process, so this is computed exactly once.
    private static let secondsPerTick: Double = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return (Double(info.numer) / Double(info.denom)) / 1_000_000_000
    }()

    /// Seconds on a monotonic, sleep-inclusive timeline.
    @inline(__always)
    static var now: TimeInterval {
        Double(mach_continuous_time()) * secondsPerTick
    }
}
