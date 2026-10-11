//
//  Deadline.swift
//  Anywhere
//
//  Created by NodePassProject on 10/11/26.
//

import Foundation

nonisolated struct Deadline: Sendable, Hashable {
    var at: MonotonicClock.Instant
    var precision: TimerPrecision

    init(at: MonotonicClock.Instant, precision: TimerPrecision) {
        self.at = at
        self.precision = precision
    }

    init(in duration: Duration, precision: TimerPrecision) {
        self.init(at: MonotonicClock.instant.advanced(by: duration), precision: precision)
    }

    init(atSeconds seconds: TimeInterval, precision: TimerPrecision) {
        self.init(at: MonotonicClock.Instant(seconds: seconds), precision: precision)
    }

    var scheduledAt: MonotonicClock.Instant { precision.aligned(at) }

    func tolerance(now: MonotonicClock.Instant = MonotonicClock.instant) -> Duration {
        precision.tolerance(forRemaining: now.duration(to: scheduledAt))
    }

    func isDue(at now: MonotonicClock.Instant = MonotonicClock.instant) -> Bool {
        scheduledAt <= now
    }
}

extension Task where Success == Never, Failure == Never {
    nonisolated static func sleep(for duration: Duration, precision: TimerPrecision) async throws {
        try await Task.sleep(
            for: duration,
            tolerance: precision.tolerance(forRemaining: duration),
            clock: .continuous
        )
    }

    nonisolated static func sleep(seconds: TimeInterval, precision: TimerPrecision) async throws {
        try await sleep(for: .seconds(max(0, seconds)), precision: precision)
    }

    nonisolated static func sleep(until deadline: Deadline) async throws {
        let now = MonotonicClock.instant
        try await Task.sleep(
            until: MonotonicClock.continuousInstant(for: deadline.scheduledAt),
            tolerance: deadline.tolerance(now: now),
            clock: .continuous
        )
    }
}
