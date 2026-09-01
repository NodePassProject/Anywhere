//
//  PressureEventThrottle.swift
//  Anywhere
//
//  Created by NodePassProject on 9/1/26.
//

import Foundation

nonisolated struct PressureEventThrottle {
    private let label: String
    private let cap: Int
    private let interval: TimeInterval
    private var evicted = 0
    private var dropped = 0
    private var lastEmit: TimeInterval = -.infinity

    init(label: String, cap: Int, interval: TimeInterval = 5) {
        self.label = label
        self.cap = cap
        self.interval = interval
    }

    mutating func noteEvicted(now: TimeInterval, logger: AnywhereLogger) {
        evicted += 1
        emitIfDue(now: now, logger: logger)
    }

    mutating func noteDropped(now: TimeInterval, logger: AnywhereLogger) {
        dropped += 1
        emitIfDue(now: now, logger: logger)
    }

    private mutating func emitIfDue(now: TimeInterval, logger: AnywhereLogger) {
        guard now - lastEmit >= interval else { return }
        logger.warning("[\(label)] Table at cap (\(cap)): evicted \(evicted), dropped \(dropped) newcomers since last report")
        evicted = 0
        dropped = 0
        lastEmit = now
    }
}
