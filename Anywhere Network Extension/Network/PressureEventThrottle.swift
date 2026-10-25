//
//  PressureEventThrottle.swift
//  Anywhere
//
//  Created by NodePassProject on 9/1/26.
//

import Foundation

nonisolated struct PressureEventThrottle {
    private let message: String
    private let interval: TimeInterval
    private var lastEmit: TimeInterval = -.infinity

    init(message: String, interval: TimeInterval = 5) {
        self.message = message
        self.interval = interval
    }

    mutating func noteDropped(now: TimeInterval, logger: AnywhereLogger) {
        guard now - lastEmit >= interval else { return }
        logger.error(message)
        lastEmit = now
    }
}
