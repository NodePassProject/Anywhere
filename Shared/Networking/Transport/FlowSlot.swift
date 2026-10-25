//
//  FlowSlot.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "FlowSlot")

nonisolated final class FlowSlot: Sendable {

    private let context: String
    private let released = OneShotLatch()

    init(context: String) {
        self.context = context
    }

    func release() {
        if !released.claim() {
            logger.error("\(context): Flow slot released twice")
        }
    }

    deinit {
        guard !released.isClaimed else { return }
        logger.error("\(context): Flow slot leaked")
    }
}
