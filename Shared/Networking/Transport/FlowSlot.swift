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
            logger.error("\(context) released twice — one teardown path is running redundantly.")
        }
    }

    deinit {
        guard !released.isClaimed else { return }
        logger.error("\(context) deallocated without release — teardown never ran; a cancel path has regressed.")
    }
}
