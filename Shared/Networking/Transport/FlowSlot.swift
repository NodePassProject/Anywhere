//
//  FlowSlot.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "FlowSlot")

nonisolated final class FlowSlot: Sendable {
    
    private let context: String
    private let released = Atomic<Bool>(false)

    init(context: String) {
        self.context = context
    }
    
    func release() {
        released.store(true, ordering: .relaxed)
    }

    deinit {
        guard !released.load(ordering: .relaxed) else { return }
        logger.error("\(context) deallocated without release — teardown never ran; a cancel path has regressed.")
    }
}
