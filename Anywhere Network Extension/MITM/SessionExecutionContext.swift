//
//  SessionExecutionContext.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

nonisolated final class SessionExecutionContext: Sendable {
    let executor: BridgeExecutor

    init(label: String) {
        self.executor = BridgeExecutor(label: label)
    }

    private var queue: DispatchQueue { executor.queue }

    func enqueue(_ work: @escaping @convention(block) @Sendable () -> Void) {
        queue.async(execute: work)
    }
}
