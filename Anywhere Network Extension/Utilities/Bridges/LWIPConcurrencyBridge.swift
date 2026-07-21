//
//  LWIPConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

nonisolated final class LWIPConcurrencyBridge: @unchecked Sendable {
    let executor: BridgeExecutor

    init(label: String) {
        self.executor = BridgeExecutor(label: label)
    }
    
    private var queue: DispatchQueue { executor.queue }
    
    func enqueue(_ work: @escaping @convention(block) @Sendable () -> Void) {
        queue.async(execute: work)
    }

    // MARK: - Async hop
    
    private struct QueueHopBody<Body>: @unchecked Sendable { let body: Body }
    
    func run<T>(_ body: @escaping () -> T) async -> T {
        let hop = QueueHopBody(body: body)
        return await withCheckedContinuation { (continuation: CheckedContinuation<T, Never>) in
            queue.async { continuation.resume(returning: hop.body()) }
        }
    }
    
    func runParked<T>(_ body: @escaping (CheckedContinuation<T, Never>) -> Void) async -> T {
        let hop = QueueHopBody(body: body)
        return await withCheckedContinuation { (continuation: CheckedContinuation<T, Never>) in
            queue.async { hop.body(continuation) }
        }
    }

    // MARK: - Timers
    
    func makeTick(intervalMs: Int, leewayMs: Int,
                  handler: @escaping @Sendable () -> Void) -> BridgeTimer {
        executor.makeRepeatingTimer(intervalMs: intervalMs, leewayMs: leewayMs, handler: handler)
    }
}
