//
//  NGTCP2ConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

nonisolated final class NGTCP2ConcurrencyBridge: @unchecked Sendable {
    let executor: BridgeExecutor

    init() {
        self.executor = BridgeExecutor(label: "com.argsment.Anywhere.NGTCP2ConcurrencyBridge")
    }
    
    private var queue: DispatchQueue { executor.queue }
    
    func enqueue(_ work: @escaping @convention(block) @Sendable () -> Void) {
        queue.async(execute: work)
    }
    
    var isOnQueue: Bool { executor.isOnQueue }
    
    func makeDeadlineTimer(handler: @escaping @Sendable () -> Void) -> BridgeDeadlineTimer {
        executor.makeDeadlineTimer(handler: handler)
    }

    // MARK: - Async hop
    
    private struct QueueHopBody<Body>: @unchecked Sendable { let body: Body }
    
    func run<T>(_ body: @escaping () -> T) async -> T {
        let hop = QueueHopBody(body: body)
        return await withCheckedContinuation { (continuation: CheckedContinuation<T, Never>) in
            queue.async { continuation.resume(returning: hop.body()) }
        }
    }
    
    func runParkedThrowing<Host: Actor>(
        host: Host,
        _ body: @escaping (isolated Host, CheckedContinuation<Void, Error>) -> Void
    ) async throws {
        let hop = QueueHopBody(body: body)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            queue.async { host.assumeIsolated { me in hop.body(me, continuation) } }
        }
    }
}
