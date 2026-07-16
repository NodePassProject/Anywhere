//
//  BridgeExecutor.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Dispatch

// IMPORTANT: BridgeExecutor is allowed to use in *ConcurrencyBridge only
nonisolated final class BridgeExecutor: SerialExecutor, @unchecked Sendable {

    /// The one queue this executor serializes onto. Exposed so the bridges' C timers and
    /// queue-confined C callbacks can join the same isolation domain as the actor.
    let queue: DispatchQueue

    /// Marks ``queue`` so ``isOnQueue`` can distinguish "already isolated here" from a
    /// cross-domain call without hopping. Per-instance: two bridges never share a domain.
    private let onQueueKey = DispatchSpecificKey<Bool>()

    init(label: String, qos: DispatchQoS = .userInitiated) {
        self.queue = DispatchQueue(label: label, qos: qos, autoreleaseFrequency: .workItem)
        self.queue.setSpecific(key: onQueueKey, value: true)
    }

    // MARK: SerialExecutor

    func enqueue(_ job: consuming ExecutorJob) {
        let job = UnownedJob(job)
        let executor = asUnownedSerialExecutor()
        queue.async {
            job.runSynchronously(on: executor)
        }
    }

    func asUnownedSerialExecutor() -> UnownedSerialExecutor {
        UnownedSerialExecutor(ordinary: self)
    }

    /// Backs `assumeIsolated` / `preconditionIsolated()`: a C callback (or any code) that
    /// claims to already be isolated here is verified against the real queue in debug.
    func checkIsolated() {
        dispatchPrecondition(condition: .onQueue(queue))
    }

    // MARK: On-queue interop

    /// True when the caller is already running on ``queue`` — lets a bridge take the
    /// synchronous `assumeIsolated` path from a C callback instead of scheduling a hop.
    var isOnQueue: Bool {
        DispatchQueue.getSpecific(key: onQueueKey) == true
    }

    /// Runs `body` synchronously on ``queue``, for the rare teardown that must complete
    /// before returning (e.g. lwIP `stop()` on the provider's thread). Never call from a
    /// context already on ``queue`` — that would deadlock; use `assumeIsolated` there.
    func runSyncOffQueue<T>(_ body: () -> T) -> T {
        precondition(!isOnQueue, "runSyncOffQueue called while already on the bridge queue")
        return queue.sync(execute: body)
    }
}
