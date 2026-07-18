//
//  BridgeExecutor.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Dispatch

// IMPORTANT: Only allowed to use in *ConcurrencyBridge.
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

    // MARK: - Timers

    /// A repeating timer whose handler fires on this executor's ``queue`` — the sanctioned way for
    /// a bridge's C library to drive its own timeout servicing (lwIP `check_timeouts`, ngtcp2
    /// loss/PTO) on the same domain as the rest of its state. The raw `DispatchSourceTimer` and its
    /// suspend-count bookkeeping stay inside the bridge layer, so callers reach for no Dispatch.
    ///
    /// All methods are queue-confined: call them from the executor's queue (the handler already
    /// runs there; callers hop on via the owning bridge). ``suspend``/``resume`` are idempotent so
    /// an idle timer can be parked without tracking the suspend count.
    func makeRepeatingTimer(intervalMs: Int, leewayMs: Int,
                            handler: @escaping @Sendable () -> Void) -> BridgeTimer {
        BridgeTimer(queue: queue, intervalMs: intervalMs, leewayMs: leewayMs, handler: handler)
    }

    /// A re-armable one-shot timer whose `handler` fires on this executor's ``queue`` — for a
    /// C library that dictates its own next deadline (ngtcp2's loss/PTO expiry, re-armed after
    /// each event). Zero leeway, so BBR-style sub-ms pacing isn't coalesced. Queue-confined.
    func makeDeadlineTimer(handler: @escaping @Sendable () -> Void) -> BridgeDeadlineTimer {
        BridgeDeadlineTimer(queue: queue, handler: handler)
    }
}

/// Queue-bound repeating timer, vended by ``BridgeExecutor/makeRepeatingTimer(intervalMs:leewayMs:handler:)``.
/// Bridge infrastructure — houses the `DispatchSourceTimer` so it never appears outside a bridge.
nonisolated final class BridgeTimer: @unchecked Sendable {

    private let timer: DispatchSourceTimer
    /// Mirrors the source's suspend count so ``suspend``/``resume`` stay balanced (an over-resume,
    /// or releasing a suspended source, traps). Queue-confined.
    private var suspended = false
    private var cancelled = false

    fileprivate init(queue: DispatchQueue, intervalMs: Int, leewayMs: Int,
                     handler: @escaping @Sendable () -> Void) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(
            deadline: .now() + .milliseconds(intervalMs),
            repeating: .milliseconds(intervalMs),
            leeway: .milliseconds(leewayMs)
        )
        timer.setEventHandler(handler: handler)
        self.timer = timer
        timer.resume()
    }

    /// Pauses firing; idempotent and a no-op after ``cancel``.
    func suspend() {
        guard !suspended, !cancelled else { return }
        suspended = true
        timer.suspend()
    }

    /// Resumes firing after a ``suspend``; idempotent and a no-op after ``cancel``.
    func resume() {
        guard suspended, !cancelled else { return }
        suspended = false
        timer.resume()
    }

    /// Stops the timer permanently, balancing any outstanding suspend so the source can deallocate.
    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        if suspended {
            suspended = false
            timer.resume()
        }
        timer.cancel()
    }
}

/// Re-armable one-shot timer, vended by ``BridgeExecutor/makeDeadlineTimer(handler:)``. Bridge
/// infrastructure — the `DispatchSourceTimer` and its zero-leeway pacing stay inside the bridge.
/// All methods are queue-confined.
nonisolated final class BridgeDeadlineTimer: @unchecked Sendable {

    private let timer: DispatchSourceTimer
    private var cancelled = false

    fileprivate init(queue: DispatchQueue, handler: @escaping @Sendable () -> Void) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.setEventHandler(handler: handler)
        self.timer = timer
        // Resumed once with no pending deadline; the first `schedule`/`parkUntilRearmed` arms it.
        timer.schedule(deadline: .distantFuture, leeway: .nanoseconds(0))
        timer.resume()
    }

    /// Re-arms to fire `nanoseconds` from now (0 = as soon as possible). Zero leeway.
    func schedule(afterNanoseconds nanoseconds: UInt64) {
        guard !cancelled else { return }
        timer.schedule(deadline: .now() + .nanoseconds(Int(min(nanoseconds, UInt64(Int.max)))),
                       leeway: .nanoseconds(0))
    }

    /// Parks the timer indefinitely (no pending expiry), without cancelling it.
    func parkUntilRearmed() {
        guard !cancelled else { return }
        timer.schedule(deadline: .distantFuture, leeway: .nanoseconds(0))
    }

    /// Stops the timer permanently.
    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        timer.cancel()
    }
}
