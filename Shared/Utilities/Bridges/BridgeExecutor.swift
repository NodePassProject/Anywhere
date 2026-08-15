//
//  BridgeExecutor.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Dispatch
import Synchronization

nonisolated final class BridgeExecutor: SerialExecutor, @unchecked Sendable {
    let queue: DispatchQueue
    
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
    
    func checkIsolated() {
        dispatchPrecondition(condition: .onQueue(queue))
    }
    
    // MARK: On-queue interop
    
    var isOnQueue: Bool {
        DispatchQueue.getSpecific(key: onQueueKey) == true
    }
    
    // MARK: - Timers
    
    func makeRepeatingTimer(intervalMs: Int, leewayMs: Int,
                            handler: @escaping @Sendable () -> Void) -> BridgeTimer {
        BridgeTimer(queue: queue, intervalMs: intervalMs, leewayMs: leewayMs, handler: handler)
    }
    
    func makeDeadlineTimer(handler: @escaping @Sendable () -> Void) -> BridgeDeadlineTimer {
        BridgeDeadlineTimer(queue: queue, handler: handler)
    }
}

nonisolated final class BridgeTimer: @unchecked Sendable {

    private enum Phase: PhaseTransitionable {
        case running
        case suspended
        case cancelled

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.running, .suspended),
                 (.suspended, .running):
                return true
            case (_, .cancelled):
                return old != .cancelled
            default:
                return false
            }
        }
    }

    private let timer: DispatchSourceTimer

    private let phase = Mutex<Phase>(.running)

    fileprivate init(
        queue: DispatchQueue,
        intervalMs: Int,
        leewayMs: Int,
        handler: @escaping @Sendable () -> Void
    ) {
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
    
    func suspend() {
        guard phase.withLock({ Phase.transition(&$0, to: .suspended) }) else { return }
        timer.suspend()
    }

    func resume() {
        guard phase.withLock({ Phase.transition(&$0, to: .running) }) else { return }
        timer.resume()
    }

    func cancel() {
        enum Exit {
            case none
            case cancel
            case resumeThenCancel
        }
        let exit: Exit = phase.withLock { phase in
            let wasSuspended = phase == .suspended
            guard Phase.transition(&phase, to: .cancelled) else { return .none }
            return wasSuspended ? .resumeThenCancel : .cancel
        }
        switch exit {
        case .none:
            return
        case .resumeThenCancel:
            timer.resume()
            timer.cancel()
        case .cancel:
            timer.cancel()
        }
    }

    deinit {
        cancel()
    }
}

nonisolated final class BridgeDeadlineTimer: @unchecked Sendable {
    
    private let timer: DispatchSourceTimer
    private let cancelled = OneShotLatch()

    fileprivate init(queue: DispatchQueue, handler: @escaping @Sendable () -> Void) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.setEventHandler(handler: handler)
        self.timer = timer
        timer.schedule(deadline: .distantFuture, leeway: .nanoseconds(0))
        timer.resume()
    }
    
    func schedule(afterNanoseconds nanoseconds: UInt64) {
        guard !cancelled.isClaimed else { return }
        timer.schedule(
            deadline: .now() + .nanoseconds(Int(min(nanoseconds, UInt64(Int.max)))),
            leeway: .nanoseconds(0)
        )
    }

    func parkUntilRearmed() {
        guard !cancelled.isClaimed else { return }
        timer.schedule(deadline: .distantFuture, leeway: .nanoseconds(0))
    }

    func cancel() {
        guard cancelled.claim() else { return }
        timer.cancel()
    }

    deinit {
        cancel()
    }
}
