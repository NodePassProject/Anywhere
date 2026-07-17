//
//  TunnelScheduler.swift
//  Anywhere
//
//  Created by NodePassProject on 6/28/26.
//

import Foundation
import Synchronization

/// Drives recurring stack-lifetime work (e.g. UDP idle cleanup) as async handlers, and reconciles
/// them on device wake so a task that fell due while the clock was frozen fires promptly instead of
/// drifting. Fully async-native — no `DispatchQueue`; each task is its own sleep loop, and the
/// handler runs on whatever isolation it hops to (the UDP cleanup handler hops onto ``UDPPlane``).
nonisolated final class TunnelScheduler: Sendable {

    private final class ScheduledTask: Sendable {
        let label: String
        let interval: TimeInterval
        let handler: @Sendable () async -> Void
        /// Set once, right after `schedule`; only read by teardown.
        let task = Mutex<Task<Void, Never>?>(nil)
        /// Monotonic instant of the last completed run; read by wake catch-up.
        let lastRun: Mutex<TimeInterval>

        init(label: String, interval: TimeInterval, handler: @escaping @Sendable () async -> Void) {
            self.label = label
            self.interval = interval
            self.handler = handler
            self.lastRun = Mutex(MonotonicClock.now)
        }

        func fire() async {
            await handler()
            lastRun.withLock { $0 = MonotonicClock.now }
        }

        /// Wake catch-up: fire once if a whole interval has elapsed on the monotonic clock since the
        /// last run. Firing twice near a wake is harmless — the handlers are idempotent reaps.
        func fireIfOverdue() async {
            let overdue = lastRun.withLock { MonotonicClock.now - $0 >= interval }
            if overdue { await fire() }
        }
    }

    private let tasks = Mutex<[ScheduledTask]>([])

    func schedule(
        label: String,
        every interval: TimeInterval,
        _ handler: @escaping @Sendable () async -> Void
    ) {
        let scheduled = ScheduledTask(label: label, interval: interval, handler: handler)
        let loop = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(interval))
                guard !Task.isCancelled else { return }
                await scheduled.fire()
            }
        }
        scheduled.task.withLock { $0 = loop }
        tasks.withLock { $0.append(scheduled) }
    }

    /// Catch-up pass for tasks that fell due while the device was frozen.
    func reconcile() {
        let snapshot = tasks.withLock { $0 }
        for scheduled in snapshot {
            Task { await scheduled.fireIfOverdue() }
        }
    }

    func cancelAll() {
        let removed: [ScheduledTask] = tasks.withLock { tasks in
            let current = tasks
            tasks = []
            return current
        }
        for scheduled in removed {
            scheduled.task.withLock { $0 }?.cancel()
        }
    }
}
