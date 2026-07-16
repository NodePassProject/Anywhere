//
//  TunnelScheduler.swift
//  Anywhere
//
//  Created by NodePassProject on 6/28/26.
//

import Foundation
import Synchronization

nonisolated final class TunnelScheduler {
    private final class ScheduledTask {
        let label: String
        let queue: DispatchQueue
        let interval: TimeInterval
        let handler: () -> Void
        /// The repeating-sleep loop; fires ``fire()`` on ``queue`` each interval.
        var task: Task<Void, Never>?
        var lastRun: TimeInterval

        init(label: String, queue: DispatchQueue, interval: TimeInterval,
             handler: @escaping () -> Void) {
            self.label = label
            self.queue = queue
            self.interval = interval
            self.handler = handler
            self.lastRun = MonotonicClock.now
        }

        deinit {
            task?.cancel()
        }

        /// Must run on ``queue``.
        func fire() {
            handler()
            lastRun = MonotonicClock.now
        }

        /// Wake catch-up: fire once if a whole interval has elapsed on the monotonic
        /// clock since the last run. Must run on ``queue``.
        func fireIfOverdue() {
            if MonotonicClock.now - lastRun >= interval {
                fire()
            }
        }
    }

    private let tasks = Mutex<[ScheduledTask]>([])

    func schedule(
        label: String, on queue: DispatchQueue,
        every interval: TimeInterval,
        leeway: TimeInterval,
        _ handler: @escaping () -> Void
    ) {
        let task = ScheduledTask(label: label, queue: queue, interval: interval, handler: handler)
        // Sleep off-queue, then hop onto `queue` so `fire()` keeps the on-queue contract.
        task.task = Task { [weak task] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(interval))
                guard !Task.isCancelled, let task else { return }
                task.queue.async { task.fire() }
            }
        }
        tasks.withLock { $0.append(task) }
    }

    /// Catch-up pass for tasks that fell due while the device was frozen.
    func reconcile() {
        // Snapshot under the lock, then act outside it.
        let snapshot = tasks.withLock { $0 }
        for task in snapshot {
            task.queue.async { task.fireIfOverdue() }
        }
    }

    func cancelAll() {
        let removed: [ScheduledTask] = tasks.withLock { tasks in
            let current = tasks
            tasks = []
            return current
        }
        for task in removed {
            task.task?.cancel()
        }
    }
}
