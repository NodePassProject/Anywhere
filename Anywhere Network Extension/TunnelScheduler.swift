//
//  TunnelScheduler.swift
//  Anywhere
//
//  Created by NodePassProject on 6/28/26.
//

import Foundation

final class TunnelScheduler {
    private final class ScheduledTask {
        let label: String
        let queue: DispatchQueue
        let interval: TimeInterval
        let handler: () -> Void
        let timer: DispatchSourceTimer
        var lastRun: TimeInterval

        init(label: String, queue: DispatchQueue, interval: TimeInterval,
             timer: DispatchSourceTimer, handler: @escaping () -> Void) {
            self.label = label
            self.queue = queue
            self.interval = interval
            self.timer = timer
            self.handler = handler
            self.lastRun = MonotonicClock.now
        }
        
        deinit {
            timer.cancel()
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
    
    private let lock = UnfairLock()
    private var tasks: [ScheduledTask] = []
    
    func schedule(
        label: String, on queue: DispatchQueue,
        every interval: TimeInterval,
        leeway: TimeInterval,
        _ handler: @escaping () -> Void
    ) {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(
            deadline: .now() + interval,
            repeating: interval,
            leeway: .milliseconds(Int(leeway * 1000))
        )
        let task = ScheduledTask(label: label, queue: queue, interval: interval,
                                 timer: timer, handler: handler)
        timer.setEventHandler { [weak task] in task?.fire() }
        lock.withLock { tasks.append(task) }
        timer.resume()
    }
    
    /// Catch-up pass for tasks that fell due while the device was frozen.
    func reconcile() {
        let snapshot = lock.withLock { tasks }
        for task in snapshot {
            task.queue.async { task.fireIfOverdue() }
        }
    }
    
    func cancelAll() {
        let removed: [ScheduledTask] = lock.withLock {
            let current = tasks
            tasks = []
            return current
        }
        for task in removed {
            task.timer.cancel()
        }
    }
}
