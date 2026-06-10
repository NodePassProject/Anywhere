//
//  ActivityTimer.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

/// Fires `onTimeout` when `update()` has not been called within the configured
/// interval. All operations must run on the provided serial queue.
class ActivityTimer {
    private var timer: DispatchSourceTimer?
    private var hasActivity = false
    private let queue: DispatchQueue
    private let onTimeout: () -> Void
    private var cancelled = false

    /// Creates and starts the timer; it is cancelled before `onTimeout` fires.
    init(queue: DispatchQueue, timeout: TimeInterval, onTimeout: @escaping () -> Void) {
        self.queue = queue
        self.onTimeout = onTimeout
        startTimer(timeout: timeout)
    }

    /// Without this, a dropped-but-uncancelled timer is retained by libdispatch
    /// and fires forever; `DispatchSource.cancel()` is thread-safe and idempotent.
    deinit {
        timer?.cancel()
    }

    func update() {
        hasActivity = true
    }

    /// Replaces the check interval, restarting the timer.
    func setTimeout(_ timeout: TimeInterval) {
        guard !cancelled else { return }
        timer?.cancel()
        if timeout <= 0 {
            cancel()
            onTimeout()
            return
        }
        startTimer(timeout: timeout)
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        timer?.cancel()
        timer = nil
    }

    // MARK: - Private

    private func startTimer(timeout: TimeInterval) {
        let newTimer = DispatchSource.makeTimerSource(queue: queue)
        // 10% leeway (≥100 ms) lets libdispatch coalesce this fire with other wakeups.
        let leeway = Swift.max(timeout * 0.1, 0.1)
        newTimer.schedule(
            deadline: .now() + timeout,
            repeating: timeout,
            leeway: .milliseconds(Int(leeway * 1000))
        )
        newTimer.setEventHandler { [weak self] in
            guard let self, !self.cancelled else { return }
            if self.hasActivity {
                self.hasActivity = false
            } else {
                self.cancel()
                self.onTimeout()
            }
        }
        newTimer.resume()
        timer = newTimer
    }
}
