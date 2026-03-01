//
//  ActivityTimer.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// Detects inactivity by periodically checking whether ``update()`` has been
/// called since the last check.  If no activity is detected within the
/// configured interval the `onTimeout` callback fires.
///
/// **Design** (mirrors Xray-core `common/signal/timer.go`):
/// - A boolean flag is set by ``update()`` (non-blocking, safe to call often).
/// - A `DispatchSourceTimer` fires every *timeout* seconds and checks the flag.
///   If the flag is still clear → inactivity → callback.
/// - ``setTimeout(_:)`` replaces the interval (used to switch between
///   `ConnectionIdle` and direction-only timeouts).
///
/// All operations must run on the provided serial queue.
class ActivityTimer {
    private var timer: DispatchSourceTimer?
    private var hasActivity = false
    private let queue: DispatchQueue
    private let onTimeout: () -> Void
    private var cancelled = false

    /// Creates and starts the timer.
    ///
    /// - Parameters:
    ///   - queue:     Serial queue for all timer operations.
    ///   - timeout:   Inactivity interval in seconds.
    ///   - onTimeout: Fired once when no ``update()`` call is observed within
    ///                a full interval.  The timer is cancelled before the
    ///                callback is invoked.
    init(queue: DispatchQueue, timeout: TimeInterval, onTimeout: @escaping () -> Void) {
        self.queue = queue
        self.onTimeout = onTimeout
        startTimer(timeout: timeout)
    }

    /// Signals that activity has occurred.
    func update() {
        hasActivity = true
    }

    /// Changes the check interval, restarting the timer.
    ///
    /// Used to switch from `ConnectionIdle` to `DownlinkOnly` / `UplinkOnly`.
    func setTimeout(_ timeout: TimeInterval) {
        guard !cancelled else { return }
        timer?.cancel()
        if timeout <= 0 {
            cancel()
            onTimeout()
            return
        }
        hasActivity = true
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
        newTimer.schedule(deadline: .now() + timeout, repeating: timeout)
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
