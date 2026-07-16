//
//  MITMScriptWatchdog.swift
//  Anywhere
//
//  Created by NodePassProject on 6/3/26.
//

import Foundation
import Synchronization

/// JSC sync execution is uninterruptible, so crashing for a clean OS relaunch is the only recovery.
/// A suspended `await` already called end(), so slow async fetches never trip this.
nonisolated enum MITMScriptWatchdog {

    /// Hard wall-clock cap on one synchronous JS span; any legitimate span finishes far inside this.
    static let hardCapSeconds = 30

    /// Coarse sampling interval; precision is irrelevant since a runaway never ends.
    private static let checkIntervalSeconds = 5

    private struct Span {
        /// `MonotonicClock.now` snapshot (monotonic, sleep-inclusive seconds) when the span began.
        var start: TimeInterval?
        /// Script source string surfaced in the crash report to identify the offending rule.
        var label = ""
    }
    private static let span = Mutex(Span())

    /// Lazily started on the first begin(). Detached + high priority so it is never starved behind the
    /// wedged script queue it exists to catch — a synchronously-wedged JSC span still can't be preempted,
    /// so the `fatalError` recovery in `checkInFlightSpan` remains the only recourse.
    private static let sampler: Task<Void, Never> = {
        Task.detached(priority: .high) {
            while true {
                try? await Task.sleep(for: .seconds(checkIntervalSeconds))
                checkInFlightSpan()
            }
        }
    }()

    /// Marks a synchronous JS span as started; must be paired with end() (use `defer`) or a phantom span stays armed.
    static func begin(_ label: String) {
        _ = sampler
        span.withLock { span in
            span.start = MonotonicClock.now
            span.label = label
        }
    }

    static func end() {
        span.withLock { span in
            span.start = nil
            span.label = ""
        }
    }

    private static func checkInFlightSpan() {
        let (start, label) = span.withLock { ($0.start, $0.label) }
        guard let start else { return }
        let elapsed = MonotonicClock.now - start
        guard elapsed >= Double(hardCapSeconds) else { return }
        let seconds = Int(elapsed)
        let shown = label.count > 200 ? String(label.prefix(200)) + "…" : label
        // JSC cannot preempt the runaway; crash so the OS relaunches the extension clean.
        fatalError("A JavaScript script span ran \(seconds)s without returning — a user `process(ctx)` is looping or recursing without bound and has wedged the MITM script queue (JSC execution is uninterruptible). Crashing the Network Extension so the system relaunches it clean. Offending script: \(shown)")
    }
}
