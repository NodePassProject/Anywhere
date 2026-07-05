//
//  MITMScriptWatchdog.swift
//  Anywhere
//
//  Created by NodePassProject on 6/3/26.
//

import Foundation
import Synchronization

/// Runs off the watched worker queue so it is never wedged behind the runaway it exists to catch.
enum MITMWatchdogMonitor {
    static let queue = DispatchQueue(label: AWCore.Identifier.mitmMonitorQueue, qos: .utility)
}

/// JSC sync execution is uninterruptible, so crashing for a clean OS relaunch is the only recovery.
/// A suspended `await` already called end(), so slow async fetches never trip this.
enum MITMScriptWatchdog {

    /// Hard wall-clock cap on one synchronous JS span; any legitimate span finishes far inside this.
    static let hardCapSeconds = 30

    /// Coarse sampling interval; precision is irrelevant since a runaway never ends.
    private static let checkIntervalSeconds = 5

    private struct Span {
        var start: DispatchTime?
        /// Script source string surfaced in the crash report to identify the offending rule.
        var label = ""
    }
    private static let span = Mutex(Span())

    /// Lazily started on the first begin().
    private static let sampler: DispatchSourceTimer = {
        let timer = DispatchSource.makeTimerSource(queue: MITMWatchdogMonitor.queue)
        timer.schedule(
            deadline: .now() + .seconds(checkIntervalSeconds),
            repeating: .seconds(checkIntervalSeconds),
            leeway: .seconds(1)
        )
        timer.setEventHandler { checkInFlightSpan() }
        timer.resume()
        return timer
    }()

    /// Marks a synchronous JS span as started; must be paired with end() (use `defer`) or a phantom span stays armed.
    static func begin(_ label: String) {
        _ = sampler
        span.withLock { span in
            span.start = .now()
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
        let elapsedNanos = DispatchTime.now().uptimeNanoseconds &- start.uptimeNanoseconds
        guard elapsedNanos >= UInt64(hardCapSeconds) * 1_000_000_000 else { return }
        let seconds = elapsedNanos / 1_000_000_000
        let shown = label.count > 200 ? String(label.prefix(200)) + "…" : label
        // JSC cannot preempt the runaway; crash so the OS relaunches the extension clean.
        fatalError("A JavaScript script span ran \(seconds)s without returning — a user `process(ctx)` is looping or recursing without bound and has wedged the MITM script queue (JSC execution is uninterruptible). Crashing the Network Extension so the system relaunches it clean. Offending script: \(shown)")
    }
}
