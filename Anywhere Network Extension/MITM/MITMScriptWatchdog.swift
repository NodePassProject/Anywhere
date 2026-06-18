//
//  MITMScriptWatchdog.swift
//  Anywhere
//
//  Created by NodePassProject on 6/3/26.
//

import Foundation

/// Shared low-priority queue for every MITM hard-cap supervisor; runs off the
/// watched worker queue so it is never wedged behind the runaway it exists to catch.
enum MITMWatchdogMonitor {
    static let queue = DispatchQueue(label: AWCore.Identifier.mitmMonitorQueue, qos: .utility)
}

/// Crash-on-runaway watchdog for synchronous JS spans. JSC sync execution is uninterruptible,
/// so crashing the extension for a clean OS relaunch is the only recovery. Samples from the
/// monitor queue; a suspended `await` already called end(), so slow async fetches never trip this.
enum MITMScriptWatchdog {

    /// Hard wall-clock cap on one synchronous JS span; any legitimate span finishes far inside this.
    static let hardCapSeconds = 30

    /// Coarse sampling interval; precision is irrelevant since a runaway never ends.
    private static let checkIntervalSeconds = 5

    private static let lock = UnfairLock()
    private static var spanStart: DispatchTime?
    /// Script source string surfaced in the crash report to identify the offending rule.
    private static var spanLabel = ""

    /// Repeating sampler, lazily started on the first begin().
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
        lock.lock()
        spanStart = .now()
        spanLabel = label
        lock.unlock()
    }

    static func end() {
        lock.lock()
        spanStart = nil
        spanLabel = ""
        lock.unlock()
    }

    private static func checkInFlightSpan() {
        lock.lock()
        let start = spanStart
        let label = spanLabel
        lock.unlock()
        guard let start else { return }
        let elapsedNanos = DispatchTime.now().uptimeNanoseconds &- start.uptimeNanoseconds
        guard elapsedNanos >= UInt64(hardCapSeconds) * 1_000_000_000 else { return }
        let seconds = elapsedNanos / 1_000_000_000
        let shown = label.count > 200 ? String(label.prefix(200)) + "…" : label
        // JSC cannot preempt the runaway; crash so the OS relaunches the extension clean.
        fatalError("A JavaScript script span ran \(seconds)s without returning — a user `process(ctx)` is looping or recursing without bound and has wedged the MITM script queue (JSC execution is uninterruptible). Crashing the Network Extension so the system relaunches it clean. Offending script: \(shown)")
    }
}
