//
//  MITMScriptWatchdog.swift
//  Anywhere
//
//  Created by NodePassProject on 6/3/26.
//

import Foundation

/// Crash-on-runaway watchdog for **synchronous** JavaScript execution spans.
///
/// A user `process(ctx)` runs synchronously on ``MITMScriptTransform/scriptQueue``
/// (the calling connection parks while it runs). JSC synchronous execution is
/// uninterruptible without `JSContextGroupSetExecutionTimeLimit` — WebKit SPI
/// that App Review's scan flags on sight, which ``MITMScriptEngine`` declines to
/// use — so a script that loops or recurses without bound, or backtracks a
/// pathological in-JS regex, pins the scriptQueue thread and wedges **every**
/// connection's scripts queued behind it on that serial queue. Nothing can
/// preempt the runaway; the only recovery is to tear the process down.
///
/// This watchdog samples the in-flight span from an **independent** monitor
/// queue and, once a span has run past ``hardCapSeconds``, crashes the extension
/// via ``fatalError`` so the OS relaunches it clean — the same abandon → crash
/// path ``MITMGateRegex`` takes for a runaway gate match. There is no
/// soft-deadline "give up and continue" stage the gate has: a parked connection
/// needs its script's result to proceed, and the runaway holds the shared
/// ``JSContext`` and engine lock, so the span can neither be interrupted nor
/// stepped over — it is left running (the "abandon") and the crash is the
/// recovery.
///
/// It **complements** ``MITMScriptEngine``'s per-invocation idle watchdog rather
/// than replacing it: that one catches an `async process` whose returned promise
/// never *settles* (a `new Promise(() => {})`, an `await` that never resolves) —
/// but it is itself dispatched onto the scriptQueue, so it can only fire while
/// the queue is *free*. A synchronous runaway never yields the queue, so the
/// idle watchdog would be stuck behind it; THIS watchdog, on a separate queue,
/// is the one that catches that case.
///
/// Because every JS span runs on the one serial scriptQueue, at most one span
/// executes at any instant, so a single `(start, label)` pair tracks "the span
/// in flight". A suspended `await` is **not** in flight — the span that
/// suspended already returned and called ``end()`` — so awaiting a slow
/// ``Anywhere/http`` fetch never trips this.
enum MITMScriptWatchdog {

    /// Hard wall-clock cap on one synchronous JS span. A legitimate
    /// `process(ctx)` span — even heavy crypto / JSON work over the 4 MiB body
    /// cap on JS's single thread — finishes far inside this; only an unbounded
    /// loop / recursion / pathological in-JS regex runs past it, and such a span
    /// never returns, so waiting longer only prolongs the wedge. Sized like
    /// ``MITMGateRegex/hardCapSeconds`` so a healthy extension is never crashed —
    /// only a genuine never-terminating runaway trips it.
    static let hardCapSeconds = 30

    /// How often the monitor samples the in-flight span. A runaway is caught
    /// between ``hardCapSeconds`` and ``hardCapSeconds`` + this; precision is
    /// irrelevant since a runaway never ends, and a coarse interval keeps the
    /// always-on tick cheap.
    private static let checkIntervalSeconds = 5

    /// Independent queue carrying the sampling timer, so the check is never
    /// itself stuck behind the wedged span it exists to catch (the wedge is on
    /// scriptQueue; this is a different queue).
    private static let monitorQueue = DispatchQueue(
        label: "com.anywhere.mitm.script-monitor",
        qos: .utility
    )

    private static let lock = UnfairLock()
    /// Start time of the span currently executing, or nil between spans.
    private static var spanStart: DispatchTime?
    /// A short identifier for the in-flight span (the script source, by
    /// reference), surfaced in the crash report so the offending rule is
    /// identifiable.
    private static var spanLabel = ""

    /// Lazily-started repeating sampler. Triggered on the first ``begin``, so an
    /// extension that never runs a MITM script pays nothing; it then runs for
    /// the process's life (a cheap no-op tick while idle). A Swift `static let`
    /// is initialized exactly once, thread-safely, on first access.
    private static let sampler: DispatchSourceTimer = {
        let timer = DispatchSource.makeTimerSource(queue: monitorQueue)
        timer.schedule(
            deadline: .now() + .seconds(checkIntervalSeconds),
            repeating: .seconds(checkIntervalSeconds)
        )
        timer.setEventHandler { checkInFlightSpan() }
        timer.resume()
        return timer
    }()

    /// Marks a synchronous JS span as started. ``label`` is a cheap identifier
    /// (the script source, passed by reference — Swift's COW means no copy) used
    /// only for the crash message. **Must** be paired with ``end()`` — use
    /// `defer` so a thrown error can't leave a phantom span armed.
    static func begin(_ label: String) {
        _ = sampler   // lazy-start the sampler on first use
        lock.lock()
        spanStart = .now()
        spanLabel = label
        lock.unlock()
    }

    /// Marks the in-flight span finished, so the sampler stops counting it.
    static func end() {
        lock.lock()
        spanStart = nil
        spanLabel = ""
        lock.unlock()
    }

    /// Sampler body: crashes when the in-flight span has run past the hard cap.
    /// A span that ended (or never started) leaves ``spanStart`` nil — a no-op.
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
        // The span has executed `seconds`s without returning to Swift: a user
        // script is looping / recursing without bound and has wedged the MITM
        // script queue, which JSC cannot preempt. Fail fast so the OS relaunches
        // the extension clean; the crash report names the offending script.
        fatalError("[MITM] A JavaScript script span ran \(seconds)s without returning — a user `process(ctx)` is looping or recursing without bound and has wedged the MITM script queue (JSC execution is uninterruptible). Crashing the Network Extension so the system relaunches it clean. Offending script: \(shown)")
    }
}
