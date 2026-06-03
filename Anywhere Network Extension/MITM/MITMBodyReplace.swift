//
//  MITMBodyReplace.swift
//  Anywhere
//
//  Created by NodePassProject on 5/31/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

/// Native regex find-and-replace over a text message body — the engine
/// behind ``MITMOperation/bodyReplace`` (import operation id `4`): a compiled
/// ``Regex`` matched anywhere in the body, with each match swapped for the
/// **literal** replacement string (no `$1` capture expansion — the
/// substitution goes through `String.replacing(_:with:)`).
///
/// **Bytes in, bytes out.** ``applyAll`` decodes the body as UTF-8 once,
/// applies every compiled edit in rule order against the running string, and
/// re-encodes once. The contract is **total / fail-closed**, matching
/// ``MITMJSONPatch``: a body that isn't valid UTF-8 yields the body
/// **unchanged**, and a search that matches nothing is simply a no-op — a
/// rewrite rule routinely fires on a response whose bytes it doesn't fully
/// control, and corrupting the wire there would be worse than doing nothing.
enum MITMBodyReplace {

    /// A ``MITMOperation/bodyReplace`` with its ``search`` pre-compiled to a
    /// ``Regex`` at rule-load time, so the per-message hot path neither
    /// re-parses nor re-compiles the pattern. ``replacement`` is the literal
    /// string each match is swapped for.
    struct CompiledOp {
        let search: Regex<AnyRegexOutput>
        let replacement: String
    }

    /// Compiles a model operation, pre-parsing its ``search`` regex. Returns
    /// nil only when the pattern won't compile (the rule is then dropped with
    /// a logged diagnostic by the caller); the replacement is never validated
    /// — it carries no wire-safety constraint the way a header value or
    /// request target does, since the result is a body whose length is
    /// recomputed downstream.
    static func compile(search: String, replacement: String) -> CompiledOp? {
        guard let regex = try? Regex(search) else { return nil }
        return CompiledOp(search: regex, replacement: replacement)
    }

    /// Applies every compiled edit, in order, to ``body``. Decodes UTF-8
    /// once, replaces every match of each op against the running string (so
    /// successive edits compose), and re-encodes UTF-8. Returns the body
    /// **unchanged** when the list is empty, the body isn't valid UTF-8, or a
    /// substitution exceeds its time budget (see ``boundedReplace``).
    static func applyAll(_ ops: [CompiledOp], to body: Data) -> Data {
        guard !ops.isEmpty else { return body }
        guard let text = String(data: body, encoding: .utf8) else { return body }
        var current = text
        for op in ops {
            guard let replaced = boundedReplace(current, op: op) else {
                // The substitution blew its time budget (catastrophic
                // backtracking) or a prior runaway is still draining. Fail
                // closed to the whole-body-unchanged contract rather than emit a
                // half-applied chain or block the shared script queue.
                return body
            }
            current = replaced
        }
        return Data(current.utf8)
    }

    /// Wall-clock budget for one regex substitution. Swift's ``Regex`` exposes
    /// no execution time limit, so a catastrophic-backtracking pattern — rules
    /// are user- or import-authored — against a crafted body — the body is
    /// intercepted traffic, hence attacker-controlled — can run effectively
    /// forever. ``boundedReplace`` runs the substitution on ``watchdogQueue``
    /// and abandons it after this budget so a runaway can't wedge
    /// ``MITMScriptTransform/scriptQueue``, the single serial queue every
    /// connection's rules share. Generous versus any legitimate replace over
    /// the 4 MiB body cap, which finishes in well under a second.
    private static let substitutionTimeLimit: DispatchTimeInterval = .seconds(2)

    /// Hard wall-clock cap on a substitution that already blew its soft
    /// ``substitutionTimeLimit``. A ``Regex`` match is uninterruptible, so one
    /// still running this long after the soft deadline is a core pinned by
    /// catastrophic backtracking that will never free on its own — and because
    /// ``substitutionInFlight`` is process-wide, it leaves bodyReplace
    /// fail-closed (every body forwarded unchanged) for *every* connection
    /// until it drains, which a non-terminating backtrack never does. The only
    /// way to reclaim the thread is to tear the process down, so a substitution
    /// past this cap ``fatalError``s and the OS relaunches the extension clean —
    /// the same abandon → hard-cap → crash backstop ``MITMGateRegex`` and
    /// ``MITMScriptWatchdog`` take for their own uninterruptible runaways, and
    /// sized to match them so a healthy substitution is never crashed.
    static let hardCapSeconds = 30

    /// Dedicated queue carrying the (possibly runaway) substitution off the
    /// shared script queue. A regex match can't be interrupted mid-flight, so a
    /// runaway keeps executing here after ``boundedReplace`` gives up;
    /// ``substitutionInFlight`` then short-circuits new work until it drains,
    /// bounding a runaway to one busy core with no backlog of pinned 4 MiB
    /// bodies. A runaway that never drains is reclaimed by the
    /// ``hardCapSeconds`` crash backstop (see ``scheduleHardCapCheck``).
    private static let watchdogQueue = DispatchQueue(
        label: "com.anywhere.mitm.body-replace.watchdog",
        qos: .userInitiated
    )

    /// Low-priority queue carrying the hard-cap crash check, separate from
    /// ``watchdogQueue`` so the check can never be stuck behind the very
    /// runaway it exists to catch (the runaway pins ``watchdogQueue``).
    private static let monitorQueue = DispatchQueue(
        label: "com.anywhere.mitm.body-replace.monitor",
        qos: .utility
    )
    private static let inFlightLock = NSLock()
    private static var substitutionInFlight = false

    /// Runs one substitution under ``substitutionTimeLimit`` on
    /// ``watchdogQueue``, returning the result — or nil when the budget is
    /// exceeded or a prior runaway is still in flight, so the caller leaves the
    /// body unchanged. ``applyAll`` is only ever entered from the serial
    /// ``scriptQueue``, so the in-flight flag is clear on entry under normal
    /// (fast) operation; it stays set only while a runaway from a *previous*
    /// call is still burning down here, during which every substitution
    /// short-circuits fail-closed.
    private static func boundedReplace(_ text: String, op: CompiledOp) -> String? {
        inFlightLock.lock()
        if substitutionInFlight {
            inFlightLock.unlock()
            return nil
        }
        substitutionInFlight = true
        inFlightLock.unlock()

        let box = ResultBox()
        let done = DispatchSemaphore(value: 0)
        watchdogQueue.async {
            box.value = text.replacing(op.search, with: op.replacement)
            inFlightLock.lock()
            substitutionInFlight = false
            inFlightLock.unlock()
            done.signal()
        }
        // The semaphore establishes happens-before between the write above and
        // the read below, so the otherwise-unsynchronized ``box`` is safe.
        guard done.wait(timeout: .now() + substitutionTimeLimit) == .success else {
            logger.warning("[MITM] bodyReplace: regex substitution exceeded its time budget over a \(text.utf8.count) B body; leaving the body unchanged (possible catastrophic backtracking in the pattern)")
            // The substitution blew its soft budget and is now abandoned — still
            // spinning on its (uninterruptible) ``watchdogQueue`` thread, with
            // ``substitutionInFlight`` stuck set, fail-closing bodyReplace
            // process-wide until it drains. Arm the hard-cap crash so a
            // non-terminating backtrack (which never drains) is reclaimed by an
            // OS relaunch instead of wedging the feature for the process's life.
            Self.scheduleHardCapCheck(done, byteCount: text.utf8.count)
            return nil
        }
        return box.value
    }

    /// Arms a one-shot crash check for a substitution that blew its soft
    /// budget. ``hardCapSeconds`` out it polls the substitution's completion
    /// semaphore; if the worker still hasn't signaled, its ``Regex`` match is a
    /// non-terminating runaway pinning ``watchdogQueue`` — and, via the
    /// process-wide ``substitutionInFlight`` flag, keeping bodyReplace
    /// fail-closed for every connection — so the extension is crashed to
    /// reclaim it. Reuses the substitution's own semaphore as the liveness
    /// signal (the worker signals it on completion whether or not the caller
    /// already gave up), so a substitution that finished within the cap makes
    /// the poll succeed and the check a no-op. Only armed on the rare timeout
    /// path, so the always-completing fast path schedules nothing.
    private static func scheduleHardCapCheck(_ done: DispatchSemaphore, byteCount: Int) {
        monitorQueue.asyncAfter(deadline: .now() + .seconds(hardCapSeconds)) {
            // `.now()` poll: success ⇒ the worker signaled within the cap ⇒
            // nothing pinned, no-op. Failure ⇒ still running after the full hard
            // cap ⇒ permanently stuck, crash to recover.
            guard done.wait(timeout: .now()) != .success else { return }
            fatalError("[MITM] bodyReplace regex substitution did not return \(hardCapSeconds)s after blowing its soft budget over a \(byteCount) B body — a worker thread is permanently pinned by catastrophic backtracking and can't be reclaimed, leaving bodyReplace disabled process-wide. Crashing the Network Extension so the system relaunches it clean.")
        }
    }

    /// One-shot carrier for the substitution result across the queue hop.
    /// Synchronized by the ``DispatchSemaphore`` in ``boundedReplace`` (written
    /// before ``signal``, read only after ``wait`` succeeds), hence the
    /// unchecked ``Sendable`` conformance.
    private final class ResultBox: @unchecked Sendable {
        var value: String?
    }
}
