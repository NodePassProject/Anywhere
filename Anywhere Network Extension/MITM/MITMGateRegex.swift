//
//  MITMGateRegex.swift
//  Anywhere
//
//  Created by NodePassProject on 6/3/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

/// ReDoS-resistant wrapper around a rule's URL-gate ``NSRegularExpression``.
///
/// The gate pattern comes from an imported / subscribed (untrusted) rule set,
/// and it is matched against the request URL — which a remote site can
/// influence (a cross-origin request to a rule-covered host with a crafted
/// path). ICU's backtracking matcher exposes no step or time limit, so a
/// catastrophic-backtracking pattern would otherwise run effectively forever
/// **synchronously on the tunnel's serial lwIP queue**, freezing every flow in
/// the tunnel (a ReDoS that escalates one bad rule into a whole-tunnel DoS).
/// Even an *accidentally* vulnerable pattern in a benign rule set is enough,
/// since the triggering URL is attacker-influenced.
///
/// This wrapper bounds every match so a runaway can never wedge the calling
/// queue:
///
///   1. **Memoization.** A per-pattern cache of normalized-URL → verdict, so a
///      repeated URL never re-runs the matcher. The steady-state hot path is a
///      dictionary lookup — no regex, no dispatch — which also means a hostile
///      peer replaying one crafted URL pays the match cost at most once.
///   2. **Off-queue, deadline-bounded execution.** A cache miss runs the match
///      on a shared *concurrent* worker queue while the caller waits on a
///      semaphore for at most ``matchDeadlineMillis``. A normal gate match
///      signals in microseconds (no perceptible block); a runaway is abandoned
///      at the deadline and the caller gets a fail-closed `false`, so the lwIP
///      queue keeps moving. The abandoned match keeps draining on its own
///      worker thread (an ``NSRegularExpression`` match can't be interrupted) —
///      the *concurrent* queue keeps it off the next match's path so one runaway
///      pins at most one core, never the tunnel.
///   3. **Strike-based quarantine.** After ``strikeLimit`` timeouts the pattern
///      is declawed: every later evaluation returns fail-closed *without*
///      running the matcher, so a hostile peer can't keep spawning runaways and
///      the per-pattern core-pinning is bounded to a handful of threads for the
///      process's life. A legitimate URL-gate match completes in microseconds,
///      so a timeout is a strong signal the pattern is pathological. Quarantine
///      is logged loudly and lifts only when the rule set is reloaded (a reload
///      builds fresh gate objects), giving the author a chance to fix it.
///
/// **Hard-cap backstop.** An abandoned worker keeps spinning until its match
/// returns, which a truly non-terminating pattern never does — quarantine
/// bounds *how many* such threads can exist but not *how long* each lives. So a
/// match still running ``hardCapSeconds`` after it blew the soft deadline is
/// taken as a permanently-pinned core and the extension is crashed via
/// ``fatalError``; the OS relaunches it with a clean slate (the only way to
/// reclaim an uninterruptible thread), and the crash report names the pattern.
///
/// **Fail-closed throughout.** A timed-out or quarantined gate reports "no
/// match", so the affected rule simply doesn't apply (traffic passes
/// unmodified) rather than the tunnel stalling — the same safety posture the
/// length cap in ``CompiledMITMRule/matchesURL`` already takes.
///
/// Thread-safety: ``matches(_:)`` is invoked from both the lwIP queue
/// (head-time rule preflights) and ``MITMScriptTransform/scriptQueue`` (native
/// body-edit matching), and the worker queue writes results back. All mutable
/// state is guarded by ``lock``; the class is therefore safe to share across
/// every connection that matched the rule set, and is ``@unchecked Sendable``.
final class MITMGateRegex: @unchecked Sendable {

    /// The compiled gate. ``NSRegularExpression`` is immutable and documented
    /// thread-safe for concurrent matching, so the worker queue can match on it
    /// while another queue reads ``cache``.
    private let regex: NSRegularExpression
    /// The source pattern, retained only for the quarantine / strike log lines.
    private let pattern: String

    /// Shared concurrent executor for bounded matching. Concurrent is load-
    /// bearing: an abandoned runaway holds one worker thread until it finishes,
    /// and matches dispatched from the lwIP queue and the script queue must not
    /// serialize behind it. CPU-bound matches keep GCD from over-committing
    /// threads, so runaways pin at most ~core-count cores even before
    /// quarantine bounds their number.
    private static let matchQueue = DispatchQueue(
        label: "com.anywhere.mitm.gate-match",
        qos: .userInitiated,
        attributes: .concurrent
    )

    /// Low-priority queue that fires the per-abandoned-match hard-cap check
    /// (see ``scheduleHardCapCheck``). Separate from ``matchQueue`` so the
    /// check can never itself be stuck behind the runaway it exists to catch.
    private static let monitorQueue = DispatchQueue(
        label: "com.anywhere.mitm.gate-monitor",
        qos: .utility
    )

    /// Wall-clock budget for one match. A real URL-gate match is microseconds,
    /// so this sits orders of magnitude above the legitimate cost: a device
    /// hiccup (GC pause, CPU contention) won't false-trip it, while a runaway is
    /// still bounded to a brief, one-off blip on the calling queue.
    static let matchDeadlineMillis = 250

    /// Hard wall-clock cap on an *abandoned* match. A match that blows the soft
    /// ``matchDeadlineMillis`` keeps spinning on its worker thread — an
    /// ``NSRegularExpression`` match is uninterruptible — and catastrophic
    /// backtracking over input this small either finishes in microseconds or
    /// not within any practical time; there is no middle ground at this scale.
    /// So a worker still running this long after the soft deadline is a core
    /// pinned forever that will never free on its own. The only way to reclaim
    /// an uninterruptible thread is to tear the process down, so we
    /// ``fatalError``: the OS relaunches the extension with a clean slate and
    /// the crash report names the offending pattern. Sized far beyond any
    /// legitimate gate match so a healthy extension is never crashed — only a
    /// genuine never-terminating runaway trips it.
    static let hardCapSeconds = 30

    /// Match timeouts, cumulative over the process, before a pattern is
    /// quarantined. >1 so a one-off scheduling stall on an otherwise-fast
    /// pattern doesn't permanently declaw a legitimate rule; a genuine ReDoS
    /// pattern strikes out within its first few crafted URLs. Strikes are sticky
    /// (not decayed) so an attacker can't dodge quarantine by interleaving fast
    /// URLs between slow ones.
    static let strikeLimit = 3

    /// Per-pattern memo cap. A connection's gate sees a bounded set of
    /// host/path URLs; 256 covers a browser's working set with negligible
    /// memory (a few KiB of strings + bools), and evicts FIFO past that.
    private static let maxCacheEntries = 256

    private let lock = UnfairLock()
    private var cache: [String: Bool] = [:]
    /// Insertion order mirror of ``cache`` for FIFO eviction past the cap.
    private var cacheOrder: [String] = []
    private var timeoutStrikes = 0
    private var quarantined = false

    /// Builds a gate from a pattern string with the default match options,
    /// returning nil when the pattern doesn't compile (the caller drops the
    /// rule with a diagnostic).
    init?(pattern: String) {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else {
            return nil
        }
        self.regex = regex
        self.pattern = pattern
    }

    /// Whether the gate matches ``normalizedURL`` (the caller has already
    /// lowercased the host and applied the length cap). Bounded, memoized, and
    /// quarantine-gated per the type doc; always fail-closed on any
    /// budget/quarantine outcome.
    func matches(_ normalizedURL: String) -> Bool {
        lock.lock()
        if quarantined {
            lock.unlock()
            return false
        }
        if let cached = cache[normalizedURL] {
            lock.unlock()
            return cached
        }
        lock.unlock()

        switch boundedMatch(normalizedURL) {
        case .matched(let matched):
            store(normalizedURL, matched)
            return matched
        case .timedOut:
            recordStrike()
            return false
        }
    }

    private enum MatchOutcome {
        case matched(Bool)
        case timedOut
    }

    /// Runs ``regex`` against ``url`` on ``matchQueue`` and waits at most
    /// ``matchDeadlineMillis``. Returns ``timedOut`` when the budget is blown;
    /// the worker keeps running and, if it eventually finishes, caches its
    /// verdict so a later repeat of the same slow URL is served from memory
    /// instead of re-dispatched.
    private func boundedMatch(_ url: String) -> MatchOutcome {
        let box = VerdictBox()
        let done = DispatchSemaphore(value: 0)
        // Capture the regex (not self) strongly so an abandoned runaway keeps
        // matching even if the rule set reloads and drops this gate; self is
        // weak so the gate's cache isn't pinned for the runaway's lifetime.
        let regex = self.regex
        Self.matchQueue.async { [weak self] in
            let range = NSRange(url.startIndex..., in: url)
            let matched = regex.firstMatch(in: url, options: [], range: range) != nil
            box.value = matched
            done.signal()
            // Best-effort: cache the verdict even when the caller already gave
            // up at the deadline. Skipped (no-op) once the gate is quarantined.
            self?.store(url, matched)
        }
        // The semaphore establishes happens-before between the worker's write
        // to ``box`` and the read below, so the otherwise-unsynchronized box is
        // safe to read on the success path.
        guard done.wait(timeout: .now() + .milliseconds(Self.matchDeadlineMillis)) == .success else {
            // The match blew its soft budget and is now abandoned — still
            // spinning on its (uninterruptible) worker thread. Arm the hard-cap
            // crash check: if it's still running ``hardCapSeconds`` from now the
            // thread is permanently pinned and we tear the extension down to
            // reclaim it.
            Self.scheduleHardCapCheck(done, pattern: pattern)
            return .timedOut
        }
        return .matched(box.value ?? false)
    }

    /// Arms a one-shot crash check for an abandoned match. ``hardCapSeconds``
    /// out, it polls the match's completion semaphore: if the worker still
    /// hasn't signaled, its ``NSRegularExpression`` match is a non-terminating
    /// runaway pinning a core that nothing can reclaim, so the extension is
    /// crashed (the OS relaunches it clean). Reusing the match's own
    /// ``DispatchSemaphore`` as the liveness signal — the worker signals it on
    /// completion whether or not the caller already gave up — needs no extra
    /// per-match bookkeeping: a match that finished within the cap makes the
    /// poll succeed and the check a no-op. Only ever armed on the rare timeout
    /// path, so the always-completing fast path schedules nothing.
    private static func scheduleHardCapCheck(_ done: DispatchSemaphore, pattern: String) {
        monitorQueue.asyncAfter(deadline: .now() + .seconds(hardCapSeconds)) {
            // `.now()` poll: success ⇒ the worker signaled at some point within
            // the cap ⇒ nothing pinned, no-op. timedOut ⇒ still running after
            // the full hard cap ⇒ permanently stuck, crash to recover.
            guard done.wait(timeout: .now()) != .success else { return }
            let shown = pattern.count > 200 ? String(pattern.prefix(200)) + "…" : pattern
            fatalError("[MITM] URL-gate regex did not return \(hardCapSeconds)s after blowing its \(matchDeadlineMillis)ms budget — a worker thread is permanently pinned by catastrophic backtracking and can't be reclaimed. Crashing the Network Extension so the system relaunches it clean. Offending pattern: \(shown)")
        }
    }

    /// Records a (normalized) URL's verdict in the memo cache, evicting the
    /// oldest entry past the cap. No-op once quarantined — a declawed pattern
    /// only ever returns fail-closed, so growing its cache would be wasted
    /// memory. Idempotent for a key already present (refreshes the value
    /// without duplicating it in ``cacheOrder``), so the caller's store and the
    /// worker's late store can't desync the FIFO.
    private func store(_ url: String, _ matched: Bool) {
        lock.lock()
        defer { lock.unlock() }
        guard !quarantined else { return }
        if cache[url] == nil {
            cache[url] = matched
            cacheOrder.append(url)
            if cacheOrder.count > Self.maxCacheEntries {
                let evicted = cacheOrder.removeFirst()
                cache.removeValue(forKey: evicted)
            }
        } else {
            cache[url] = matched
        }
    }

    /// Tallies a match timeout and, past ``strikeLimit``, quarantines the
    /// pattern — every later ``matches(_:)`` then fail-closes without running
    /// the matcher, so no further runaways are spawned. Clears the cache on
    /// quarantine since it's no longer consulted.
    private func recordStrike() {
        lock.lock()
        defer { lock.unlock() }
        guard !quarantined else { return }
        timeoutStrikes += 1
        if timeoutStrikes >= Self.strikeLimit {
            quarantined = true
            cache.removeAll(keepingCapacity: false)
            cacheOrder.removeAll(keepingCapacity: false)
            logger.warning("[MITM] URL-gate pattern quarantined after \(Self.strikeLimit) match timeouts (\(Self.matchDeadlineMillis)ms each) — likely catastrophic backtracking. The rule is disabled (fail-closed) until the rule set is reloaded. Pattern: \(pattern)")
        } else {
            logger.warning("[MITM] URL-gate match exceeded its \(Self.matchDeadlineMillis)ms budget (strike \(timeoutStrikes)/\(Self.strikeLimit)); failing this match closed. Pattern: \(pattern)")
        }
    }

    /// One-shot carrier for the worker's verdict across the queue hop.
    /// Synchronized by the ``DispatchSemaphore`` in ``boundedMatch`` (written
    /// before ``signal``, read only after ``wait`` succeeds), hence the
    /// unchecked ``Sendable`` conformance.
    private final class VerdictBox: @unchecked Sendable {
        var value: Bool?
    }
}
