//
//  MITMGateRegex.swift
//  Anywhere
//
//  Created by NodePassProject on 6/3/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITMGateRegex")

/// ReDoS containment for an untrusted URL-gate regex: memoization, deadline-bounded matching
/// on a worker queue, and quarantine after repeated timeouts — all fail-closed (no-match).
final class MITMGateRegex: @unchecked Sendable {

    /// NSRegularExpression is immutable and thread-safe for concurrent matching.
    private let regex: NSRegularExpression
    /// Retained only for quarantine/strike log lines.
    private let pattern: String

    /// No ICU metacharacters → can't backtrack, so the match runs inline. Empty patterns
    /// are excluded: `range(of:)` finds nothing where `firstMatch` matches everywhere.
    private let isLiteral: Bool

    /// Literal fast-path pattern with the authority lowercased; equals `pattern` for
    /// regex patterns, where auto-lowercasing could corrupt escapes like `\D`.
    private let literalPattern: String

    /// A pattern containing none of these is a plain literal.
    private static let regexMetacharacters: Set<Character> = [
        "\\", "^", "$", ".", "|", "?", "*", "+", "(", ")", "[", "]", "{", "}"
    ]

    /// Concurrent is load-bearing: an abandoned runaway must not block subsequent matches.
    private static let matchQueue = DispatchQueue(
        label: AWCore.Identifier.mitmGateMatchQueue,
        qos: .userInitiated,
        attributes: .concurrent
    )

    /// Soft deadline per cache-miss match; far above the legitimate microsecond cost so scheduling hiccups don't false-trip it.
    static let matchDeadlineMillis = 100

    /// Hard cap on an abandoned match: a worker alive this long is a core pinned
    /// forever, and the only recourse is fatalError (the match is uninterruptible).
    static let hardCapSeconds = 30

    /// Timeouts before quarantine; >1 so a scheduling stall doesn't permanently
    /// declaw a legitimate rule. Strikes are sticky.
    static let strikeLimit = 3

    /// FIFO eviction cap; 256 covers a browser's working set at negligible memory.
    private static let maxCacheEntries = 256

    private let lock = UnfairLock()
    private var cache: [String: Bool] = [:]
    /// Insertion-order mirror of `cache` for FIFO eviction.
    private var cacheOrder: [String] = []
    private var timeoutStrikes = 0
    private var quarantined = false

    /// nil when the pattern fails to compile; the caller drops the rule.
    init?(pattern: String) {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else {
            return nil
        }
        self.regex = regex
        self.pattern = pattern
        let literal = !pattern.isEmpty
            && !pattern.contains { Self.regexMetacharacters.contains($0) }
        self.isLiteral = literal
        if literal {
            self.literalPattern = Self.lowercasingHostRegion(pattern)
        } else {
            self.literalPattern = pattern
            // Regex hosts can't be safely auto-lowercased; warn the author instead.
            Self.warnIfHostRegionHasUppercase(pattern)
        }
    }

    /// Lowercases only the authority region; unchanged when no `://` is present.
    private static func lowercasingHostRegion(_ pattern: String) -> String {
        guard let sep = pattern.range(of: "://") else { return pattern }
        let authStart = sep.upperBound
        let authEnd = pattern[authStart...].firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) ?? pattern.endIndex
        return pattern[..<authStart].lowercased()
            + pattern[authStart..<authEnd].lowercased()
            + String(pattern[authEnd...])
    }

    /// Warns about uppercase in the authority region — URL hosts are matched lowercased, so the rule would never fire.
    private static func warnIfHostRegionHasUppercase(_ pattern: String) {
        guard let schemeRange = pattern.range(of: "://") else { return }
        let authority = pattern[schemeRange.upperBound...].prefix { $0 != "/" }
        if authority.contains(where: { $0.isASCII && $0.isUppercase }) {
            logger.warning("[MITM] gate pattern \"\(pattern)\" has an uppercase letter in its host region; the URL host is matched lowercased, so this rule will never fire — write the host in lowercase")
        }
    }

    /// Whether the gate matches the URL (caller already lowercased the host and
    /// capped length). Fail-closed on timeout or quarantine.
    func matches(_ normalizedURL: String) -> Bool {
        // Literal gates can't backtrack — match inline; `.literal` is code-unit-exact and unanchored like `firstMatch`.
        if isLiteral {
            return normalizedURL.range(of: literalPattern, options: .literal) != nil
        }
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

    /// Runs the match on the worker queue under the deadline; an abandoned worker that finishes still caches its verdict.
    private func boundedMatch(_ url: String) -> MatchOutcome {
        let box = VerdictBox()
        let done = DispatchSemaphore(value: 0)
        // Strong regex + weak self: a runaway can outlive a reload without pinning the cache.
        let regex = self.regex
        Self.matchQueue.async { [weak self] in
            let range = NSRange(url.startIndex..., in: url)
            let matched = regex.firstMatch(in: url, options: [], range: range) != nil
            box.value = matched
            done.signal()
            // Best-effort late cache: no-op once quarantined.
            self?.store(url, matched)
        }
        // The semaphore establishes happens-before for the unsynchronized box.
        guard done.wait(timeout: .now() + .milliseconds(Self.matchDeadlineMillis)) == .success else {
            Self.scheduleHardCapCheck(done, pattern: pattern)
            return .timedOut
        }
        return .matched(box.value ?? false)
    }

    /// One-shot hard-cap crash check; the match's own semaphore is the liveness
    /// signal, so a match that finishes within the cap makes this a no-op.
    private static func scheduleHardCapCheck(_ done: DispatchSemaphore, pattern: String) {
        MITMWatchdogMonitor.queue.asyncAfter(deadline: .now() + .seconds(hardCapSeconds)) {
            guard done.wait(timeout: .now()) != .success else { return }
            let shown = pattern.count > 200 ? String(pattern.prefix(200)) + "…" : pattern
            fatalError("[MITM] URL-gate regex did not return \(hardCapSeconds)s after blowing its \(matchDeadlineMillis)ms budget — a worker thread is permanently pinned by catastrophic backtracking and can't be reclaimed. Crashing the Network Extension so the system relaunches it clean. Offending pattern: \(shown)")
        }
    }

    /// FIFO-evicting memo store; no-op when quarantined. Idempotent so a caller
    /// store and a concurrent late worker store can't desync `cacheOrder`.
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

    /// Tallies a timeout strike, quarantining the pattern at `strikeLimit`.
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

    /// Synchronized by the semaphore (written before `signal`, read after `wait`) — hence `@unchecked Sendable`.
    private final class VerdictBox: @unchecked Sendable {
        var value: Bool?
    }
}
