//
//  MITMGateRegex.swift
//  Anywhere
//
//  Created by NodePassProject on 6/3/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMGateRegex")

nonisolated final class MITMGateRegex: @unchecked Sendable {

    /// NSRegularExpression is immutable and thread-safe for concurrent matching.
    private let regex: NSRegularExpression
    /// Retained only for quarantine/strike log lines.
    private let pattern: String

    /// No ICU metacharacters → can't backtrack, so the match runs inline. Empty patterns are
    /// excluded: `range(of:)` finds nothing where `firstMatch` matches everywhere.
    private let isLiteral: Bool

    /// Literal fast-path pattern with the authority lowercased; equals `pattern` for
    /// regex patterns, where auto-lowercasing could corrupt escapes like `\D`.
    private let literalPattern: String

    /// A pattern containing none of these is a plain literal.
    private static let regexMetacharacters: Set<Character> = [
        "\\", "^", "$", ".", "|", "?", "*", "+", "(", ")", "[", "]", "{", "}"
    ]

    /// Soft deadline per cache-miss match; far above the legitimate microsecond cost so
    /// scheduling hiccups don't false-trip it.
    static let matchDeadlineMillis = 100

    /// Hard cap on an abandoned match: a worker alive this long is a core pinned
    /// forever, and the only recourse is fatalError (the match is uninterruptible).
    static let hardCapSeconds = 30

    /// Timeouts before quarantine; >1 so a scheduling stall doesn't permanently
    /// declaw a legitimate rule. Strikes are sticky.
    static let strikeLimit = 3
    
    private static let maxCacheEntries = 64

    private struct State {
        var cache: [String: Bool] = [:]
        /// Insertion-order mirror of `cache` for FIFO eviction.
        var cacheOrder: [String] = []
        var timeoutStrikes = 0
        var quarantined = false
    }

    private let state = Mutex(State())

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
            logger.warning("gate pattern \"\(pattern)\" has an uppercase letter in its host region; the URL host is matched lowercased, so this rule will never fire — write the host in lowercase")
        }
    }

    /// Whether the gate matches the URL (caller already lowercased the host and
    /// capped length). Fail-closed on timeout or quarantine.
    func matches(_ normalizedURL: String) -> Bool {
        // Literal gates can't backtrack — match inline; `.literal` is code-unit-exact and
        // unanchored like `firstMatch`.
        if isLiteral {
            return normalizedURL.range(of: literalPattern, options: .literal) != nil
        }
        enum CachePeek { case quarantined, cached(Bool), miss }
        let peek: CachePeek = state.withLock { state in
            if state.quarantined { return .quarantined }
            if let cached = state.cache[normalizedURL] { return .cached(cached) }
            return .miss
        }
        switch peek {
        case .quarantined: return false
        case .cached(let cached): return cached
        case .miss: break
        }

        switch boundedMatch(normalizedURL) {
        case .matched(let matched):
            store(normalizedURL, matched)
            return matched
        case .timedOut:
            recordStrike()
            return false
        }
    }

    /// Capture groups of the first match (index 0 = whole match), or nil on no match,
    /// timeout, or quarantine. Not memoized (unbounded URL-specific working set), but shares
    /// the deadline, hard-cap crash, and strike/quarantine machinery of ``matches(_:)``.
    func firstMatchCaptures(_ normalizedURL: String) -> [String?]? {
        // A literal pattern has no capturing groups; group 0 is the matched span.
        if isLiteral {
            guard let r = normalizedURL.range(of: literalPattern, options: .literal) else { return nil }
            return [String(normalizedURL[r])]
        }
        if state.withLock({ $0.quarantined }) { return nil }

        // Strong regex, no self: a runaway can outlive a reload without pinning the cache.
        // Not memoized. `.completed(nil)` is a real no-match; `.timedOut` is an abandoned worker.
        let regex = self.regex
        let pattern = self.pattern
        let outcome = MITMGateRegexMatchConcurrencyBridge.shared.runBounded(
            deadlineMillis: Self.matchDeadlineMillis,
            hardCapSeconds: Self.hardCapSeconds,
            hardCapMessage: { Self.hardCapMessage(pattern: pattern) }
        ) {
            Self.captureGroups(regex, in: normalizedURL)
        }
        switch outcome {
        case .completed(let captures):
            return captures
        case .timedOut:
            recordStrike()
            return nil
        }
    }

    /// Extracts the first match's groups (index 0 = whole match); a non-participating
    /// group is `nil`. nil overall means the pattern did not match.
    private static func captureGroups(_ regex: NSRegularExpression, in url: String) -> [String?]? {
        let range = NSRange(url.startIndex..., in: url)
        guard let match = regex.firstMatch(in: url, options: [], range: range) else { return nil }
        var groups: [String?] = []
        groups.reserveCapacity(match.numberOfRanges)
        for i in 0..<match.numberOfRanges {
            let nsRange = match.range(at: i)
            if nsRange.location == NSNotFound {
                groups.append(nil)
            } else if let r = Range(nsRange, in: url) {
                groups.append(String(url[r]))
            } else {
                groups.append(nil)
            }
        }
        return groups
    }

    private enum MatchOutcome {
        case matched(Bool)
        case timedOut
    }

    /// Runs the match on a bounded worker via the gate-match bridge; an abandoned worker that
    /// finishes late still caches its verdict (the `store` in `body`).
    private func boundedMatch(_ url: String) -> MatchOutcome {
        // Strong regex + weak self: a runaway can outlive a reload without pinning the cache.
        let regex = self.regex
        let pattern = self.pattern
        let outcome = MITMGateRegexMatchConcurrencyBridge.shared.runBounded(
            deadlineMillis: Self.matchDeadlineMillis,
            hardCapSeconds: Self.hardCapSeconds,
            hardCapMessage: { Self.hardCapMessage(pattern: pattern) }
        ) { [weak self] () -> Bool in
            let range = NSRange(url.startIndex..., in: url)
            let matched = regex.firstMatch(in: url, options: [], range: range) != nil
            // Best-effort late cache: no-op once quarantined.
            self?.store(url, matched)
            return matched
        }
        switch outcome {
        case .completed(let matched):
            return .matched(matched)
        case .timedOut:
            return .timedOut
        }
    }

    /// The `fatalError` message for a permanently-pinned URL-gate worker, built off the crash path.
    private static func hardCapMessage(pattern: String) -> String {
        let shown = pattern.count > 200 ? String(pattern.prefix(200)) + "…" : pattern
        return "URL-gate regex did not return \(hardCapSeconds)s after blowing its \(matchDeadlineMillis)ms budget — a worker thread is permanently pinned by catastrophic backtracking and can't be reclaimed. Crashing the Network Extension so the system relaunches it clean. Offending pattern: \(shown)"
    }

    /// FIFO-evicting memo store; no-op when quarantined. Idempotent so a caller store and a
    /// concurrent late worker store can't desync `cacheOrder`.
    private func store(_ url: String, _ matched: Bool) {
        state.withLock { state in
            guard !state.quarantined else { return }
            if state.cache[url] == nil {
                state.cache[url] = matched
                state.cacheOrder.append(url)
                if state.cacheOrder.count > Self.maxCacheEntries {
                    let evicted = state.cacheOrder.removeFirst()
                    state.cache.removeValue(forKey: evicted)
                }
            } else {
                state.cache[url] = matched
            }
        }
    }

    /// Tallies a timeout strike, quarantining the pattern at `strikeLimit`.
    private func recordStrike() {
        let message: String? = state.withLock { state in
            guard !state.quarantined else { return nil }
            state.timeoutStrikes += 1
            if state.timeoutStrikes >= Self.strikeLimit {
                state.quarantined = true
                state.cache.removeAll(keepingCapacity: false)
                state.cacheOrder.removeAll(keepingCapacity: false)
                return "URL-gate pattern quarantined after \(Self.strikeLimit) match timeouts (\(Self.matchDeadlineMillis)ms each); the rule is disabled. Pattern: \(pattern)"
            } else {
                return "URL-gate match exceeded its \(Self.matchDeadlineMillis)ms budget (strike \(state.timeoutStrikes)/\(Self.strikeLimit)); failing this match closed. Pattern: \(pattern)"
            }
        }
        if let message {
            logger.warning(message)
        }
    }
}
