//
//  MITMGateRegex.swift
//  Anywhere
//
//  Created by NodePassProject on 6/3/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMGateRegex")

nonisolated final class MITMGateRegex: Sendable {
    typealias Verdict = MITMRegexConcurrencyBridge.GateMatch

    struct Request {
        let gate: MITMGateRegex
        let wantsCaptures: Bool
    }

    private let regex: NSRegularExpression
    private let pattern: String

    private let isLiteral: Bool
    private let literalPattern: String

    private static let regexMetacharacters: Set<Character> = [
        "\\", "^", "$", ".", "|", "?", "*", "+", "(", ")", "[", "]", "{", "}"
    ]

    static let matchDeadlineMillis = 100
    static let hardCapSeconds = 30
    static let strikeLimit = 3

    private static let maxCacheEntries = 64

    private struct State {
        var cache: [String: Verdict] = [:]
        var cacheOrder: [String] = []
        var timeoutStrikes = 0
        var isQuarantined = false
    }

    private let state = Mutex(State())

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
            Self.warnIfHostRegionHasUppercase(pattern)
        }
    }

    private static func lowercasingHostRegion(_ pattern: String) -> String {
        guard let schemeSeparator = pattern.range(of: "://") else { return pattern }
        let authorityStart = schemeSeparator.upperBound
        let authorityEnd = pattern[authorityStart...].firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) ?? pattern.endIndex
        return pattern[..<authorityStart].lowercased()
            + pattern[authorityStart..<authorityEnd].lowercased()
            + String(pattern[authorityEnd...])
    }

    private static func warnIfHostRegionHasUppercase(_ pattern: String) {
        guard let schemeRange = pattern.range(of: "://") else { return }
        let authority = pattern[schemeRange.upperBound...].prefix { $0 != "/" }
        if authority.contains(where: { $0.isASCII && $0.isUppercase }) {
            logger.warning("gate pattern \"\(pattern)\" has an uppercase letter in its host region; the URL host is matched lowercased, so this rule will never fire")
        }
    }

    func peek(_ normalizedURL: String, wantsCaptures: Bool) -> Verdict? {
        if isLiteral {
            guard let range = normalizedURL.range(of: literalPattern, options: .literal) else { return .noMatch }
            return .match(wantsCaptures ? [String(normalizedURL[range])] : nil)
        }
        return state.withLock { state in
            if state.isQuarantined { return .noMatch }
            switch state.cache[normalizedURL] {
            case .noMatch:
                return .noMatch
            case .match(let captures):
                guard wantsCaptures, captures == nil else { return .match(captures) }
                return nil
            case nil:
                return nil
            }
        }
    }

    static func resolve(_ requests: [Request], in normalizedURL: String) async -> [Verdict] {
        var verdicts = [Verdict?](repeating: nil, count: requests.count)
        var slots: [ObjectIdentifier: Int] = [:]
        var pending: [(gate: MITMGateRegex, wantsCaptures: Bool, requests: [Int])] = []
        for (index, request) in requests.enumerated() {
            if let verdict = request.gate.peek(normalizedURL, wantsCaptures: request.wantsCaptures) {
                verdicts[index] = verdict
                continue
            }
            let key = ObjectIdentifier(request.gate)
            if let slot = slots[key] {
                pending[slot].wantsCaptures = pending[slot].wantsCaptures || request.wantsCaptures
                pending[slot].requests.append(index)
            } else {
                slots[key] = pending.count
                pending.append((gate: request.gate, wantsCaptures: request.wantsCaptures, requests: [index]))
            }
        }
        guard !pending.isEmpty, !Task.isCancelled else { return verdicts.map { $0 ?? .noMatch } }

        let outcomes = await MITMRegexConcurrencyBridge.shared.firstMatches(
            pending.map { entry in
                let gate = entry.gate
                return MITMRegexConcurrencyBridge.GateRequest(
                    regex: gate.regex,
                    wantsCaptures: entry.wantsCaptures,
                    onResolved: { [weak gate] verdict in gate?.store(normalizedURL, verdict) },
                    hardCapMessage: { Self.hardCapMessage(pattern: gate.pattern) }
                )
            },
            in: normalizedURL,
            deadlineMillis: matchDeadlineMillis,
            hardCapSeconds: hardCapSeconds
        )
        let cancelled = Task.isCancelled
        for (entry, outcome) in zip(pending, outcomes) {
            let verdict: Verdict
            switch outcome {
            case .completed(let resolved):
                verdict = resolved
            case .timedOut:
                if !cancelled { entry.gate.recordStrike() }
                verdict = .noMatch
            }
            for index in entry.requests { verdicts[index] = verdict }
        }
        return verdicts.map { $0 ?? .noMatch }
    }

    private static func hardCapMessage(pattern: String) -> String {
        let shown = pattern.count > 200 ? String(pattern.prefix(200)) + "…" : pattern
        return "URL-gate regex did not return \(hardCapSeconds)s after blowing its \(matchDeadlineMillis)ms budget — a worker thread is permanently pinned by catastrophic backtracking and can't be reclaimed. Crashing the Network Extension so the system relaunches it clean. Offending pattern: \(shown)"
    }

    private func store(_ url: String, _ verdict: Verdict) {
        state.withLock { state in
            guard !state.isQuarantined else { return }
            switch (state.cache[url], verdict) {
            case (nil, _):
                state.cache[url] = verdict
                state.cacheOrder.append(url)
                if state.cacheOrder.count > Self.maxCacheEntries {
                    let evicted = state.cacheOrder.removeFirst()
                    state.cache.removeValue(forKey: evicted)
                }
            case (.some(.match(.some)), .match(.none)):
                return
            default:
                state.cache[url] = verdict
            }
        }
    }

    private func recordStrike() {
        let message: String? = state.withLock { state in
            guard !state.isQuarantined else { return nil }
            state.timeoutStrikes += 1
            if state.timeoutStrikes >= Self.strikeLimit {
                state.isQuarantined = true
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
