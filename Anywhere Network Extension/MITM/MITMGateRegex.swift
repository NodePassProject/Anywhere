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
    private let literalPatternBytes: [UInt8]

    private let alwaysMatches: Bool
    private let requiredLiterals: [[UInt8]]

    private enum PrefixAtom {
        case byte(UInt8)
        case any
    }
    private let anchoredPrefix: [(atom: PrefixAtom, isOptional: Bool)]

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
        self.alwaysMatches = pattern == ".*" || pattern == "^.*"
        if literal {
            self.literalPattern = Self.lowercasingHostRegion(pattern)
            self.requiredLiterals = []
        } else {
            self.literalPattern = pattern
            self.requiredLiterals = (MITMRegexLiterals.required(in: pattern) ?? []).map { Array($0.utf8) }
            Self.warnIfHostRegionHasUppercase(pattern)
        }
        self.literalPatternBytes = Array(literalPattern.utf8)
        self.anchoredPrefix = literal ? [] : Self.anchoredPrefix(of: pattern)
    }

    static func urlPrefix(scheme: String, host: String) -> [UInt8]? {
        let host = host.lowercased()
        guard !host.isEmpty, !host.hasSuffix("."),
              host.utf8.allSatisfy({ (0x21...0x7E).contains($0) && $0 != UInt8(ascii: "/") && $0 != UInt8(ascii: "?") && $0 != UInt8(ascii: "#") })
        else { return nil }
        return Array("\(scheme.lowercased())://\(host)".utf8)
    }

    func mayMatch(urlPrefix: [UInt8]?) -> Bool {
        guard let urlPrefix, !anchoredPrefix.isEmpty else { return true }
        var positions: Set<Int> = [0]
        for token in anchoredPrefix {
            var next: Set<Int> = []
            for position in positions {
                if position == urlPrefix.count { return true }
                if token.isOptional { next.insert(position) }
                switch token.atom {
                case .any:
                    next.insert(position + 1)
                case .byte(let byte) where urlPrefix[position] == byte:
                    next.insert(position + 1)
                case .byte:
                    break
                }
            }
            guard !next.isEmpty else { return false }
            positions = next
        }
        return true
    }

    private static func anchoredPrefix(of pattern: String) -> [(atom: PrefixAtom, isOptional: Bool)] {
        let bytes = Array(pattern.utf8)
        guard bytes.first == UInt8(ascii: "^"), !bytes.contains(UInt8(ascii: "|")) else { return [] }
        let stops = Set("^$()[]{}*+?|".utf8)
        let quantifiers = Set("*+?{".utf8)
        var tokens: [(atom: PrefixAtom, isOptional: Bool)] = []
        var index = 1
        while index < bytes.count {
            let byte = bytes[index]
            let atom: PrefixAtom
            var next = index + 1
            if byte == UInt8(ascii: "\\") {
                guard next < bytes.count else { break }
                let escaped = bytes[next]
                guard (0x21...0x7E).contains(escaped), !isASCIIAlphanumeric(escaped) else { break }
                atom = .byte(escaped)
                next += 1
            } else if byte == UInt8(ascii: ".") {
                atom = .any
            } else if stops.contains(byte) || !(0x21...0x7E).contains(byte) {
                break
            } else {
                atom = .byte(byte)
            }
            var isOptional = false
            if next < bytes.count, quantifiers.contains(bytes[next]) {
                guard bytes[next] == UInt8(ascii: "?"),
                      next + 1 >= bytes.count || !quantifiers.contains(bytes[next + 1])
                else { break }
                isOptional = true
                next += 1
            }
            tokens.append((atom: atom, isOptional: isOptional))
            index = next
        }
        return tokens
    }

    private static func isASCIIAlphanumeric(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte) || (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
    }

    private static func contains(_ haystack: UnsafeBufferPointer<UInt8>, _ needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, needle.count <= haystack.count, let base = haystack.baseAddress else { return false }
        return needle.withUnsafeBufferPointer { needle in
            memmem(base, haystack.count, needle.baseAddress, needle.count) != nil
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
            logger.warning("[MITM] Uppercase host in URL pattern: \(pattern)")
        }
    }

    func peek(_ normalizedURL: String, wantsCaptures: Bool) -> Verdict? {
        if isLiteral {
            var url = normalizedURL
            guard url.withUTF8({ Self.contains($0, literalPatternBytes) }) else { return .noMatch }
            return .match(wantsCaptures ? [literalPattern] : nil)
        }
        if alwaysMatches, !wantsCaptures { return .match(nil) }
        if !requiredLiterals.isEmpty {
            var url = normalizedURL
            let missesLiteral = url.withUTF8 { haystack in
                requiredLiterals.contains { !Self.contains(haystack, $0) }
            }
            if missesLiteral { return .noMatch }
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
        let struck = state.withLock { state in
            guard !state.isQuarantined else { return false }
            state.timeoutStrikes += 1
            if state.timeoutStrikes >= Self.strikeLimit {
                state.isQuarantined = true
                state.cache.removeAll(keepingCapacity: false)
                state.cacheOrder.removeAll(keepingCapacity: false)
            }
            return true
        }
        if struck {
            logger.warning("[MITM] URL pattern match timed out: \(pattern)")
        }
    }
}
