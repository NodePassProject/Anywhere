//
//  MITMRewritePolicy.swift
//  Anywhere
//
//  Created by NodePassProject on 5/4/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMRewritePolicy")

nonisolated struct CompiledMITMRule {
    let phase: MITMPhase
    let gate: MITMGateRegex
    let operation: CompiledMITMOperation
}

extension CompiledMITMRule {
    static let maxGateURLLength = 8 * 1024
    
    func matchesURL(_ url: String?) async -> Bool {
        guard let url, url.utf16.count <= Self.maxGateURLLength else { return false }
        return await gate.matches(Self.lowercasingHost(url))
    }
    
    func peekMatchesURL(_ url: String?) -> Bool? {
        guard let url, url.utf16.count <= Self.maxGateURLLength else { return false }
        return gate.peekMatches(Self.lowercasingHost(url))
    }
    
    private static func lowercasingHost(_ url: String) -> String {
        guard let sep = url.range(of: "://") else { return url }
        let authStart = sep.upperBound
        let authEnd = url[authStart...].firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) ?? url.endIndex
        var authority = url[authStart..<authEnd].lowercased()
        if authority.hasSuffix(".") { authority.removeLast() }
        return url[..<authStart].lowercased() + authority + String(url[authEnd...])
    }
}

extension CompiledMITMRule {
    func capturesForURL(_ url: String?) async -> [String?]? {
        guard let url, url.utf16.count <= Self.maxGateURLLength else { return nil }
        return await gate.firstMatchCaptures(Self.lowercasingHost(url))
    }
    
    func peekCapturesForURL(_ url: String?) -> [String?]?? {
        guard let url, url.utf16.count <= Self.maxGateURLLength else { return .some(nil) }
        return gate.peekFirstMatchCaptures(Self.lowercasingHost(url))
    }
    
    func resolvedRewriteAction(verdicts: MITMGateVerdictTable, at index: Int) -> ResolvedRewriteAction? {
        guard case .rewrite(let action) = operation else { return nil }
        switch action {
        case .transparent(.resolved(let replacement)):
            return verdicts.matches(at: index) ? .transparent(replacement) : nil
        case .transparent(.templated(let template)):
            guard let captures = verdicts.captures(at: index),
                  let replacement = MITMRewritePolicy.resolveTransparentTemplate(template, captures: captures)
            else { return nil }
            return .transparent(replacement)
        case .redirect302(.location(let location)):
            return verdicts.matches(at: index) ? .redirect302(location: location) : nil
        case .redirect302(.templated(let template)):
            guard let captures = verdicts.captures(at: index),
                  let location = MITMRewritePolicy.resolveRedirectTemplate(template, captures: captures)
            else { return nil }
            return .redirect302(location: location)
        case .reject200Text(let content):
            return verdicts.matches(at: index) ? .reject200Text(content: content) : nil
        case .reject200Gif:
            return verdicts.matches(at: index) ? .reject200Gif : nil
        case .reject200Data(let base64):
            return verdicts.matches(at: index) ? .reject200Data(base64: base64) : nil
        }
    }
}

nonisolated struct MITMGateVerdictTable: Sendable {
    let url: String?
    private let matched: [Bool]
    private let captureGroups: [[String?]?]

    func matches(at index: Int) -> Bool { matched[index] }
    func captures(at index: Int) -> [String?]? { captureGroups[index] }
    
    static let empty = MITMGateVerdictTable(url: nil, matched: [], captureGroups: [])
    
    private static func needsCaptures(_ rule: CompiledMITMRule) -> Bool {
        guard case .rewrite(let action) = rule.operation else { return false }
        switch action {
        case .transparent(.templated), .redirect302(.templated):
            return true
        case .transparent(.resolved), .redirect302(.location),
             .reject200Text, .reject200Gif, .reject200Data:
            return false
        }
    }
    
    static func peek(rules: [CompiledMITMRule], url: String?) -> MITMGateVerdictTable? {
        var matched = [Bool]()
        matched.reserveCapacity(rules.count)
        var captureGroups = [[String?]?](repeating: nil, count: rules.count)
        for (index, rule) in rules.enumerated() {
            if needsCaptures(rule) {
                guard let groups = rule.peekCapturesForURL(url) else { return nil }
                captureGroups[index] = groups
                matched.append(groups != nil)
            } else {
                guard let verdict = rule.peekMatchesURL(url) else { return nil }
                matched.append(verdict)
            }
        }
        return MITMGateVerdictTable(url: url, matched: matched, captureGroups: captureGroups)
    }
    
    static func resolve(rules: [CompiledMITMRule], url: String?) async -> MITMGateVerdictTable {
        var matched = [Bool]()
        matched.reserveCapacity(rules.count)
        var captureGroups = [[String?]?](repeating: nil, count: rules.count)
        for (index, rule) in rules.enumerated() {
            if needsCaptures(rule) {
                let groups = await rule.capturesForURL(url)
                captureGroups[index] = groups
                matched.append(groups != nil)
            } else {
                matched.append(await rule.matchesURL(url))
            }
        }
        return MITMGateVerdictTable(url: url, matched: matched, captureGroups: captureGroups)
    }
}

nonisolated struct ReplacementURL: Equatable {
    let host: String
    let port: UInt16?
    let requestTarget: String
    
    var authority: String {
        let bracketedHost = host.contains(":") ? "[\(host)]" : host
        if let port { return "\(bracketedHost):\(port)" }
        return bracketedHost
    }
}

nonisolated enum TransparentTarget {
    case resolved(ReplacementURL)
    case templated(MITMCaptureTemplate)
}

nonisolated enum RedirectTarget {
    case location(String)
    case templated(MITMCaptureTemplate)
}

nonisolated enum CompiledRewriteAction {
    case transparent(TransparentTarget)
    case redirect302(RedirectTarget)
    case reject200Text(content: String)
    case reject200Gif
    case reject200Data(base64: String)
}

nonisolated enum ResolvedRewriteAction {
    case transparent(ReplacementURL)
    case redirect302(location: String)
    case reject200Text(content: String)
    case reject200Gif
    case reject200Data(base64: String)
}

nonisolated enum CompiledMITMOperation {
    case rewrite(CompiledRewriteAction)
    case headerAdd(name: String, value: String)
    case headerDelete(nameLower: String)
    case headerReplace(name: String, value: String)
    case bodyReplace(MITMBodyReplace.CompiledOperation)
    case bodyJSON(MITMJSONPatch.CompiledOperation)
    case script(source: String)
    case streamScript(source: String)
}

nonisolated struct CompiledMITMRuleSet {
    let id: UUID
    let domainSuffix: String
    let rules: [CompiledMITMRule]
}

nonisolated final class MITMRewritePolicy: Sendable {
    private struct PolicyState {
        var trie = FlatLabelTrie<Int16>()
        var compiledSets: [CompiledMITMRuleSet] = []
        var setCount: Int = 0
        var gateCache: [String: MITMGateRegex] = [:]
    }
    
    private let state = Mutex(PolicyState())
    
    var hasRules: Bool { state.withLock { $0.setCount > 0 } }

    func reset() {
        state.withLock { $0 = PolicyState() }
    }
    
    func load(ruleSets: [MITMRuleSet]) {
        var scopedRules: [(scope: UUID, rules: [CompiledMITMRule])] = []
        let previousGates = state.withLock { $0.gateCache }
        var newState = PolicyState()
        let trie = FlatLabelTrieBuilder<Int16>()
        var newGates: [String: MITMGateRegex] = [:]
        for set in ruleSets {
            guard set.enabled else { continue }
            if let compiled = insert(set, into: &newState, trie: trie, previousGates: previousGates, newGates: &newGates) {
                scopedRules.append((scope: set.id, rules: compiled))
            }
        }
        newState.gateCache = newGates
        newState.trie = trie.freeze()
        state.withLock { $0 = newState }
        let activeIDs = Set(ruleSets.map { $0.id })
        MITMScriptEngine.purgeRuns(activeIDs: activeIDs)
        MITMParamStore.shared.replaceAll(ruleSets.map { (scope: $0.id, values: $0.parameterValues) })
        MITMScriptTransform.rulesDidReload(scopedRules: scopedRules)
        let purged = MITMScriptStore.shared.purgeExcept(activeIDs: activeIDs)
        if purged > 0 {
            logger.debug("Loaded \(ruleSets.count) rule set(s); purged \(purged) stale script-store bucket(s)")
        } else {
            logger.debug("Loaded \(ruleSets.count) rule set(s)")
        }
    }
    
    private func insert(
        _ set: MITMRuleSet,
        into state: inout PolicyState,
        trie: FlatLabelTrieBuilder<Int16>,
        previousGates: [String: MITMGateRegex],
        newGates: inout [String: MITMGateRegex]
    ) -> [CompiledMITMRule]? {
        let suffixes = set.domainSuffixes
            .map { $0.lowercased().trimmingCharacters(in: CharacterSet.whitespaces) }
            .filter { !$0.isEmpty }
        guard !suffixes.isEmpty else { return nil }

        let compiledRules = set.rules.compactMap { rule -> CompiledMITMRule? in
            let gate: MITMGateRegex
            if let cached = newGates[rule.urlPattern] ?? previousGates[rule.urlPattern] {
                gate = cached
            } else {
                guard let compiled = MITMGateRegex(pattern: rule.urlPattern) else {
                    logger.warning("rule URL pattern failed to compile (suffix=\(set.name)): \(rule.urlPattern)")
                    return nil
                }
                gate = compiled
            }
            newGates[rule.urlPattern] = gate
            guard let op = compile(rule.operation, suffix: set.name) else { return nil }
            return CompiledMITMRule(phase: rule.phase, gate: gate, operation: op)
        }

        for suffix in suffixes {
            guard state.compiledSets.count < Int(Int16.max) else {
                logger.warning("MITM suffix table full (\(state.compiledSets.count) entries)")
                break
            }
            let payload = CompiledMITMRuleSet(
                id: set.id,
                domainSuffix: suffix,
                rules: compiledRules
            )
            let payloadID = Int16(state.compiledSets.count)
            state.compiledSets.append(payload)
            if trie.insert(suffix: suffix, payload: payloadID) {
                state.setCount += 1
            } else {
                // Later set (user-list order) wins; log so the override is never silent.
                logger.warning("duplicate domain suffix \"\(suffix)\": rule set \"\(set.name)\" overrides an earlier set's rules for it")
            }
        }
        return compiledRules
    }

    func matches(_ host: String) -> Bool {
        set(for: host) != nil
    }
    
    func set(for host: String) -> CompiledMITMRuleSet? {
        guard !host.isEmpty else { return nil }
        var lowered = host.lowercased()
        return state.withLock { state -> CompiledMITMRuleSet? in
            guard state.setCount > 0 else { return nil }
            guard let id = lowered.withUTF8({ state.trie.lookup($0) }) else { return nil }
            let index = Int(id)
            guard index >= 0, index < state.compiledSets.count else { return nil }
            return state.compiledSets[index]
        }
    }
    
    func rules(for host: String, phase: MITMPhase) -> [CompiledMITMRule] {
        guard let set = set(for: host) else { return [] }
        return set.rules.filter { $0.phase == phase }
    }

    // MARK: - Compilation

    private func compile(_ operation: MITMOperation, suffix: String) -> CompiledMITMOperation? {
        switch operation {
        case .rewrite(let action):
            guard let compiled = Self.compileRewrite(action, suffix: suffix) else { return nil }
            return .rewrite(compiled)
        case .headerAdd(let name, let value):
            guard HTTPHeader.isValidName(name) else {
                logger.warning("headerAdd dropped: invalid header name \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            guard !Self.isFramingHeader(name) else {
                logger.warning("headerAdd dropped: \"\(name)\" controls message framing and can't be set by a header rule (suffix=\(suffix))")
                return nil
            }
            guard HTTPHeader.isValidValue(value) else {
                logger.warning("headerAdd dropped: CR/LF/NUL in value for header \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            return .headerAdd(name: name, value: value)
        case .headerDelete(let name):
            guard HTTPHeader.isValidName(name) else {
                logger.warning("headerDelete dropped: invalid header name \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            return .headerDelete(nameLower: name.lowercased())
        case .headerReplace(let name, let value):
            guard HTTPHeader.isValidName(name) else {
                logger.warning("headerReplace dropped: invalid header name \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            guard !Self.isFramingHeader(name) else {
                logger.warning("headerReplace dropped: \"\(name)\" controls message framing and can't be set by a header rule (suffix=\(suffix))")
                return nil
            }
            guard HTTPHeader.isValidValue(value) else {
                logger.warning("headerReplace dropped: CR/LF/NUL in value for header \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            return .headerReplace(name: name, value: value)
        case .script(let scriptBase64):
            guard let source = decodeScript(scriptBase64, suffix: suffix, kind: "script") else {
                return nil
            }
            return .script(source: source)
        case .streamScript(let scriptBase64):
            guard let source = decodeScript(scriptBase64, suffix: suffix, kind: "streamScript") else {
                return nil
            }
            return .streamScript(source: source)
        case .bodyReplace(let search, let replacement):
            guard let compiled = MITMBodyReplace.compile(search: search, replacement: replacement) else {
                logger.warning("bodyReplace dropped: search is not a valid regex (suffix=\(suffix))")
                return nil
            }
            return .bodyReplace(compiled)
        case .bodyJSON(let operation):
            guard let compiled = MITMJSONPatch.compile(operation) else {
                logger.warning("bodyJSON dropped: malformed JSON path in \(operation.action) (suffix=\(suffix))")
                return nil
            }
            return .bodyJSON(compiled)
        }
    }
    
    private func decodeScript(_ scriptBase64: String, suffix: String, kind: String) -> String? {
        guard let raw = Data(base64Encoded: scriptBase64) else {
            logger.warning("\(kind) invalid base64 (suffix=\(suffix))")
            return nil
        }
        guard let source = String(data: raw, encoding: .utf8) else {
            logger.warning("\(kind) source not valid UTF-8 (suffix=\(suffix))")
            return nil
        }
        return source
    }

    // MARK: - Static-rule validation
    
    private static func isFramingHeader(_ name: String) -> Bool {
        switch name.lowercased() {
        case "content-length", "transfer-encoding",
             "connection", "keep-alive", "proxy-connection", "upgrade", "te", "trailer":
            return true
        default:
            return false
        }
    }
    
    private static func isValidRequestTargetReplacement(_ replacement: String) -> Bool {
        for byte in replacement.utf8 {
            if byte <= 0x20 || byte == 0x7F {
                return false
            }
        }
        return true
    }

    // MARK: - Rewrite compilation
    
    private static func compileRewrite(_ action: MITMRewriteAction, suffix: String) -> CompiledRewriteAction? {
        switch action {
        case .transparent(let url):
            // A `$1`-style target's final URL is only known per request — keep the
            // template and validate the expansion when the gate matches.
            let template = MITMCaptureTemplate(url)
            if template.referencesCaptures {
                return .transparent(.templated(template))
            }
            guard let parsed = parseReplacementURL(url) else {
                logger.warning("rewrite(transparent) dropped: \"\(url)\" is not an absolute URL with a host (suffix=\(suffix))")
                return nil
            }
            guard isValidRequestTargetReplacement(parsed.requestTarget) else {
                logger.warning("rewrite(transparent) dropped: replacement path is not wire-safe (suffix=\(suffix))")
                return nil
            }
            return .transparent(.resolved(parsed))
        case .redirect302(let url):
            let template = MITMCaptureTemplate(url)
            if template.referencesCaptures {
                return .redirect302(.templated(template))
            }
            let trimmed = url.trimmingCharacters(in: .whitespaces)
            guard parseReplacementURL(trimmed) != nil, HTTPHeader.isValidValue(trimmed) else {
                logger.warning("rewrite(302) dropped: \"\(url)\" is not a valid, wire-safe URL (suffix=\(suffix))")
                return nil
            }
            return .redirect302(.location(trimmed))
        case .reject200Text(let content):
            return .reject200Text(content: content)
        case .reject200Gif:
            return .reject200Gif
        case .reject200Data(let base64):
            // Empty → the respond builder substitutes the default payload.
            if !base64.isEmpty, Data(base64Encoded: base64) == nil {
                logger.warning("rewrite(reject-data) dropped: contents are not valid base64 (suffix=\(suffix))")
                return nil
            }
            return .reject200Data(base64: base64)
        }
    }
    
    static func parseReplacementURL(_ raw: String) -> ReplacementURL? {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty,
              let components = URLComponents(string: trimmed),
              let rawHost = components.host, !rawHost.isEmpty else { return nil }
        var host = rawHost
        if host.hasPrefix("["), host.hasSuffix("]"), host.count >= 2 {
            host = String(host.dropFirst().dropLast())
        }
        let port: UInt16?
        if let rawPort = components.port {
            guard let valid = UInt16(exactly: rawPort) else {
                logger.warning("rewrite replacement URL dropped: port \(rawPort) out of range (0–65535)")
                return nil
            }
            port = valid
        } else {
            port = nil
        }
        var target = components.percentEncodedPath
        if target.isEmpty { target = "/" }
        if let query = components.percentEncodedQuery, !query.isEmpty {
            target += "?\(query)"
        }
        return ReplacementURL(host: host, port: port, requestTarget: target)
    }

    // MARK: - Per-request template resolution
    
    static func resolveTransparentTemplate(_ template: MITMCaptureTemplate, captures: [String?]) -> ReplacementURL? {
        let url = template.expand(captures: captures)
        guard let parsed = parseReplacementURL(url),
              isValidRequestTargetReplacement(parsed.requestTarget) else { return nil }
        return parsed
    }
    
    static func resolveRedirectTemplate(_ template: MITMCaptureTemplate, captures: [String?]) -> String? {
        let location = template.expand(captures: captures).trimmingCharacters(in: .whitespaces)
        guard parseReplacementURL(location) != nil, HTTPHeader.isValidValue(location) else { return nil }
        return location
    }
}

// MARK: - Binary deserialization

nonisolated enum MITMBinaryReader {
    static func decode(_ data: Data) -> (enabled: Bool, ruleSets: [MITMRuleSet])? {
        data.withUnsafeBytes { raw -> (enabled: Bool, ruleSets: [MITMRuleSet])? in
            var cursor = Cursor(bytes: raw.bindMemory(to: UInt8.self))
            do {
                return try cursor.readSnapshot()
            } catch {
                logger.report("binary payload decode failed", error: error)
                return nil
            }
        }
    }

    private struct Cursor {
        let bytes: UnsafeBufferPointer<UInt8>
        private var readOffset = 0
        private var count: Int { bytes.count }
        private var version: UInt8 = 0

        init(bytes: UnsafeBufferPointer<UInt8>) { self.bytes = bytes }

        mutating func readSnapshot() throws(AnywhereError) -> (enabled: Bool, ruleSets: [MITMRuleSet]) {
            try expectMagic()
            let payloadVersion = try u8()
            guard payloadVersion >= 1, payloadVersion <= MITMBinaryFormat.version else {
                throw AnywhereError.mitm(.rewriteRulesCorrupted(.unsupportedVersion))
            }
            version = payloadVersion
            let enabled = try u8() != 0
            let setCount = try u32()
            var sets: [MITMRuleSet] = []
            sets.reserveCapacity(Int(min(setCount, 4096)))
            var remaining = setCount
            while remaining > 0 {
                sets.append(try readSet())
                remaining -= 1
            }
            return (enabled, sets)
        }

        private mutating func readSet() throws(AnywhereError) -> MITMRuleSet {
            let id = try readUUID()
            let name = try str16()
            let enabled = try u8() != 0
            let suffixCount = try u16()
            var suffixes: [String] = []
            suffixes.reserveCapacity(Int(suffixCount))
            for _ in 0..<suffixCount { suffixes.append(try str16()) }
            let ruleCount = try u32()
            var rules: [MITMRule] = []
            rules.reserveCapacity(Int(min(ruleCount, UInt32(MITMRuleSet.maxRuleCount))))
            var remaining = ruleCount
            while remaining > 0 {
                rules.append(try readRule())
                remaining -= 1
            }
            // v2: resolved parameter values (name → value). Absent in v1 payloads.
            var parameterValues: [String: String] = [:]
            if version >= 2 {
                let paramCount = try u16()
                parameterValues.reserveCapacity(Int(paramCount))
                for _ in 0..<paramCount {
                    let key = try str16()
                    let value = try str16()
                    parameterValues[key] = value
                }
            }
            var set = MITMRuleSet(id: id, name: name, enabled: enabled,
                                  domainSuffixes: suffixes, rules: rules, subscriptionURL: nil)
            set.parameterValues = parameterValues
            return set
        }

        private mutating func readRule() throws(AnywhereError) -> MITMRule {
            let phase: MITMPhase
            switch try u8() {
            case MITMBinaryFormat.Phase.httpRequest.rawValue: phase = .httpRequest
            case MITMBinaryFormat.Phase.httpResponse.rawValue: phase = .httpResponse
            default: throw AnywhereError.mitm(.rewriteRulesCorrupted(.malformed))
            }
            let urlPattern = try str32()
            return MITMRule(phase: phase, urlPattern: urlPattern, operation: try readOperation())
        }

        private mutating func readOperation() throws(AnywhereError) -> MITMOperation {
            guard let kind = MITMBinaryFormat.OpKind(rawValue: try u8()) else { throw AnywhereError.mitm(.rewriteRulesCorrupted(.malformed)) }
            switch kind {
            case .rewrite:       return .rewrite(try readRewrite())
            case .headerAdd:     return .headerAdd(name: try str16(), value: try str32())
            case .headerDelete:  return .headerDelete(name: try str16())
            case .headerReplace: return .headerReplace(name: try str16(), value: try str32())
            case .script:        return .script(scriptBase64: try str32())
            case .streamScript:  return .streamScript(scriptBase64: try str32())
            case .bodyReplace:   return .bodyReplace(search: try str32(), replacement: try str32())
            case .bodyJSON:      return .bodyJSON(try readJSON())
            }
        }

        private mutating func readRewrite() throws(AnywhereError) -> MITMRewriteAction {
            guard let kind = MITMBinaryFormat.RewriteKind(rawValue: try u8()) else { throw AnywhereError.mitm(.rewriteRulesCorrupted(.malformed)) }
            switch kind {
            case .transparent:   return .transparent(url: try str32())
            case .redirect302:   return .redirect302(url: try str32())
            case .reject200Text: return .reject200Text(content: try str32())
            case .reject200Gif:  return .reject200Gif
            case .reject200Data: return .reject200Data(base64: try str32())
            }
        }

        private mutating func readJSON() throws(AnywhereError) -> MITMJSONOperation {
            guard let action = MITMBinaryFormat.JSONAction(rawValue: try u8()) else { throw AnywhereError.mitm(.rewriteRulesCorrupted(.malformed)) }
            switch action {
            case .add:                  return .add(path: try str32(), value: try str32())
            case .replace:              return .replace(path: try str32(), value: try str32())
            case .delete:               return .delete(path: try str32())
            case .replaceRecursive:     return .replaceRecursive(key: try str32(), value: try str32())
            case .deleteRecursive:      return .deleteRecursive(key: try str32())
            case .removeWhereKeyExists: return .removeWhereKeyExists(path: try str32(), key: try str32())
            case .removeWhereFieldIn:   return .removeWhereFieldIn(path: try str32(), field: try str32(), values: try str32())
            }
        }

        // MARK: Primitives

        private mutating func expectMagic() throws(AnywhereError) {
            let magic = MITMBinaryFormat.magic
            guard readOffset + magic.count <= count else { throw AnywhereError.mitm(.rewriteRulesCorrupted(.truncated)) }
            for k in 0..<magic.count where bytes[readOffset + k] != magic[k] { throw AnywhereError.mitm(.rewriteRulesCorrupted(.badMagic)) }
            readOffset += magic.count
        }

        private mutating func u8() throws(AnywhereError) -> UInt8 {
            guard readOffset < count else { throw AnywhereError.mitm(.rewriteRulesCorrupted(.truncated)) }
            defer { readOffset += 1 }
            return bytes[readOffset]
        }

        private mutating func u16() throws(AnywhereError) -> UInt16 {
            guard readOffset + 2 <= count else { throw AnywhereError.mitm(.rewriteRulesCorrupted(.truncated)) }
            defer { readOffset += 2 }
            return UInt16(bytes[readOffset]) | (UInt16(bytes[readOffset + 1]) << 8)
        }

        private mutating func u32() throws(AnywhereError) -> UInt32 {
            guard readOffset + 4 <= count else { throw AnywhereError.mitm(.rewriteRulesCorrupted(.truncated)) }
            defer { readOffset += 4 }
            return UInt32(bytes[readOffset]) | (UInt32(bytes[readOffset + 1]) << 8)
                 | (UInt32(bytes[readOffset + 2]) << 16) | (UInt32(bytes[readOffset + 3]) << 24)
        }

        private mutating func str16() throws(AnywhereError) -> String {
            let n = Int(try u16())
            guard readOffset + n <= count else { throw AnywhereError.mitm(.rewriteRulesCorrupted(.truncated)) }
            defer { readOffset += n }
            return String(decoding: bytes[readOffset..<readOffset + n], as: UTF8.self)
        }

        private mutating func str32() throws(AnywhereError) -> String {
            let n = Int(try u32())
            guard readOffset + n <= count else { throw AnywhereError.mitm(.rewriteRulesCorrupted(.truncated)) }
            defer { readOffset += n }
            return String(decoding: bytes[readOffset..<readOffset + n], as: UTF8.self)
        }

        private mutating func readUUID() throws(AnywhereError) -> UUID {
            guard readOffset + 16 <= count else { throw AnywhereError.mitm(.rewriteRulesCorrupted(.truncated)) }
            let u = UUID(uuid: (
                bytes[readOffset], bytes[readOffset + 1], bytes[readOffset + 2], bytes[readOffset + 3],
                bytes[readOffset + 4], bytes[readOffset + 5], bytes[readOffset + 6], bytes[readOffset + 7],
                bytes[readOffset + 8], bytes[readOffset + 9], bytes[readOffset + 10], bytes[readOffset + 11],
                bytes[readOffset + 12], bytes[readOffset + 13], bytes[readOffset + 14], bytes[readOffset + 15]
            ))
            readOffset += 16
            return u
        }
    }
}
