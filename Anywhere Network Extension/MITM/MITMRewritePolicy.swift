//
//  MITMRewritePolicy.swift
//  Anywhere
//
//  Created by NodePassProject on 5/4/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITMRewritePolicy")

/// Runtime form: regexes pre-compiled, header names case-folded.
struct CompiledMITMRule {
    let phase: MITMPhase
    /// Regex over the whole request URL; bounded so a ReDoS pattern can't stall the tunnel.
    let gate: MITMGateRegex
    let operation: CompiledMITMOperation
}

extension CompiledMITMRule {
    /// Over-long URLs fail closed without running the matcher.
    static let maxGateURLLength = 8 * 1024

    /// Whether the gate matches the URL. The gate is unanchored; the host is lowercased
    /// before matching (RFC 3986), path/query keep case; nil/over-long URLs fail closed.
    func matchesURL(_ url: String?) -> Bool {
        guard let url, url.utf16.count <= Self.maxGateURLLength else { return false }
        return gate.matches(Self.lowercasingHost(url))
    }

    /// Lowercases only the authority, leaving path/query untouched.
    private static func lowercasingHost(_ url: String) -> String {
        guard let sep = url.range(of: "://") else { return url }
        let authStart = sep.upperBound
        let authEnd = url[authStart...].firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) ?? url.endIndex
        var authority = url[authStart..<authEnd].lowercased()
        // Strip a trailing FQDN dot (an SNI may carry one) — URL side only;
        // in a pattern a trailing `.` is the any-char metacharacter.
        if authority.hasSuffix(".") { authority.removeLast() }
        return url[..<authStart].lowercased() + authority + String(url[authEnd...])
    }
}

extension CompiledMITMRule {
    /// Capture groups from the gate match (index 0 = whole match), or nil on no match /
    /// over-long. Mirrors ``matchesURL(_:)``'s host normalization so a templated rewrite
    /// captures from the same string the gate matched.
    func capturesForURL(_ url: String?) -> [String?]? {
        guard let url, url.utf16.count <= Self.maxGateURLLength else { return nil }
        return gate.firstMatchCaptures(Self.lowercasingHost(url))
    }

    /// Resolves this rule's rewrite action for `url`, expanding any capture template.
    /// nil when the operation isn't a rewrite, the gate doesn't match, or a templated
    /// target expands to an invalid URL (rule then no-ops). Static targets reuse their
    /// compile-time parse.
    func resolvedRewriteAction(for url: String?) -> ResolvedRewriteAction? {
        guard case .rewrite(let action) = operation else { return nil }
        switch action {
        case .transparent(.resolved(let replacement)):
            return matchesURL(url) ? .transparent(replacement) : nil
        case .transparent(.templated(let template)):
            guard let captures = capturesForURL(url),
                  let replacement = MITMRewritePolicy.resolveTransparentTemplate(template, captures: captures)
            else { return nil }
            return .transparent(replacement)
        case .redirect302(.location(let location)):
            return matchesURL(url) ? .redirect302(location: location) : nil
        case .redirect302(.templated(let template)):
            guard let captures = capturesForURL(url),
                  let location = MITMRewritePolicy.resolveRedirectTemplate(template, captures: captures)
            else { return nil }
            return .redirect302(location: location)
        case .reject200Text(let content):
            return matchesURL(url) ? .reject200Text(content: content) : nil
        case .reject200Gif:
            return matchesURL(url) ? .reject200Gif : nil
        case .reject200Data(let base64):
            return matchesURL(url) ? .reject200Data(base64: base64) : nil
        }
    }
}

/// Replacement URL parsed once at compile time: host/port for the dial, requestTarget for the start line.
struct ReplacementURL: Equatable {
    /// IPv6 URI brackets stripped, matching the form the resolver expects.
    let host: String
    let port: UInt16?
    /// path+query in origin form; `/` when the URL carries no path.
    let requestTarget: String

    /// RFC 9112 §3.2 authority: bare host (IPv6 re-bracketed), or `host:port` when a port was given.
    var authority: String {
        let h = host.contains(":") ? "[\(host)]" : host
        if let port { return "\(h):\(port)" }
        return h
    }
}

/// Transparent rewrite target: parsed at compile time, or a per-request capture template.
enum TransparentTarget {
    case resolved(ReplacementURL)
    case templated(MITMCaptureTemplate)
}

/// 302 `Location` target: validated literal, or a per-request capture template.
enum RedirectTarget {
    case location(String)
    case templated(MITMCaptureTemplate)
}

/// `transparent` drives the request rewrite + deferred dial; the rest synthesize an
/// inner-leg response. transparent/302 targets may carry a `$1`-style capture template.
enum CompiledRewriteAction {
    case transparent(TransparentTarget)
    case redirect302(RedirectTarget)
    case reject200Text(content: String)
    case reject200Gif
    case reject200Data(base64: String)
}

/// Rewrite action with every capture template expanded for one specific request.
enum ResolvedRewriteAction {
    case transparent(ReplacementURL)
    case redirect302(location: String)
    case reject200Text(content: String)
    case reject200Gif
    case reject200Data(base64: String)
}

enum CompiledMITMOperation {
    case rewrite(CompiledRewriteAction)
    case headerAdd(name: String, value: String)
    case headerDelete(nameLower: String)
    /// Overwrites every matching header (case-insensitive); absent headers are left untouched.
    case headerReplace(name: String, value: String)
    /// JavaScript transform; sourceKey is the compile-cache key. At most one script fires per message.
    case script(source: String, sourceKey: Int)
    /// Like `script` but invoked per DATA chunk so streaming bodies flow unbuffered; at most one fires per stream.
    case streamScript(source: String, sourceKey: Int)
    /// Regex find-and-replace over the text body (import op id `4`); matching rules compose in rule order.
    case bodyReplace(MITMBodyReplace.CompiledOp)
    /// JSON body edit (import op id `5`); composes in rule order before any script.
    case bodyJSON(MITMJSONPatch.CompiledOp)
}

/// Compiled rule set at one trie terminal (one per suffix). `id` is the source set's,
/// used as the stable script-store scope key.
struct CompiledMITMRuleSet {
    let id: UUID
    let domainSuffix: String
    let rules: [CompiledMITMRule]
}

/// Domain-suffix matching is most-specific-wins via a trie of reversed labels.
final class MITMRewritePolicy {

    private var trie = FlatLabelTrie<CompiledMITMRuleSet>()
    private var setCount: Int = 0

    /// Guards trie + setCount; reload holds it across the full rebuild so lookups never see a half-built trie.
    private let lock = UnfairLock()

    /// lwIP fast path: keeps the no-rules case at a single bool check.
    var hasRules: Bool { lock.withLock { setCount > 0 } }

    func reset() {
        lock.withLock { resetUnlocked() }
    }

    /// Caller must hold `lock`.
    private func resetUnlocked() {
        trie = FlatLabelTrie<CompiledMITMRuleSet>()
        setCount = 0
    }

    /// Replaces the rule set table. Bad rules are dropped (logged) without
    /// dropping their set; on duplicate suffixes the later set wins.
    func load(ruleSets: [MITMRuleSet]) {
        var scopedRules: [(scope: UUID, rules: [CompiledMITMRule])] = []
        lock.withLock {
            resetUnlocked()
            for set in ruleSets {
                // Disabled sets stay in activeIDs so toggling off preserves the script-store bucket.
                guard set.enabled else { continue }
                if let compiled = insertUnlocked(set) {
                    scopedRules.append((scope: set.id, rules: compiled))
                }
            }
            trie.freeze()
        }
        // Purge JS engine state for deleted sets; edited sets (stable id) keep theirs.
        let activeIDs = Set(ruleSets.map { $0.id })
        MITMScriptEngine.purgeEngines(activeIDs: activeIDs)
        // Prewarm compile caches so the first intercepted flow doesn't pay cold-start inline.
        MITMScriptTransform.prewarm(scopedRules: scopedRules)
        let purged = MITMScriptStore.shared.purgeExcept(activeIDs: activeIDs)
        if purged > 0 {
            logger.debug("Loaded \(ruleSets.count) rule set(s); purged \(purged) stale script-store bucket(s)")
        } else {
            logger.debug("Loaded \(ruleSets.count) rule set(s)")
        }
    }

    /// Inserts one rule set and returns its compiled rules, or nil without a usable suffix. Caller must hold `lock`.
    private func insertUnlocked(_ set: MITMRuleSet) -> [CompiledMITMRule]? {
        let suffixes = set.domainSuffixes
            .map { $0.lowercased().trimmingCharacters(in: CharacterSet.whitespaces) }
            .filter { !$0.isEmpty }
        guard !suffixes.isEmpty else { return nil }

        let compiledRules = set.rules.compactMap { rule -> CompiledMITMRule? in
            guard let gate = MITMGateRegex(pattern: rule.urlPattern) else {
                logger.warning("rule URL pattern failed to compile (suffix=\(set.name)): \(rule.urlPattern)")
                return nil
            }
            guard let op = compile(rule.operation, suffix: set.name) else { return nil }
            return CompiledMITMRule(phase: rule.phase, gate: gate, operation: op)
        }

        for suffix in suffixes {
            let payload = CompiledMITMRuleSet(
                id: set.id,
                domainSuffix: suffix,
                rules: compiledRules
            )
            if trie.insert(suffix: suffix, payload: payload) {
                setCount += 1
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

    /// Returns the most-specific rule set covering ``host``, or nil.
    func set(for host: String) -> CompiledMITMRuleSet? {
        guard !host.isEmpty else { return nil }
        var lowered = host.lowercased()
        return lock.withLock { () -> CompiledMITMRuleSet? in
            guard setCount > 0 else { return nil }
            return lowered.withUTF8 { trie.lookup($0) }
        }
    }

    /// Rules from the most-specific set matching ``host``, filtered to ``phase``.
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
            guard isValidHTTPHeaderName(name) else {
                logger.warning("headerAdd dropped: invalid header name \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            guard !Self.isFramingHeader(name) else {
                logger.warning("headerAdd dropped: \"\(name)\" controls message framing and can't be set by a header rule (suffix=\(suffix))")
                return nil
            }
            guard isValidHTTPHeaderValue(value) else {
                logger.warning("headerAdd dropped: CR/LF/NUL in value for header \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            return .headerAdd(name: name, value: value)
        case .headerDelete(let name):
            guard isValidHTTPHeaderName(name) else {
                logger.warning("headerDelete dropped: invalid header name \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            return .headerDelete(nameLower: name.lowercased())
        case .headerReplace(let name, let value):
            guard isValidHTTPHeaderName(name) else {
                logger.warning("headerReplace dropped: invalid header name \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            guard !Self.isFramingHeader(name) else {
                logger.warning("headerReplace dropped: \"\(name)\" controls message framing and can't be set by a header rule (suffix=\(suffix))")
                return nil
            }
            guard isValidHTTPHeaderValue(value) else {
                logger.warning("headerReplace dropped: CR/LF/NUL in value for header \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            return .headerReplace(name: name, value: value)
        case .script(let scriptBase64):
            guard let source = decodeScript(scriptBase64, suffix: suffix, kind: "script") else {
                return nil
            }
            return .script(source: source, sourceKey: sourceCacheKey(source))
        case .streamScript(let scriptBase64):
            guard let source = decodeScript(scriptBase64, suffix: suffix, kind: "streamScript") else {
                return nil
            }
            return .streamScript(source: source, sourceKey: sourceCacheKey(source))
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

    /// Compile-cache key; the per-process hasher seed is fine — caches never cross processes.
    private func sourceCacheKey(_ source: String) -> Int {
        var hasher = Hasher()
        hasher.combine(source.utf8.count)
        hasher.combine(source)
        return hasher.finalize()
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
    //
    // Rule sets are untrusted; serializers emit header bytes verbatim, so CR/LF in a
    // value enables response-splitting. Validated once at compile time.

    /// Framing (RFC 9112 §6) and connection-management headers are blocked for add/replace:
    /// divergent framing is the request-smuggling primitive, and an injected token desyncs
    /// keep-alive (the h1 leg doesn't strip hop-by-hop, so it reaches upstream). Delete only
    /// makes framing more conservative, so it stays allowed.
    private static func isFramingHeader(_ name: String) -> Bool {
        switch name.lowercased() {
        case "content-length", "transfer-encoding",
             "connection", "keep-alive", "proxy-connection", "upgrade", "te", "trailer":
            return true
        default:
            return false
        }
    }

    /// SP/HTAB/CR/LF/NUL/DEL would break HTTP/1's start line or be rejected by HTTP/2 receivers.
    private static func isValidRequestTargetReplacement(_ replacement: String) -> Bool {
        for byte in replacement.utf8 {
            if byte <= 0x20 || byte == 0x7F {
                return false
            }
        }
        return true
    }

    // MARK: - Rewrite compilation

    /// Returns nil to drop the rule with a logged diagnostic.
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
            // Trim first: isValidHTTPHeaderValue allows SP/HTAB, and stray whitespace in Location trips some clients.
            let trimmed = url.trimmingCharacters(in: .whitespaces)
            guard parseReplacementURL(trimmed) != nil, isValidHTTPHeaderValue(trimmed) else {
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

    /// Parses a replacement URL into dial + request-target parts; requires an absolute URL with a host.
    static func parseReplacementURL(_ raw: String) -> ReplacementURL? {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty,
              let comps = URLComponents(string: trimmed),
              let rawHost = comps.host, !rawHost.isEmpty else { return nil }
        // Strip IPv6 URI brackets for the dial; `authority` re-adds them.
        var host = rawHost
        if host.hasPrefix("["), host.hasSuffix("]"), host.count >= 2 {
            host = String(host.dropFirst().dropLast())
        }
        // An out-of-range port drops the rule rather than silently falling back to the scheme default.
        let port: UInt16?
        if let rawPort = comps.port {
            guard let valid = UInt16(exactly: rawPort) else {
                logger.warning("rewrite replacement URL dropped: port \(rawPort) out of range (0–65535)")
                return nil
            }
            port = valid
        } else {
            port = nil
        }
        var target = comps.percentEncodedPath
        if target.isEmpty { target = "/" }
        if let query = comps.percentEncodedQuery, !query.isEmpty {
            target += "?\(query)"
        }
        return ReplacementURL(host: host, port: port, requestTarget: target)
    }

    // MARK: - Per-request template resolution

    /// Expands a transparent target template, then parses and wire-safety-checks the result.
    /// nil (rule no-ops) when the expansion isn't an absolute URL with a host, or the path
    /// isn't wire-safe.
    static func resolveTransparentTemplate(_ template: MITMCaptureTemplate, captures: [String?]) -> ReplacementURL? {
        let url = template.expand(captures: captures)
        guard let parsed = parseReplacementURL(url),
              isValidRequestTargetReplacement(parsed.requestTarget) else { return nil }
        return parsed
    }

    /// Expands a 302 target template, then trims and validates it as a wire-safe `Location`.
    /// nil leaves the rule a no-op for this request.
    static func resolveRedirectTemplate(_ template: MITMCaptureTemplate, captures: [String?]) -> String? {
        let location = template.expand(captures: captures).trimmingCharacters(in: .whitespaces)
        guard parseReplacementURL(location) != nil, isValidHTTPHeaderValue(location) else { return nil }
        return location
    }
}

// MARK: - Binary deserialization

/// Decodes the `AMR1` MITM blob the host exports back into `MITMRuleSet` models.
enum MITMBinaryReader {
    private enum ReadError: Error { case badMagic, badVersion, truncated, malformed }

    /// nil on bad magic/version/truncation.
    static func decode(_ data: Data) -> (enabled: Bool, ruleSets: [MITMRuleSet])? {
        data.withUnsafeBytes { raw -> (enabled: Bool, ruleSets: [MITMRuleSet])? in
            var cursor = Cursor(bytes: raw.bindMemory(to: UInt8.self))
            do {
                return try cursor.readSnapshot()
            } catch {
                logger.warning("binary payload decode failed: \(error)")
                return nil
            }
        }
    }

    private struct Cursor {
        let bytes: UnsafeBufferPointer<UInt8>
        private var i = 0
        private var count: Int { bytes.count }

        init(bytes: UnsafeBufferPointer<UInt8>) { self.bytes = bytes }

        mutating func readSnapshot() throws -> (enabled: Bool, ruleSets: [MITMRuleSet]) {
            try expectMagic()
            guard try u8() == MITMBinaryFormat.version else { throw ReadError.badVersion }
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

        private mutating func readSet() throws -> MITMRuleSet {
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
            return MITMRuleSet(id: id, name: name, enabled: enabled,
                               domainSuffixes: suffixes, rules: rules, subscriptionURL: nil)
        }

        private mutating func readRule() throws -> MITMRule {
            let phase: MITMPhase
            switch try u8() {
            case MITMBinaryFormat.Phase.httpRequest.rawValue: phase = .httpRequest
            case MITMBinaryFormat.Phase.httpResponse.rawValue: phase = .httpResponse
            default: throw ReadError.malformed
            }
            let urlPattern = try str32()
            return MITMRule(phase: phase, urlPattern: urlPattern, operation: try readOperation())
        }

        private mutating func readOperation() throws -> MITMOperation {
            guard let kind = MITMBinaryFormat.OpKind(rawValue: try u8()) else { throw ReadError.malformed }
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

        private mutating func readRewrite() throws -> MITMRewriteAction {
            guard let kind = MITMBinaryFormat.RewriteKind(rawValue: try u8()) else { throw ReadError.malformed }
            switch kind {
            case .transparent:   return .transparent(url: try str32())
            case .redirect302:   return .redirect302(url: try str32())
            case .reject200Text: return .reject200Text(content: try str32())
            case .reject200Gif:  return .reject200Gif
            case .reject200Data: return .reject200Data(base64: try str32())
            }
        }

        private mutating func readJSON() throws -> MITMJSONOperation {
            guard let action = MITMBinaryFormat.JSONAction(rawValue: try u8()) else { throw ReadError.malformed }
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

        private mutating func expectMagic() throws {
            let magic = MITMBinaryFormat.magic
            guard i + magic.count <= count else { throw ReadError.truncated }
            for k in 0..<magic.count where bytes[i + k] != magic[k] { throw ReadError.badMagic }
            i += magic.count
        }

        private mutating func u8() throws -> UInt8 {
            guard i < count else { throw ReadError.truncated }
            defer { i += 1 }
            return bytes[i]
        }

        private mutating func u16() throws -> UInt16 {
            guard i + 2 <= count else { throw ReadError.truncated }
            defer { i += 2 }
            return UInt16(bytes[i]) | (UInt16(bytes[i + 1]) << 8)
        }

        private mutating func u32() throws -> UInt32 {
            guard i + 4 <= count else { throw ReadError.truncated }
            defer { i += 4 }
            return UInt32(bytes[i]) | (UInt32(bytes[i + 1]) << 8)
                 | (UInt32(bytes[i + 2]) << 16) | (UInt32(bytes[i + 3]) << 24)
        }

        private mutating func str16() throws -> String {
            let n = Int(try u16())
            guard i + n <= count else { throw ReadError.truncated }
            defer { i += n }
            return String(decoding: bytes[i..<i + n], as: UTF8.self)
        }

        private mutating func str32() throws -> String {
            let n = Int(try u32())
            guard i + n <= count else { throw ReadError.truncated }
            defer { i += n }
            return String(decoding: bytes[i..<i + n], as: UTF8.self)
        }

        private mutating func readUUID() throws -> UUID {
            guard i + 16 <= count else { throw ReadError.truncated }
            let u = UUID(uuid: (bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3],
                                bytes[i + 4], bytes[i + 5], bytes[i + 6], bytes[i + 7],
                                bytes[i + 8], bytes[i + 9], bytes[i + 10], bytes[i + 11],
                                bytes[i + 12], bytes[i + 13], bytes[i + 14], bytes[i + 15]))
            i += 16
            return u
        }
    }
}
