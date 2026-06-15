//
//  MITMRewritePolicy.swift
//  Anywhere
//
//  Created by NodePassProject on 5/4/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITMRewritePolicy")

/// One rewrite as the runtime sees it: regexes pre-compiled, header names case-folded.
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

/// A replacement URL parsed once at compile time: host/port for the deferred dial, requestTarget for the start line.
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

/// `transparent` drives the request rewrite + deferred dial; the rest synthesize an inner-leg response.
enum CompiledRewriteAction {
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
    /// JavaScript transform; sourceKey is the compile-cache key, precomputed at
    /// rule load. At most one script fires per message.
    case script(source: String, sourceKey: Int)
    /// Like `script` but invoked per DATA chunk so streaming bodies flow unbuffered; at most one fires per stream.
    case streamScript(source: String, sourceKey: Int)
    /// Native regex find-and-replace over the text body (import op id `4`); matching rules compose in rule order.
    case bodyReplace(search: Regex<AnyRegexOutput>, replacement: String)
    /// Native JSON body edit (import op id `5`); composes in rule order before any script.
    case bodyJSON(MITMJSONPatch.CompiledOp)
}

/// Compiled rule set at one trie terminal; a multi-suffix source set produces one
/// per suffix. `id` is the source set's, used as the stable script-store scope key.
struct CompiledMITMRuleSet {
    let id: UUID
    let domainSuffix: String
    let rules: [CompiledMITMRule]
}

/// Owns compiled MITM rule sets; domain-suffix matching is most-specific-wins via a trie of reversed labels.
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
            logger.debug("[MITM] Loaded \(ruleSets.count) rule set(s); purged \(purged) stale script-store bucket(s)")
        } else {
            logger.debug("[MITM] Loaded \(ruleSets.count) rule set(s)")
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
                logger.warning("[MITM] rule URL pattern failed to compile (suffix=\(set.name)): \(rule.urlPattern)")
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
                logger.warning("[MITM] duplicate domain suffix \"\(suffix)\": rule set \"\(set.name)\" overrides an earlier set's rules for it")
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
                logger.warning("[MITM] headerAdd dropped: invalid header name \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            guard !Self.isFramingHeader(name) else {
                logger.warning("[MITM] headerAdd dropped: \"\(name)\" controls message framing and can't be set by a header rule (suffix=\(suffix))")
                return nil
            }
            guard isValidHTTPHeaderValue(value) else {
                logger.warning("[MITM] headerAdd dropped: CR/LF/NUL in value for header \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            return .headerAdd(name: name, value: value)
        case .headerDelete(let name):
            guard isValidHTTPHeaderName(name) else {
                logger.warning("[MITM] headerDelete dropped: invalid header name \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            return .headerDelete(nameLower: name.lowercased())
        case .headerReplace(let name, let value):
            guard isValidHTTPHeaderName(name) else {
                logger.warning("[MITM] headerReplace dropped: invalid header name \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            guard !Self.isFramingHeader(name) else {
                logger.warning("[MITM] headerReplace dropped: \"\(name)\" controls message framing and can't be set by a header rule (suffix=\(suffix))")
                return nil
            }
            guard isValidHTTPHeaderValue(value) else {
                logger.warning("[MITM] headerReplace dropped: CR/LF/NUL in value for header \"\(name)\" (suffix=\(suffix))")
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
                logger.warning("[MITM] bodyReplace dropped: search is not a valid regex (suffix=\(suffix))")
                return nil
            }
            return .bodyReplace(search: compiled.search, replacement: compiled.replacement)
        case .bodyJSON(let operation):
            guard let compiled = MITMJSONPatch.compile(operation) else {
                logger.warning("[MITM] bodyJSON dropped: malformed JSON path in \(operation.action) (suffix=\(suffix))")
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
            logger.warning("[MITM] \(kind) invalid base64 (suffix=\(suffix))")
            return nil
        }
        guard let source = String(data: raw, encoding: .utf8) else {
            logger.warning("[MITM] \(kind) source not valid UTF-8 (suffix=\(suffix))")
            return nil
        }
        return source
    }

    // MARK: - Static-rule validation
    //
    // Rule sets are untrusted; serializers emit header bytes verbatim, so CR/LF
    // in a value enables response-splitting. Validated once at compile time.

    /// Framing headers (RFC 9112 §6) are blocked for add/replace — divergent framing
    /// is the request-smuggling primitive; delete only makes framing more conservative.
    private static func isFramingHeader(_ name: String) -> Bool {
        let lower = name.lowercased()
        return lower == "content-length" || lower == "transfer-encoding"
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
            guard let parsed = parseReplacementURL(url) else {
                logger.warning("[MITM] rewrite(transparent) dropped: \"\(url)\" is not an absolute URL with a host (suffix=\(suffix))")
                return nil
            }
            guard isValidRequestTargetReplacement(parsed.requestTarget) else {
                logger.warning("[MITM] rewrite(transparent) dropped: replacement path is not wire-safe (suffix=\(suffix))")
                return nil
            }
            return .transparent(parsed)
        case .redirect302(let url):
            // Trim first: isValidHTTPHeaderValue allows SP/HTAB, and stray whitespace in Location trips some clients.
            let trimmed = url.trimmingCharacters(in: .whitespaces)
            guard parseReplacementURL(trimmed) != nil, isValidHTTPHeaderValue(trimmed) else {
                logger.warning("[MITM] rewrite(302) dropped: \"\(url)\" is not a valid, wire-safe URL (suffix=\(suffix))")
                return nil
            }
            return .redirect302(location: trimmed)
        case .reject200Text(let content):
            return .reject200Text(content: content)
        case .reject200Gif:
            return .reject200Gif
        case .reject200Data(let base64):
            // Empty → the respond builder substitutes the default payload.
            if !base64.isEmpty, Data(base64Encoded: base64) == nil {
                logger.warning("[MITM] rewrite(reject-data) dropped: contents are not valid base64 (suffix=\(suffix))")
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
                logger.warning("[MITM] rewrite replacement URL dropped: port \(rawPort) out of range (0–65535)")
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
}
