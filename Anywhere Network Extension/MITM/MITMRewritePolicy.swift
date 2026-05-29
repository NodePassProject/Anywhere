//
//  MITMRewritePolicy.swift
//  Anywhere
//
//  Created by NodePassProject on 5/4/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

/// One rewrite as the runtime sees it: regexes pre-compiled, header
/// names case-folded.
struct CompiledMITMRule {
    let phase: MITMPhase
    /// Pre-compiled URL gate: a regex over the request-target's
    /// path-and-query. The ``operation`` only fires when this matches;
    /// for ``CompiledMITMOperation/urlReplace`` it is also the
    /// substitution regex.
    let patternRegex: NSRegularExpression
    let operation: CompiledMITMOperation
}

extension CompiledMITMRule {
    /// Whether this rule's URL gate matches the given request-target
    /// (path-and-query). A nil target — the URL could not be determined
    /// — fails closed, so the rule is skipped rather than applied blind.
    func matchesURL(_ pathAndQuery: String?) -> Bool {
        guard let pathAndQuery else { return false }
        let range = NSRange(pathAndQuery.startIndex..., in: pathAndQuery)
        return patternRegex.firstMatch(in: pathAndQuery, options: [], range: range) != nil
    }
}

/// Path-and-query extraction for rule gating, shared by the HTTP/1 and
/// HTTP/2 paths and the script transform.
enum MITMRequestURL {
    /// Extracts the request-target (path-and-query) from an absolute URL
    /// string — the same string ``MITMScriptEngine/Message`` exposes as
    /// `ctx.url`. Returns nil for relative or unparseable input so the
    /// gate fails closed.
    static func pathAndQuery(from url: String?) -> String? {
        guard let url, let components = URLComponents(string: url) else { return nil }
        if components.scheme == nil && components.host == nil { return nil }
        var target = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        if let query = components.percentEncodedQuery {
            target += "?\(query)"
        }
        return target
    }
}

enum CompiledMITMOperation {
    case urlReplace(replacement: String)
    case headerAdd(name: String, value: String)
    case headerDelete(nameLower: String)
    /// Overwrites the value of every header named ``name`` (matched
    /// case-insensitively) with ``value``; headers that are absent are
    /// left untouched.
    case headerReplace(name: String, value: String)
    /// JavaScript transform. ``source`` is the decoded UTF-8 source of
    /// `function process(ctx)`. Compilation/execution belongs to
    /// ``MITMScriptEngine`` so the policy stays free of JSContext.
    ///
    /// ``sourceKey`` is a precomputed identifier the engine uses as
    /// the compile cache key. Hashing the full source on every JS call
    /// would otherwise be the dominant cost for large scripts (think
    /// 100 KB) since ``[String: JSValue]`` walks every byte on lookup.
    /// Computed once at rule-load time via ``Hasher`` so identical
    /// sources share the same cache entry within a process.
    ///
    /// Although the policy compiles every script rule a user declares,
    /// only one ``.script`` (and one ``.streamScript``) fires per
    /// message — this is a deliberate design choice for performance
    /// and efficiency, not a limitation. The runtime selection lives
    /// in ``MITMScriptTransform``.
    case script(source: String, sourceKey: Int)
    /// Per-frame JavaScript transform. Same runtime contract as
    /// ``script`` for ctx fields the script reads, but the function is
    /// invoked once per DATA frame (HTTP/2) or per chunk (HTTP/1
    /// chunked) and only ``ctx.body`` is read back. Used to keep
    /// streaming-style bodies flowing without buffering the entire
    /// response.
    ///
    /// Single-rule runtime semantics apply (see ``.script`` above):
    /// at most one ``.streamScript`` runs per stream by design.
    case streamScript(source: String, sourceKey: Int)
}

/// Compiled view of a rule set at one trie terminal: the specific suffix
/// reached, the optional upstream redirect, and rules ready to apply. A
/// source set with multiple suffixes produces one of these per suffix,
/// each sharing the same compiled rules and target. ``id`` is copied
/// from the source ``MITMRuleSet`` so the runtime can use it as a
/// stable scope key for ``MITMScriptStore``.
struct CompiledMITMRuleSet {
    let id: UUID
    let domainSuffix: String
    let rewriteTarget: MITMRewriteTarget?
    let rules: [CompiledMITMRule]
}

/// Owns configured MITM rule sets in compiled form. Decides:
///   - whether a given SNI/destination host should be intercepted
///     (``matches``), driving the lwIP-side branch into ``MITMSession``;
///   - which set's rules apply for a host (``set(for:)``), consumed by
///     the HTTP/1.1 and HTTP/2 rewriters.
///
/// Domain suffix matching is **most-specific-win**: when both
/// `example.com` and `api.example.com` are configured, a request to
/// `api.example.com` selects only the latter set's rules and target.
/// A trie of reversed labels enforces that ordering.
final class MITMRewritePolicy {

    private var trie = FlatLabelTrie<CompiledMITMRuleSet>()
    private var setCount: Int = 0

    /// Guards ``trie`` + ``setCount``. ``matches`` / ``set(for:)`` are now read
    /// from both ``lwipQueue`` (TCP accept) and ``udpQueue`` (UDP/443 new-flow),
    /// while ``load`` / ``reset`` rebuild the trie on ``lwipQueue`` at config
    /// change. The reload holds the lock across the rebuild so a lookup never
    /// sees a half-built trie; lookups take it briefly. Reads are cold (per
    /// connection / new flow), never per-packet, so the lock stays uncontended.
    private let lock = UnfairLock()

    /// Whether any rule sets have been loaded. Used by the lwIP path so
    /// the no-op case stays at a single bool check.
    var hasRules: Bool { lock.withLock { setCount > 0 } }

    func reset() {
        lock.withLock { resetUnlocked() }
    }

    /// Clears the trie. Caller must hold ``lock``.
    private func resetUnlocked() {
        trie = FlatLabelTrie<CompiledMITMRuleSet>()
        setCount = 0
    }

    /// Replaces the in-memory rule set table from a typed
    /// ``MITMSnapshot``. Suffixes that are empty are skipped silently;
    /// a set with no usable suffixes contributes nothing. Rules whose
    /// regex fails to compile are dropped with a log line; the rest of
    /// the set still applies.
    ///
    /// Conflict handling: if two sets declare the same suffix, the
    /// later one wins (with a warning).
    func load(ruleSets: [MITMRuleSet]) {
        // Build under the lock so a concurrent lookup never sees a half-built
        // trie. The script-store purge + logging below touch a different shared
        // store and don't need this lock, so they run after release.
        var scopedRules: [(scope: UUID, rules: [CompiledMITMRule])] = []
        lock.withLock {
            resetUnlocked()
            for set in ruleSets {
                // Disabled sets are never compiled into the trie, so they
                // match no traffic until re-enabled. They still count toward
                // `activeIDs` below, so toggling a set off (vs. removing it)
                // keeps its script-store bucket — "cleared only on removal".
                guard set.enabled else { continue }
                if let compiled = insertUnlocked(set) {
                    scopedRules.append((scope: set.id, rules: compiled))
                }
            }
            trie.freeze()
        }
        // Drop per-rule-set state for sets the user deleted since the
        // last load: the shared ``MITMScriptEngine`` (its JSContext +
        // compiled-function cache) and the ``MITMScriptStore`` bucket (up
        // to ``MITMScriptStore.maxBytesPerScope``). Both are keyed by
        // rule-set id and would otherwise linger until the Network
        // Extension recycles — a real drift for users who iterate on rule
        // sets during development. In-memory script state survives an edit
        // (the id is stable) and is cleared only on removal.
        let activeIDs = Set(ruleSets.map { $0.id })
        MITMScriptEngine.purgeEngines(activeIDs: activeIDs)
        // Prewarm the JS engine + compile cache for script-bearing sets so
        // the first intercepted flow that triggers a script doesn't pay the
        // cold start inline (see ``MITMScriptTransform/prewarm``). Runs after
        // the purge so it only builds engines for sets still active.
        MITMScriptTransform.prewarm(scopedRules: scopedRules)
        let purged = MITMScriptStore.shared.purgeExcept(activeIDs: activeIDs)
        if purged > 0 {
            logger.debug("[MITM] Loaded \(ruleSets.count) rule set(s); purged \(purged) stale script-store bucket(s)")
        } else {
            logger.debug("[MITM] Loaded \(ruleSets.count) rule set(s)")
        }
    }

    /// Inserts one rule set, returning its compiled rules — or nil when the
    /// set had no usable domain suffix and was skipped — so ``load`` can
    /// prewarm the script engine for it. Caller must hold ``lock`` (invoked
    /// only from ``load`` while building the trie).
    private func insertUnlocked(_ set: MITMRuleSet) -> [CompiledMITMRule]? {
        let suffixes = set.domainSuffixes
            .map { $0.lowercased().trimmingCharacters(in: CharacterSet.whitespaces) }
            .filter { !$0.isEmpty }
        guard !suffixes.isEmpty else { return nil }

        let compiledRules = set.rules.compactMap { rule -> CompiledMITMRule? in
            guard let regex = try? NSRegularExpression(pattern: rule.pattern, options: []) else {
                logger.warning("[MITM] rule pattern failed to compile (suffix=\(set.name)): \(rule.pattern)")
                return nil
            }
            guard let op = compile(rule.operation, suffix: set.name) else { return nil }
            return CompiledMITMRule(phase: rule.phase, patternRegex: regex, operation: op)
        }

        // Synthesize-response actions (reject_200 / redirect_302) bypass
        // the rewriter pipeline entirely and write a canned reply on the
        // inner leg, so any header / URL / script rules in the same set
        // never fire. Flag the mismatch at load time so users notice
        // before debugging "why isn't my script running"; the rule set
        // is still installed (the synthesize action remains useful).
        if let target = set.rewriteTarget, target.action.synthesizesResponse, !set.rules.isEmpty {
            logger.warning("[MITM] Rule set \"\(set.name)\" combines action=\(target.action.rawValue) with \(set.rules.count) rule(s); rules will not fire (action synthesizes the response)")
        }

        for suffix in suffixes {
            let payload = CompiledMITMRuleSet(
                id: set.id,
                domainSuffix: suffix,
                rewriteTarget: set.rewriteTarget,
                rules: compiledRules
            )
            if trie.insert(suffix: suffix, payload: payload) {
                setCount += 1
            }
        }
        return compiledRules
    }

    /// Returns `true` when the hostname is covered by any rule set. Empty
    /// input always returns `false`.
    func matches(_ host: String) -> Bool {
        set(for: host) != nil
    }

    /// Returns the most-specific rule set that covers ``host``, or nil
    /// if no set applies. Walks the label trie greedily; the deepest
    /// terminal reached during descent is the most-specific match.
    func set(for host: String) -> CompiledMITMRuleSet? {
        guard !host.isEmpty else { return nil }
        var lowered = host.lowercased()
        return lock.withLock { () -> CompiledMITMRuleSet? in
            guard setCount > 0 else { return nil }
            return lowered.withUTF8 { trie.lookup($0) }
        }
    }

    /// Convenience for the rewriters: rules from the most-specific set
    /// matching ``host``, filtered to ``phase`` and stored insertion order.
    /// Empty when no set matches.
    func rules(for host: String, phase: MITMPhase) -> [CompiledMITMRule] {
        guard let set = set(for: host) else { return [] }
        return set.rules.filter { $0.phase == phase }
    }

    /// Convenience for ``TCPConnection`` and ``MITMSession``: the
    /// upstream redirect for a host, if any.
    func rewriteTarget(for host: String) -> MITMRewriteTarget? {
        set(for: host)?.rewriteTarget
    }

    // MARK: - Compilation

    private func compile(_ operation: MITMOperation, suffix: String) -> CompiledMITMOperation? {
        switch operation {
        case .urlReplace(let replacement):
            guard Self.isValidRequestTargetTemplate(replacement) else {
                logger.warning("[MITM] urlReplace dropped: replacement contains whitespace or control bytes (suffix=\(suffix))")
                return nil
            }
            return .urlReplace(replacement: replacement)
        case .headerAdd(let name, let value):
            guard Self.isValidHeaderName(name) else {
                logger.warning("[MITM] headerAdd dropped: invalid header name \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            guard Self.isValidHeaderValue(value) else {
                logger.warning("[MITM] headerAdd dropped: CR/LF/NUL in value for header \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            return .headerAdd(name: name, value: value)
        case .headerDelete(let name):
            guard Self.isValidHeaderName(name) else {
                logger.warning("[MITM] headerDelete dropped: invalid header name \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            return .headerDelete(nameLower: name.lowercased())
        case .headerReplace(let name, let value):
            guard Self.isValidHeaderName(name) else {
                logger.warning("[MITM] headerReplace dropped: invalid header name \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            guard Self.isValidHeaderValue(value) else {
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
        }
    }

    /// Produces the compile-cache key for a script source. Mixes both
    /// the source bytes and the length into the hash so two distinct
    /// sources of the same length still take different cache slots
    /// even on the (vanishingly rare) ``Hasher`` byte-content
    /// collision. Within a process Swift's hasher is stable, which is
    /// all the engine needs — caches are per-session and the seed
    /// only has to be consistent for the engine's lifetime.
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
    // Rule sets imported from third-party URLs (see ``ImportMITMRuleSetView``)
    // are untrusted input by the time they reach this policy. The wire
    // serializers — both HTTP/1's ``MITMHTTP1Stream.serializeHead`` and
    // HTTP/2's HPACK encoder — emit header bytes verbatim, so a rule
    // with CR/LF in a header value would split the response head
    // (response-splitting) on HTTP/1 or trip the receiver's HPACK
    // validator on HTTP/2. Validation lives here, at rule-compile
    // time, so an offending rule is dropped once with a logged
    // diagnostic rather than checked again on every intercepted
    // message. The script-side helpers (``Anywhere.respond``,
    // ``ctx.headers``) already do the same check inside
    // ``MITMScriptEngine``; this closes the gap for statically-
    // configured rules.

    /// RFC 9110 §5.6.2: header field-name and method token alphabet.
    /// Duplicated from the wire layers rather than shared via a helper
    /// type so the policy stays dependency-free of them.
    private static func isValidHeaderName(_ name: String) -> Bool {
        guard !name.isEmpty else { return false }
        for byte in name.utf8 {
            switch byte {
            case 0x21, 0x23, 0x24, 0x25, 0x26, 0x27,
                 0x2A, 0x2B, 0x2D, 0x2E,
                 0x5E, 0x5F, 0x60, 0x7C, 0x7E:
                continue
            case 0x30...0x39, 0x41...0x5A, 0x61...0x7A:
                continue
            default:
                return false
            }
        }
        return true
    }

    /// RFC 9110 §5.5: header field-value must not contain CR / LF /
    /// NUL — those bytes are exactly what splits a wire message into
    /// two.
    private static func isValidHeaderValue(_ value: String) -> Bool {
        for byte in value.utf8 {
            if byte == 0x0D || byte == 0x0A || byte == 0x00 {
                return false
            }
        }
        return true
    }

    /// Conservative check for an ``urlReplace`` replacement template.
    /// The template becomes the new request-target (HTTP/1 start line
    /// or HTTP/2 ``:path``) once regex substitution runs; allowing
    /// SP / HTAB / CR / LF / NUL / DEL would either break HTTP/1's
    /// SP-delimited start line or be rejected by HTTP/2 receivers.
    /// Empty replacements pass — deleting a matched substring is
    /// legitimate.
    private static func isValidRequestTargetTemplate(_ replacement: String) -> Bool {
        for byte in replacement.utf8 {
            if byte <= 0x20 || byte == 0x7F {
                return false
            }
        }
        return true
    }
}
