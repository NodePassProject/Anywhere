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
    /// Pre-compiled gate: a regex over the whole request URL. The
    /// ``operation`` only fires when this matches — it is purely a gate.
    /// Matching is bounded and memoized via ``MITMGateRegex`` so an untrusted
    /// catastrophic-backtracking pattern can't stall the tunnel (ReDoS).
    let gate: MITMGateRegex
    let operation: CompiledMITMOperation
}

extension CompiledMITMRule {
    /// Cap on the URL length the gate regex is run against. Real request URLs
    /// are far shorter; an over-long one fails closed (unmatched) without
    /// running the matcher at all — a cheap first bound on per-match work. The
    /// real ReDoS containment, keeping an untrusted catastrophic-backtracking
    /// pattern from running unbounded on the serial lwIP queue, lives in
    /// ``MITMGateRegex``; this cap only limits the input that reaches it.
    static let maxGateURLLength = 8 * 1024

    /// Whether this rule's gate matches the given request URL. The gate is an
    /// **unanchored substring** regex over the whole `https://host/path?query`
    /// — e.g. `/admin` matches anywhere in the URL, so anchor with `^…$` in the
    /// pattern to pin it. The **host** is matched case-insensitively (lowercased
    /// here, mirroring the host trie), so a lowercase-host pattern matches
    /// regardless of the SNI's case; the path/query keep their case (RFC 3986
    /// paths are case-sensitive). A nil or over-long URL fails closed, so the
    /// rule is skipped rather than applied blind.
    func matchesURL(_ url: String?) -> Bool {
        guard let url, url.utf16.count <= Self.maxGateURLLength else { return false }
        // Delegate to the bounded, memoized gate so an untrusted
        // catastrophic-backtracking pattern can't run unbounded on the lwIP
        // queue and freeze the tunnel. The host is lowercased here (the gate's
        // memo keys on this normalized form).
        return gate.matches(Self.lowercasingHost(url))
    }

    /// Lowercases only the authority (`host[:port]`) of a `scheme://authority/…`
    /// URL, leaving the path/query untouched. The gate URLs this sees are
    /// always `https://host/target` with no userinfo, so lowercasing the whole
    /// authority is safe.
    private static func lowercasingHost(_ url: String) -> String {
        guard let sep = url.range(of: "://") else { return url }
        let authStart = sep.upperBound
        let authEnd = url[authStart...].firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) ?? url.endIndex
        return url[..<authStart].lowercased() + url[authStart..<authEnd].lowercased() + String(url[authEnd...])
    }
}

/// A replacement URL parsed once at compile time, split into the parts the
/// rewriters need: the upstream ``host``/``port`` (for the deferred dial and
/// the `Host`/`:authority` rewrite) and the origin-form ``requestTarget``
/// (path+query) spliced onto the HTTP/1 start line or the HTTP/2 `:path`.
struct ReplacementURL: Equatable {
    /// Upstream host for the dial, with any IPv6 URI brackets stripped so it
    /// matches the form the connect layer's resolver expects.
    let host: String
    let port: UInt16?
    /// path+query in origin form; `/` when the URL carries no path.
    let requestTarget: String

    /// RFC 9112 §3.2 authority for the Host / `:authority` rewrite: bare host
    /// (an IPv6 literal is re-bracketed), or `host:port` when a port was given.
    var authority: String {
        let h = host.contains(":") ? "[\(host)]" : host
        if let port { return "\(h):\(port)" }
        return h
    }
}

/// Compiled form of ``MITMRewriteAction`` — the sub-mode of the unified
/// "Rewrite" operation. ``transparent`` carries the parsed replacement and
/// drives the request rewrite + deferred dial; the rest carry pre-validated
/// data for ``MITMRespondBuilder`` to synthesize an inner-leg response.
enum CompiledRewriteAction {
    case transparent(ReplacementURL)
    case redirect302(location: String)
    case reject200Text(content: String)
    case reject200Gif
    case reject200Data(base64: String)
}

enum CompiledMITMOperation {
    /// Request-phase "Rewrite" operation. ``transparent`` rewrites the
    /// request URL to the replacement and (on a host change) redirects the
    /// outer dial + authority; the synthesize sub-modes answer on the inner
    /// leg. The ``CompiledMITMRule/gate`` decides whether the rule fires.
    case rewrite(CompiledRewriteAction)
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
    /// Native regex find-and-replace over the text body (import op id `4`).
    /// The ``search`` pattern is pre-compiled at rule-load time (see
    /// ``MITMBodyReplace``); ``replacement`` is the literal swapped in for
    /// each match. ``MITMScriptTransform`` applies every matching
    /// ``bodyReplace`` rule to the buffered body in rule order — like
    /// ``bodyJSON`` these compose and run in native code without a
    /// `JSContext`.
    case bodyReplace(search: Regex<AnyRegexOutput>, replacement: String)
    /// Native JSON body edit (import op id `5`). Each edit's path and
    /// value are pre-parsed at rule-load time (see ``MITMJSONPatch``);
    /// ``MITMScriptTransform`` applies every matching ``bodyJSON`` rule to
    /// the buffered body in rule order. Unlike ``script`` these compose —
    /// all matching rules fire — and they run in native code without a
    /// `JSContext`. When a ``script`` also matches, the JSON edits run
    /// first and the script sees the edited body.
    case bodyJSON(MITMJSONPatch.CompiledOp)
}

/// Compiled view of a rule set at one trie terminal: the specific suffix
/// reached and the rules ready to apply. A source set with multiple
/// suffixes produces one of these per suffix, each sharing the same
/// compiled rules. ``id`` is copied from the source ``MITMRuleSet`` so the
/// runtime can use it as a stable scope key for ``MITMScriptStore``.
struct CompiledMITMRuleSet {
    let id: UUID
    let domainSuffix: String
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
                // Two enabled rule sets declared the same domain suffix; the
                // later one (this set, in user list order) overwrites the
                // earlier payload. Surface it — the precedence contract above
                // promises this warning, and without it, reordering sets in the
                // UI silently changes which rules apply for the suffix.
                logger.warning("[MITM] duplicate domain suffix \"\(suffix)\": rule set \"\(set.name)\" overrides an earlier set's rules for it")
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

    // MARK: - Compilation

    private func compile(_ operation: MITMOperation, suffix: String) -> CompiledMITMOperation? {
        switch operation {
        case .rewrite(let action):
            guard let compiled = Self.compileRewrite(action, suffix: suffix) else { return nil }
            return .rewrite(compiled)
        case .headerAdd(let name, let value):
            guard Self.isValidHeaderName(name) else {
                logger.warning("[MITM] headerAdd dropped: invalid header name \"\(name)\" (suffix=\(suffix))")
                return nil
            }
            guard !Self.isFramingHeader(name) else {
                logger.warning("[MITM] headerAdd dropped: \"\(name)\" controls message framing and can't be set by a header rule (suffix=\(suffix))")
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
            guard !Self.isFramingHeader(name) else {
                logger.warning("[MITM] headerReplace dropped: \"\(name)\" controls message framing and can't be set by a header rule (suffix=\(suffix))")
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
        case .bodyReplace(let search, let replacement):
            // The only compile failure is a malformed search regex; the
            // replacement is lenient and carries no wire-safety constraint
            // (it produces a body, not a head), so a dropped rule means the
            // author's search pattern couldn't be compiled.
            guard let compiled = MITMBodyReplace.compile(search: search, replacement: replacement) else {
                logger.warning("[MITM] bodyReplace dropped: search is not a valid regex (suffix=\(suffix))")
                return nil
            }
            return .bodyReplace(search: compiled.search, replacement: compiled.replacement)
        case .bodyJSON(let operation):
            // The only compile failure is a malformed JSONPath; values
            // are lenient (a non-JSON string is taken literally), so a
            // dropped rule means the author's path couldn't be parsed.
            guard let compiled = MITMJSONPatch.compile(operation) else {
                logger.warning("[MITM] bodyJSON dropped: malformed JSON path in \(operation.action) (suffix=\(suffix))")
                return nil
            }
            return .bodyJSON(compiled)
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
    // Rule sets imported from `.amrs` files or subscription URLs
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

    /// Headers that determine message framing (RFC 9112 §6). A header rule that
    /// adds or replaces one of these would let the serialized head's framing
    /// diverge from the body the proxy actually streams — a duplicate or
    /// mismatched ``Content-Length`` / ``Transfer-Encoding`` is the classic
    /// request/response-smuggling (CL.CL / CL.TE) primitive, and the inbound
    /// parser works hard to reject exactly that divergence. Letting a rule
    /// re-introduce it on the way out would reopen the hole, so framing headers
    /// aren't settable by add/replace. (``headerDelete`` is left alone: removing
    /// a framing header only ever makes the message *more* conservatively
    /// framed, never divergent.)
    private static func isFramingHeader(_ name: String) -> Bool {
        let lower = name.lowercased()
        return lower == "content-length" || lower == "transfer-encoding"
    }

    /// Conservative check for a rewrite replacement target. It is spliced
    /// into the request-target (HTTP/1 start line or HTTP/2 ``:path``) at
    /// every match site; allowing SP / HTAB / CR / LF / NUL / DEL would
    /// either break HTTP/1's SP-delimited start line or be rejected by
    /// HTTP/2 receivers. Empty replacements pass — deleting a matched
    /// substring is legitimate.
    private static func isValidRequestTargetReplacement(_ replacement: String) -> Bool {
        for byte in replacement.utf8 {
            if byte <= 0x20 || byte == 0x7F {
                return false
            }
        }
        return true
    }

    // MARK: - Rewrite compilation

    /// Compiles a ``MITMRewriteAction`` sub-mode, validating the replacement
    /// URL (transparent / 302) or reject payload. Returns nil to drop the
    /// rule with a logged diagnostic.
    private static func compileRewrite(_ action: MITMRewriteAction, suffix: String) -> CompiledRewriteAction? {
        switch action {
        case .transparent(let url):
            guard let parsed = parseReplacementURL(url) else {
                logger.warning("[MITM] rewrite(transparent) dropped: \"\(url)\" is not an absolute URL with a host (suffix=\(suffix))")
                return nil
            }
            // The path+query is spliced verbatim onto the request-target, so
            // it must be wire-safe (no SP/CR/LF/CTL that would split the
            // HTTP/1 start line or trip an HTTP/2 receiver).
            guard isValidRequestTargetReplacement(parsed.requestTarget) else {
                logger.warning("[MITM] rewrite(transparent) dropped: replacement path is not wire-safe (suffix=\(suffix))")
                return nil
            }
            return .transparent(parsed)
        case .redirect302(let url):
            // The URL lands in a `Location` header value, so it must parse to
            // an absolute URL and be free of CR/LF/NUL.
            guard parseReplacementURL(url) != nil, isValidHeaderValue(url) else {
                logger.warning("[MITM] rewrite(302) dropped: \"\(url)\" is not a valid, wire-safe URL (suffix=\(suffix))")
                return nil
            }
            return .redirect302(location: url)
        case .reject200Text(let content):
            return .reject200Text(content: content)
        case .reject200Gif:
            return .reject200Gif
        case .reject200Data(let base64):
            // Empty → ``MITMRespondBuilder`` substitutes the default payload.
            if !base64.isEmpty, Data(base64Encoded: base64) == nil {
                logger.warning("[MITM] rewrite(reject-data) dropped: contents are not valid base64 (suffix=\(suffix))")
                return nil
            }
            return .reject200Data(base64: base64)
        }
    }

    /// Parses a full replacement URL into its dial + request-target parts.
    /// Requires an absolute URL with a host (the replacement is always a full
    /// URL). The path defaults to `/` when absent; the query is preserved in
    /// percent-encoded form.
    static func parseReplacementURL(_ raw: String) -> ReplacementURL? {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty,
              let comps = URLComponents(string: trimmed),
              let rawHost = comps.host, !rawHost.isEmpty else { return nil }
        // Strip the URI brackets from an IPv6 literal so the dial leg receives
        // the bare address its resolver expects; ``ReplacementURL/authority``
        // re-adds them for the Host / `:authority` header.
        var host = rawHost
        if host.hasPrefix("["), host.hasSuffix("]"), host.count >= 2 {
            host = String(host.dropFirst().dropLast())
        }
        let port = comps.port.flatMap { UInt16(exactly: $0) }
        var target = comps.percentEncodedPath
        if target.isEmpty { target = "/" }
        if let query = comps.percentEncodedQuery, !query.isEmpty {
            target += "?\(query)"
        }
        return ReplacementURL(host: host, port: port, requestTarget: target)
    }
}
