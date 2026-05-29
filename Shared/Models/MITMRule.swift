//
//  MITMRule.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation

enum MITMPhase: String, Codable, CaseIterable, Identifiable {
    case httpRequest
    case httpResponse

    var id: String { rawValue }
}

extension MITMPhase: CustomStringConvertible {
    var description: String {
        switch self {
        case .httpRequest:
            String(localized: "Request")
        case .httpResponse:
            String(localized: "Response")
        }
    }
}

/// A single rewrite operation. The associated values carry only the
/// fields that operation needs; the URL-match ``pattern`` that gates
/// every rule lives one level up on ``MITMRule``, uniform across
/// operations, and the upstream destination is separate again on
/// ``MITMRuleSet/rewriteTarget``. See ``MITMRuleSetParser`` for the text
/// import format and the per-operation field layout.
enum MITMOperation: Equatable {
    /// Request-phase only. ``path`` is the replacement template; the
    /// rule's ``MITMRule/pattern`` is the substitution regex.
    case urlReplace(path: String)
    case headerAdd(name: String, value: String)
    case headerDelete(name: String)
    /// Overwrites the value of every header named ``name``
    /// (case-insensitive); absent headers are left untouched.
    case headerReplace(name: String, value: String)
    /// JavaScript transform. ``scriptBase64`` is the base64-encoded UTF-8
    /// source defining `function process(ctx)`. See ``MITMScriptEngine``
    /// for the runtime contract.
    ///
    /// Single-rule semantics, by design, not a limitation: at most one
    /// ``.script`` fires per message; when several match, the last wins.
    /// This is a deliberate performance choice (see ``MITMScriptTransform``)
    /// — authors needing composed behaviour should consolidate into one
    /// `process(ctx)`.
    case script(scriptBase64: String)
    /// Per-frame JavaScript transform for streaming bodies (gRPC, SSE,
    /// chunked APIs): same storage shape as ``script`` but invoked once
    /// per HTTP/2 DATA frame or HTTP/1 chunked chunk, without buffering,
    /// decompression, or head-field mutation. See ``MITMScriptEngine``.
    ///
    /// HTTP/1 Content-Length bodies are skipped (the byte count is
    /// already committed). When both a ``script`` and a ``streamScript``
    /// match, ``streamScript`` wins; otherwise single-rule semantics
    /// match ``script`` — at most one fires per stream, last match wins.
    case streamScript(scriptBase64: String)
}

extension MITMOperation: CustomStringConvertible {
    var description: String {
        switch self {
        case .urlReplace:
            String(localized: "URL Replace")
        case .headerAdd:
            String(localized: "Header Add")
        case .headerDelete:
            String(localized: "Header Delete")
        case .headerReplace:
            String(localized: "Header Replace")
        case .script:
            String(localized: "Script")
        case .streamScript:
            String(localized: "Stream Script")
        }
    }
}

extension MITMOperation: Codable {
    private enum Kind: String, Codable {
        case urlReplace
        case headerAdd
        case headerDelete
        case headerReplace
        case script
        case streamScript
    }

    private enum CodingKeys: String, CodingKey {
        case kind
        case name
        case value
        case replacement
        case script
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(Kind.self, forKey: .kind)
        switch kind {
        case .urlReplace:
            self = .urlReplace(path: try c.decode(String.self, forKey: .replacement))
        case .headerAdd:
            self = .headerAdd(
                name: try c.decode(String.self, forKey: .name),
                value: try c.decode(String.self, forKey: .value)
            )
        case .headerDelete:
            self = .headerDelete(name: try c.decode(String.self, forKey: .name))
        case .headerReplace:
            self = .headerReplace(
                name: try c.decode(String.self, forKey: .name),
                value: try c.decode(String.self, forKey: .value)
            )
        case .script:
            self = .script(scriptBase64: try c.decode(String.self, forKey: .script))
        case .streamScript:
            self = .streamScript(scriptBase64: try c.decode(String.self, forKey: .script))
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .urlReplace(let path):
            try c.encode(Kind.urlReplace, forKey: .kind)
            try c.encode(path, forKey: .replacement)
        case .headerAdd(let name, let value):
            try c.encode(Kind.headerAdd, forKey: .kind)
            try c.encode(name, forKey: .name)
            try c.encode(value, forKey: .value)
        case .headerDelete(let name):
            try c.encode(Kind.headerDelete, forKey: .kind)
            try c.encode(name, forKey: .name)
        case .headerReplace(let name, let value):
            try c.encode(Kind.headerReplace, forKey: .kind)
            try c.encode(name, forKey: .name)
            try c.encode(value, forKey: .value)
        case .script(let scriptBase64):
            try c.encode(Kind.script, forKey: .kind)
            try c.encode(scriptBase64, forKey: .script)
        case .streamScript(let scriptBase64):
            try c.encode(Kind.streamScript, forKey: .kind)
            try c.encode(scriptBase64, forKey: .script)
        }
    }
}

struct MITMRule: Codable, Equatable, Identifiable {
    var id = UUID()
    var phase: MITMPhase
    /// `NSRegularExpression` over the request target's path-and-query
    /// that gates the ``operation`` (and doubles as the substitution
    /// regex for ``MITMOperation/urlReplace``). The set's domain suffixes
    /// gate the host; this refines by path.
    var pattern: String
    var operation: MITMOperation

    init(
        id: UUID = UUID(),
        phase: MITMPhase,
        pattern: String,
        operation: MITMOperation
    ) {
        self.id = id
        self.phase = phase
        self.pattern = pattern
        self.operation = operation
    }

    private enum CodingKeys: String, CodingKey {
        case phase
        case pattern
        case operation
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = UUID()
        self.phase = try c.decode(MITMPhase.self, forKey: .phase)
        self.pattern = try c.decode(String.self, forKey: .pattern)
        self.operation = try c.decode(MITMOperation.self, forKey: .operation)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(phase, forKey: .phase)
        try c.encode(pattern, forKey: .pattern)
        try c.encode(operation, forKey: .operation)
    }
}

/// Action applied to traffic matched by a rule set. See
/// ``MITMRuleSetParser`` for how each is written in import text and
/// ``MITMResponseSynthesizer`` for the synthesized wire format.
///
/// - ``transparent``: dial the outer leg to ``host``:``port`` instead of
///   the original destination and rewrite the request authority; the
///   client still sees the original SNI on the leaf certificate. A nil
///   ``port`` keeps the original.
/// - ``redirect302``: no outer leg; synthesize a `302 Found` redirecting
///   to the target.
/// - ``reject200``: no outer leg; synthesize a `200 OK` from the
///   configured ``rejectBody`` and optional Content-Type override.
enum MITMRewriteAction: String, Codable {
    case transparent
    case redirect302
    case reject200

    /// True for actions that synthesize the response on the inner leg
    /// without ever opening an outer connection. The lwIP/MITM glue uses
    /// this to skip the proxy/direct dial entirely.
    var synthesizesResponse: Bool {
        switch self {
        case .transparent: return false
        case .redirect302, .reject200: return true
        }
    }
}

/// Canned response body for ``MITMRewriteAction/reject200``; see
/// ``MITMRuleSetParser`` for how kind and contents are written in import
/// text. ``contentType`` overrides the per-kind default Content-Type
/// (empty/nil keeps it): ``text`` → `text/plain; charset=utf-8`, ``gif``
/// → `image/gif`, ``data`` → `application/octet-stream`.
struct MITMRejectBody: Codable, Equatable {
    enum Kind: String, Codable {
        case text
        case gif
        case data

        /// Body to use when the user left ``MITMRejectBody/contents``
        /// blank. Substituted at response-synthesis time so the wire
        /// reply is never zero-length (some upstream apps treat an empty
        /// 200 response as an error). The stored model keeps the empty
        /// string so the editor doesn't show a fabricated value.
        ///
        /// - ``text``: a short ASCII line.
        /// - ``data``: base64 for the literal "Anywhere".
        /// - ``gif``: empty — the synthesizer always emits the canned
        ///   1×1 GIF for this kind, regardless of ``contents``.
        var defaultContents: String {
            switch self {
            case .text: return "Success from Anywhere"
            case .data: return "QW55d2hlcmU="
            case .gif:  return ""
            }
        }
    }

    var kind: Kind
    var contents: String
    var contentType: String?

    init(kind: Kind = .text, contents: String = "", contentType: String? = nil) {
        self.kind = kind
        self.contents = contents
        self.contentType = contentType
    }
}

/// Per-rule-set redirect/reject configuration. The ``action`` field
/// selects the mode; ``host``/``port`` only apply to ``transparent`` and
/// ``redirect302``; ``rejectBody`` only applies to ``reject200``.
///
/// Codable is backward-compatible: persisted blobs that predate the
/// ``action`` field decode as ``transparent``, preserving the host/port
/// the user originally configured.
struct MITMRewriteTarget: Codable, Equatable {
    var action: MITMRewriteAction
    var host: String
    var port: UInt16?
    var rejectBody: MITMRejectBody?

    init(
        action: MITMRewriteAction = .transparent,
        host: String = "",
        port: UInt16? = nil,
        rejectBody: MITMRejectBody? = nil
    ) {
        self.action = action
        self.host = host
        self.port = port
        self.rejectBody = rejectBody
    }

    private enum CodingKeys: String, CodingKey {
        case action
        case host
        case port
        case rejectBody
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.action = try c.decodeIfPresent(MITMRewriteAction.self, forKey: .action) ?? .transparent
        self.host = try c.decodeIfPresent(String.self, forKey: .host) ?? ""
        self.port = try c.decodeIfPresent(UInt16.self, forKey: .port)
        self.rejectBody = try c.decodeIfPresent(MITMRejectBody.self, forKey: .rejectBody)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(action, forKey: .action)
        try c.encode(host, forKey: .host)
        try c.encodeIfPresent(port, forKey: .port)
        try c.encodeIfPresent(rejectBody, forKey: .rejectBody)
    }
}

/// An ordered group of rewrite rules identified by a user-supplied name
/// and applied to any host matching one of ``domainSuffixes``. The
/// optional ``rewriteTarget`` gives the set a coherent upstream; if set,
/// every connection covered by the set is redirected to the target,
/// regardless of which rule fires.
///
/// When ``subscriptionURL`` is set, the suffixes, rewrite target, and
/// rules are sourced from a remote `.amrs` file and replaced on refresh;
/// the set's ``id`` (its ``MITMScriptStore`` scope key) and user-given
/// ``name`` are preserved across refreshes so the scope and any rename
/// stick.
struct MITMRuleSet: Codable, Equatable, Identifiable {
    static let maxRuleCount = 10000

    var id = UUID()
    var name: String
    /// Per-set master switch. A disabled set is persisted and editable but
    /// excluded from the compiled rewrite policy, so it matches no traffic
    /// until re-enabled. Blobs predating this field decode as enabled.
    var enabled: Bool
    var domainSuffixes: [String]
    var rewriteTarget: MITMRewriteTarget?
    var rules: [MITMRule]
    /// When set, the set's content is sourced from a remote `.amrs` file
    /// and replaced on refresh.
    var subscriptionURL: URL?

    init(
        id: UUID = UUID(),
        name: String,
        enabled: Bool = true,
        domainSuffixes: [String] = [],
        rewriteTarget: MITMRewriteTarget? = nil,
        rules: [MITMRule] = [],
        subscriptionURL: URL? = nil
    ) {
        self.id = id
        self.name = name
        self.enabled = enabled
        self.domainSuffixes = domainSuffixes
        self.rewriteTarget = rewriteTarget
        self.rules = rules
        self.subscriptionURL = subscriptionURL
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case enabled
        case domainSuffix       // legacy: single-suffix shape predating named sets
        case domainSuffixes
        case rewriteTarget
        case rules
        case subscriptionURL
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // Persisted id keeps ``MITMScriptStore`` scope keys stable across
        // snapshot reloads. Pre-id blobs decode with a fresh UUID; any
        // script-store buckets written under that fresh id stay reachable
        // for the rest of the process (and get persisted on the next save).
        self.id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        let legacySuffix = try c.decodeIfPresent(String.self, forKey: .domainSuffix)
        if let suffixes = try c.decodeIfPresent([String].self, forKey: .domainSuffixes) {
            self.domainSuffixes = suffixes
        } else if let legacySuffix {
            self.domainSuffixes = [legacySuffix]
        } else {
            self.domainSuffixes = []
        }
        self.name = try c.decodeIfPresent(String.self, forKey: .name) ?? legacySuffix ?? ""
        self.enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        self.rewriteTarget = try c.decodeIfPresent(MITMRewriteTarget.self, forKey: .rewriteTarget)
        // A single corrupt rule shouldn't take down the whole set.
        self.rules = try c.decodeSkippingInvalid([MITMRule].self, forKey: .rules)
        self.subscriptionURL = try c.decodeIfPresent(URL.self, forKey: .subscriptionURL)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encode(enabled, forKey: .enabled)
        try c.encode(domainSuffixes, forKey: .domainSuffixes)
        try c.encodeIfPresent(rewriteTarget, forKey: .rewriteTarget)
        try c.encode(rules, forKey: .rules)
        try c.encodeIfPresent(subscriptionURL, forKey: .subscriptionURL)
    }

    /// Returns a parsed http(s) URL whose path ends with `.amrs` (case-insensitive), or nil.
    static func validSubscriptionURL(from rawValue: String) -> URL? {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              url.path.lowercased().hasSuffix(".amrs") else { return nil }
        return url
    }
}

/// Persisted shape for the MITM feature: master toggle plus the user's
/// rule sets. Owned by the app side via ``MITMRuleSetStore`` and read by the
/// network extension via ``TunnelStack/loadMITMSetting``.
struct MITMSnapshot: Codable, Equatable {
    var enabled: Bool
    var ruleSets: [MITMRuleSet]

    static let empty = MITMSnapshot(enabled: false, ruleSets: [])

    init(enabled: Bool, ruleSets: [MITMRuleSet]) {
        self.enabled = enabled
        self.ruleSets = ruleSets
    }

    private enum CodingKeys: String, CodingKey {
        case enabled
        case ruleSets
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        // A single corrupt rule set shouldn't take down the whole snapshot.
        self.ruleSets = try c.decodeSkippingInvalid([MITMRuleSet].self, forKey: .ruleSets)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(enabled, forKey: .enabled)
        try c.encode(ruleSets, forKey: .ruleSets)
    }

    /// Best-effort decode of the persisted blob. Returns ``empty`` when no
    /// snapshot has been written yet or the blob fails to decode. Both sides
    /// treat that as "MITM disabled" rather than crashing.
    ///
    /// If SwiftData has nothing yet, fall back to the legacy UserDefaults
    /// key so the Network Extension keeps working during the upgrade window
    /// before the host has migrated. The host removes that key once the
    /// blob is in SwiftData, so the fallback turns into a no-op afterwards.
    static func load() -> MITMSnapshot {
        if let data = JSONBlobStore.shared.load(.mitm),
           let snapshot = try? JSONDecoder().decode(MITMSnapshot.self, from: data) {
            return snapshot
        }
        if let data = UserDefaults(suiteName: AWCore.Identifier.appGroupSuite)?.data(forKey: legacyMITMDefaultsKey),
           let snapshot = try? JSONDecoder().decode(MITMSnapshot.self, from: data) {
            return snapshot
        }
        return .empty
    }

    private static let legacyMITMDefaultsKey = "mitmData"

    /// Encodes and persists the snapshot, then fires the Darwin
    /// notification the extension observes to trigger a reload.
    func save() {
        guard let data = try? JSONEncoder().encode(self) else { return }
        JSONBlobStore.shared.save(.mitm, data: data)
        AWCore.notifyMITMChanged()
    }
}
