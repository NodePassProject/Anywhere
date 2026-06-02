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

/// One declarative edit to a JSON message body — the native,
/// rule-configured analog of the ``Anywhere.json`` script API. A single
/// ``MITMOperation/bodyJSON`` rule carries exactly one of these; several
/// ``bodyJSON`` rules matching the same message compose in rule order
/// (unlike ``MITMOperation/script``, which is single-rule, last-wins).
/// The body is parsed once, every matching edit applies in turn, and the
/// result is re-serialized — and, exactly as in ``Anywhere.json``, a body
/// that isn't JSON or an edit that doesn't resolve leaves the body
/// untouched (total / fail-closed).
///
/// ``path`` is a JSONPath like `"$.data.items[0].id"` (leading `$`
/// optional; dotted keys and `[index]` / `["key"]` brackets). ``key`` and
/// ``field`` are bare names — for the recursive ops ``key`` matches at any
/// depth. ``value`` / ``values`` are authored as JSON literals (`true`,
/// `42`, `"text"`, `{"a":1}`); a string that isn't valid JSON is taken as
/// a literal JSON string, so the common case `value = Anywhere` means the
/// string `"Anywhere"`. The compile step (``MITMJSONPatch/compile``)
/// pre-parses path and value once at rule-load time.
enum MITMJSONOperation: Equatable {
    /// Upsert: create the addressed member (or overwrite it if present);
    /// for an array index, set in range or append when index == count.
    case add(path: String, value: String)
    /// Modify-in-place: does nothing when the addressed member/index
    /// doesn't already exist, so it can't introduce new fields.
    case replace(path: String, value: String)
    /// Remove the addressed member/element.
    case delete(path: String)
    /// Overwrite every property named ``key`` at any depth (existing
    /// occurrences only; never created where absent).
    case replaceRecursive(key: String, value: String)
    /// Remove every property named ``key`` at any depth.
    case deleteRecursive(key: String)
    /// At the array addressed by ``path``, drop every object element that
    /// contains ``key``.
    case removeWhereKeyExists(path: String, key: String)
    /// At the array addressed by ``path``, drop every object element whose
    /// ``field`` equals one of ``values`` (a JSON array literal, or a lone
    /// scalar).
    case removeWhereFieldIn(path: String, field: String, values: String)
}

extension MITMJSONOperation: CustomStringConvertible {
    /// Short action token, reused by the text import format and the rule
    /// list subtitle.
    var action: String {
        switch self {
        case .add:                  return "add"
        case .replace:              return "replace"
        case .delete:               return "delete"
        case .replaceRecursive:     return "replace-recursive"
        case .deleteRecursive:      return "delete-recursive"
        case .removeWhereKeyExists: return "remove-where-key-exists"
        case .removeWhereFieldIn:   return "remove-where-field-in"
        }
    }

    /// `action target` for the rule list, e.g. `add $.user.vip`.
    var description: String {
        switch self {
        case .add(let path, _),
             .replace(let path, _),
             .delete(let path),
             .removeWhereKeyExists(let path, _),
             .removeWhereFieldIn(let path, _, _):
            return "\(action) \(path)"
        case .replaceRecursive(let key, _),
             .deleteRecursive(let key):
            return "\(action) \(key)"
        }
    }
}

extension MITMJSONOperation: Codable {
    private enum Action: String, Codable {
        case add
        case replace
        case delete
        case replaceRecursive
        case deleteRecursive
        case removeWhereKeyExists
        case removeWhereFieldIn
    }

    private enum CodingKeys: String, CodingKey {
        case action
        case path
        case key
        case field
        case value
        case values
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(Action.self, forKey: .action) {
        case .add:
            self = .add(
                path: try c.decode(String.self, forKey: .path),
                value: try c.decode(String.self, forKey: .value)
            )
        case .replace:
            self = .replace(
                path: try c.decode(String.self, forKey: .path),
                value: try c.decode(String.self, forKey: .value)
            )
        case .delete:
            self = .delete(path: try c.decode(String.self, forKey: .path))
        case .replaceRecursive:
            self = .replaceRecursive(
                key: try c.decode(String.self, forKey: .key),
                value: try c.decode(String.self, forKey: .value)
            )
        case .deleteRecursive:
            self = .deleteRecursive(key: try c.decode(String.self, forKey: .key))
        case .removeWhereKeyExists:
            self = .removeWhereKeyExists(
                path: try c.decode(String.self, forKey: .path),
                key: try c.decode(String.self, forKey: .key)
            )
        case .removeWhereFieldIn:
            self = .removeWhereFieldIn(
                path: try c.decode(String.self, forKey: .path),
                field: try c.decode(String.self, forKey: .field),
                values: try c.decode(String.self, forKey: .values)
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .add(let path, let value):
            try c.encode(Action.add, forKey: .action)
            try c.encode(path, forKey: .path)
            try c.encode(value, forKey: .value)
        case .replace(let path, let value):
            try c.encode(Action.replace, forKey: .action)
            try c.encode(path, forKey: .path)
            try c.encode(value, forKey: .value)
        case .delete(let path):
            try c.encode(Action.delete, forKey: .action)
            try c.encode(path, forKey: .path)
        case .replaceRecursive(let key, let value):
            try c.encode(Action.replaceRecursive, forKey: .action)
            try c.encode(key, forKey: .key)
            try c.encode(value, forKey: .value)
        case .deleteRecursive(let key):
            try c.encode(Action.deleteRecursive, forKey: .action)
            try c.encode(key, forKey: .key)
        case .removeWhereKeyExists(let path, let key):
            try c.encode(Action.removeWhereKeyExists, forKey: .action)
            try c.encode(path, forKey: .path)
            try c.encode(key, forKey: .key)
        case .removeWhereFieldIn(let path, let field, let values):
            try c.encode(Action.removeWhereFieldIn, forKey: .action)
            try c.encode(path, forKey: .path)
            try c.encode(field, forKey: .field)
            try c.encode(values, forKey: .values)
        }
    }
}

/// A single rewrite operation. The associated values carry only the
/// fields that operation needs; the ``MITMRule/urlPattern`` that gates
/// every rule lives one level up on ``MITMRule``, uniform across
/// operations. See ``MITMRuleSetParser`` for the text import format and
/// the per-operation field layout.
enum MITMOperation: Equatable {
    /// Request-phase only. The unified "Rewrite" operation (import op id
    /// `0`): rewrites the request URL to a full replacement URL, redirects
    /// with a synthesized `302`, or rejects with a synthesized `200`. The
    /// specific behavior is carried by the ``MITMRewriteAction`` sub-mode.
    /// When the sub-mode is ``MITMRewriteAction/transparent(url:)`` the outer
    /// leg is dialed to the replacement host and `Host`/`:authority` is
    /// rewritten to match; the other sub-modes synthesize the response on the
    /// inner leg without an upstream dial. Gated, like every operation, by
    /// ``MITMRule/urlPattern``.
    case rewrite(MITMRewriteAction)
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
    /// Native regex find-and-replace over the decompressed text body
    /// (import op id `4`). ``search`` is a regex and ``replacement`` the
    /// literal swapped in for each match, applied to the body. Buffered like
    /// ``bodyJSON`` (the body is accumulated, decompressed, edited, and
    /// re-emitted with a fresh length) and, like it, **every** matching
    /// ``bodyReplace`` rule fires in rule order so edits compose. Total /
    /// fail-closed: a body that isn't valid UTF-8 — or a search that matches
    /// nothing — leaves the body untouched. See ``MITMBodyReplace`` for the
    /// runtime.
    case bodyReplace(search: String, replacement: String)
    /// Native JSON body edit — the declarative analog of the
    /// ``Anywhere.json`` script API, applied in compiled native code
    /// rather than JavaScript. Buffered like ``script`` (the body is
    /// accumulated, decompressed, edited, and re-emitted with a fresh
    /// length), but, unlike ``script``, **every** matching ``bodyJSON``
    /// rule fires in rule order so edits compose. When a ``script`` rule
    /// also matches the same message, the JSON edits run first and the
    /// script sees the already-edited body. See ``MITMJSONOperation`` for
    /// the edit catalog and ``MITMJSONPatch`` for the runtime.
    case bodyJSON(MITMJSONOperation)
}

extension MITMOperation: CustomStringConvertible {
    var description: String {
        switch self {
        case .rewrite:
            String(localized: "Rewrite")
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
        case .bodyReplace:
            String(localized: "Body Replace")
        case .bodyJSON:
            String(localized: "Body JSON")
        }
    }
}

extension MITMOperation: Codable {
    private enum Kind: String, Codable {
        case rewrite
        case headerAdd
        case headerDelete
        case headerReplace
        case script
        case streamScript
        case bodyReplace
        case bodyJSON
    }

    private enum CodingKeys: String, CodingKey {
        case kind
        case name
        case value
        case replacement
        case search
        case script
        case json
        case rewrite
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(Kind.self, forKey: .kind)
        switch kind {
        case .rewrite:
            self = .rewrite(try c.decode(MITMRewriteAction.self, forKey: .rewrite))
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
        case .bodyReplace:
            self = .bodyReplace(
                search: try c.decode(String.self, forKey: .search),
                replacement: try c.decode(String.self, forKey: .replacement)
            )
        case .bodyJSON:
            self = .bodyJSON(try c.decode(MITMJSONOperation.self, forKey: .json))
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .rewrite(let action):
            try c.encode(Kind.rewrite, forKey: .kind)
            try c.encode(action, forKey: .rewrite)
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
        case .bodyReplace(let search, let replacement):
            try c.encode(Kind.bodyReplace, forKey: .kind)
            try c.encode(search, forKey: .search)
            try c.encode(replacement, forKey: .replacement)
        case .bodyJSON(let operation):
            try c.encode(Kind.bodyJSON, forKey: .kind)
            try c.encode(operation, forKey: .json)
        }
    }
}

struct MITMRule: Codable, Equatable, Identifiable {
    var id = UUID()
    var phase: MITMPhase
    /// `NSRegularExpression` over the **whole request URL**
    /// (`https://host/path?query`) that gates the ``operation``. The set's
    /// domain suffixes gate the host; this refines against the full URL.
    var urlPattern: String
    var operation: MITMOperation

    init(
        id: UUID = UUID(),
        phase: MITMPhase,
        urlPattern: String,
        operation: MITMOperation
    ) {
        self.id = id
        self.phase = phase
        self.urlPattern = urlPattern
        self.operation = operation
    }

    private enum CodingKeys: String, CodingKey {
        case phase
        case urlPattern
        case operation
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = UUID()
        self.phase = try c.decode(MITMPhase.self, forKey: .phase)
        self.urlPattern = try c.decode(String.self, forKey: .urlPattern)
        self.operation = try c.decode(MITMOperation.self, forKey: .operation)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(phase, forKey: .phase)
        try c.encode(urlPattern, forKey: .urlPattern)
        try c.encode(operation, forKey: .operation)
    }
}

/// The sub-mode of the unified "Rewrite" operation (``MITMOperation/rewrite``).
/// Maps 1:1 to the numeric sub-mode in the import format (see
/// ``MITMRuleSetParser``); ``MITMRespondBuilder`` produces the synthesized
/// wire response for the non-transparent sub-modes.
///
/// - ``transparent(url:)`` (0): rewrite the request URL to ``url`` (a full
///   URL). The outer leg is dialed to ``url``'s host and `Host`/`:authority`
///   is rewritten to match (a no-op in effect when ``url`` keeps the original
///   host); the client still sees the original SNI on the leaf certificate.
/// - ``redirect302(url:)`` (1): no outer leg; synthesize a `302 Found`
///   whose `Location` is ``url``.
/// - ``reject200Text(content:)`` (2): no outer leg; synthesize a `200 OK`
///   with a `text/plain` body (empty ``content`` → a default line).
/// - ``reject200Gif`` (3): no outer leg; synthesize a `200 OK` carrying the
///   canned 1×1 GIF.
/// - ``reject200Data(base64:)`` (4): no outer leg; synthesize a `200 OK`
///   with an `application/octet-stream` body decoded from ``base64`` (empty
///   → a default payload).
enum MITMRewriteAction: Equatable {
    case transparent(url: String)
    case redirect302(url: String)
    case reject200Text(content: String)
    case reject200Gif
    case reject200Data(base64: String)
}

extension MITMRewriteAction: Codable {
    private enum Kind: String, Codable {
        case transparent
        case redirect302
        case reject200Text
        case reject200Gif
        case reject200Data
    }

    private enum CodingKeys: String, CodingKey {
        case kind
        case url
        case content
        case base64
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(Kind.self, forKey: .kind) {
        case .transparent:
            self = .transparent(url: try c.decode(String.self, forKey: .url))
        case .redirect302:
            self = .redirect302(url: try c.decode(String.self, forKey: .url))
        case .reject200Text:
            self = .reject200Text(content: try c.decode(String.self, forKey: .content))
        case .reject200Gif:
            self = .reject200Gif
        case .reject200Data:
            self = .reject200Data(base64: try c.decode(String.self, forKey: .base64))
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .transparent(let url):
            try c.encode(Kind.transparent, forKey: .kind)
            try c.encode(url, forKey: .url)
        case .redirect302(let url):
            try c.encode(Kind.redirect302, forKey: .kind)
            try c.encode(url, forKey: .url)
        case .reject200Text(let content):
            try c.encode(Kind.reject200Text, forKey: .kind)
            try c.encode(content, forKey: .content)
        case .reject200Gif:
            try c.encode(Kind.reject200Gif, forKey: .kind)
        case .reject200Data(let base64):
            try c.encode(Kind.reject200Data, forKey: .kind)
            try c.encode(base64, forKey: .base64)
        }
    }
}

/// An ordered group of rewrite rules identified by a user-supplied name
/// and applied to any host matching one of ``domainSuffixes``. Redirect /
/// reject / host-rewrite behavior lives on individual ``rules`` via the
/// ``MITMOperation/rewrite`` operation, not on the set.
///
/// When ``subscriptionURL`` is set, the suffixes and rules are sourced
/// from a remote `.amrs` file and replaced on refresh; the set's ``id``
/// (its ``MITMScriptStore`` scope key) and user-given ``name`` are
/// preserved across refreshes so the scope and any rename stick.
struct MITMRuleSet: Codable, Equatable, Identifiable {
    static let maxRuleCount = 10000

    var id = UUID()
    var name: String
    /// Per-set master switch. A disabled set is persisted and editable but
    /// excluded from the compiled rewrite policy, so it matches no traffic
    /// until re-enabled. Blobs predating this field decode as enabled.
    var enabled: Bool
    var domainSuffixes: [String]
    var rules: [MITMRule]
    /// When set, the set's content is sourced from a remote `.amrs` file
    /// and replaced on refresh.
    var subscriptionURL: URL?

    init(
        id: UUID = UUID(),
        name: String,
        enabled: Bool = true,
        domainSuffixes: [String] = [],
        rules: [MITMRule] = [],
        subscriptionURL: URL? = nil
    ) {
        self.id = id
        self.name = name
        self.enabled = enabled
        self.domainSuffixes = domainSuffixes
        self.rules = rules
        self.subscriptionURL = subscriptionURL
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case enabled
        case domainSuffix       // legacy: single-suffix shape predating named sets
        case domainSuffixes
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
