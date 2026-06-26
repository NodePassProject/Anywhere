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

/// `path` is a JSONPath; `value`/`values` are JSON literals, but a non-JSON
/// string is taken literally (`value = Anywhere` means `"Anywhere"`).
enum MITMJSONOperation: Equatable {
    /// Upsert: create or overwrite the addressed member; an array index appends when index == count.
    case add(path: String, value: String)
    /// Modify-in-place: a no-op when the addressed member doesn't already exist.
    case replace(path: String, value: String)
    case delete(path: String)
    /// Overwrite every existing property named `key` at any depth; never creates.
    case replaceRecursive(key: String, value: String)
    /// Remove every property named `key` at any depth.
    case deleteRecursive(key: String)
    /// At the array at `path`, drop every object element that contains `key`.
    case removeWhereKeyExists(path: String, key: String)
    /// At the array at `path`, drop every object element whose `field` equals
    /// one of `values` (a JSON array literal, or a lone scalar).
    case removeWhereFieldIn(path: String, field: String, values: String)
}

extension MITMJSONOperation: CustomStringConvertible {
    /// Action token; must match the text import format.
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

/// A single rewrite operation; the gating `urlPattern` lives on `MITMRule`.
enum MITMOperation: Equatable {
    /// Request-phase only: rewrites the request URL, redirects with a synthesized
    /// `302`, or rejects with a synthesized `200`, per the `MITMRewriteAction` sub-mode.
    case rewrite(MITMRewriteAction)
    case headerAdd(name: String, value: String)
    case headerDelete(name: String)
    /// Overwrites every header named `name` (case-insensitive); absent headers are untouched.
    case headerReplace(name: String, value: String)
    /// JavaScript transform; `scriptBase64` is base64 UTF-8 source defining
    /// `function process(ctx)`. Single-rule by design: at most one `.script`
    /// fires per message, last match wins.
    case script(scriptBase64: String)
    /// Per-frame script for streaming bodies: runs once per HTTP/2 DATA frame or
    /// HTTP/1 chunk, without buffering or decompression. HTTP/1 Content-Length
    /// bodies are skipped; beats a matching `script`, otherwise last match wins.
    case streamScript(scriptBase64: String)
    /// Regex find-and-replace over the buffered, decompressed text body; every
    /// matching rule fires in rule order. Fail-closed: a non-UTF-8 body or a
    /// search with no matches leaves the body untouched.
    case bodyReplace(search: String, replacement: String)
    /// Native JSON body edit over the buffered, decompressed body; every matching
    /// rule fires in rule order, and a matching `script` runs after the edits.
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
    /// `NSRegularExpression` over the whole request URL (`https://host/path?query`);
    /// the set's domain suffixes gate the host first.
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

extension MITMRule {
    var summaryTitle: String {
        "\(phase.description) \(operation.description)"
    }

    var summarySubtitle: String {
        switch operation {
        case .rewrite(let action):
            switch action {
            case .transparent(let url), .redirect302(let url):
                return url
            case .reject200Text:
                return String(localized: "Reject Text")
            case .reject200Gif:
                return String(localized: "Reject GIF")
            case .reject200Data:
                return String(localized: "Reject Data")
            }
        case .headerAdd(let name, _):
            return name
        case .headerDelete(let name):
            return name
        case .headerReplace(let name, _):
            return name
        case .script(let scriptBase64),
             .streamScript(let scriptBase64):
            let bytes = Data(base64Encoded: scriptBase64)?.count ?? 0
            return String(localized: "\(bytes) byte(s)")
        case .bodyReplace(let search, _):
            return search
        case .bodyJSON(let operation):
            return operation.description
        }
    }
}

/// Cases map 1:1 to the import format's numeric ids (transparent 0 … reject200Data 4).
/// Only `transparent` dials upstream — it rewrites the URL and `Host`/`:authority`;
/// the rest synthesize the response locally.
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

struct MITMRuleSet: Codable, Equatable, Identifiable {
    static let maxRuleCount = 10000

    var id = UUID()
    var name: String
    /// Per-set master switch; a disabled set stays editable but matches no traffic.
    var enabled: Bool
    var domainSuffixes: [String]
    var rules: [MITMRule]
    /// When set, the suffixes and rules are sourced from a remote `.amrs` file
    /// and replaced on refresh; `id` and `name` are preserved.
    var subscriptionURL: URL?
    var deletedAt: Date? = nil

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
        case deletedAt
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // Persisted id keeps MITMScriptStore scope keys stable across reloads;
        // pre-id blobs decode with a fresh UUID.
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
        self.deletedAt = try c.decodeIfPresent(Date.self, forKey: .deletedAt)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encode(enabled, forKey: .enabled)
        try c.encode(domainSuffixes, forKey: .domainSuffixes)
        try c.encode(rules, forKey: .rules)
        try c.encodeIfPresent(subscriptionURL, forKey: .subscriptionURL)
        try c.encodeIfPresent(deletedAt, forKey: .deletedAt)
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

struct MITMSnapshot: Codable, Equatable {
    var enabled: Bool
    var ruleSets: [MITMRuleSet]

    static let empty = MITMSnapshot(enabled: false, ruleSets: [])

    /// Rule sets minus soft-deleted tombstones — the set the data path should actually apply.
    var liveRuleSets: [MITMRuleSet] { ruleSets.filter { $0.deletedAt == nil } }

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
    
    static func load() -> MITMSnapshot {
        decode(from: JSONBlobStore.shared.load(.mitm))
    }
    
    nonisolated static func decode(from data: Data?) -> MITMSnapshot {
        if let data, let snapshot = try? JSONDecoder().decode(MITMSnapshot.self, from: data) {
            return snapshot
        }
        if let data = UserDefaults(suiteName: AWCore.Identifier.appGroupSuite)?.data(forKey: legacyMITMDefaultsKey),
           let snapshot = try? JSONDecoder().decode(MITMSnapshot.self, from: data) {
            return snapshot
        }
        return .empty
    }

    private static let legacyMITMDefaultsKey = "mitmData"

    /// Persists the snapshot and fires the Darwin notification the extension observes.
    func save() {
        guard let data = try? JSONEncoder().encode(self) else { return }
        JSONBlobStore.shared.save(.mitm, data: data)
        exportBinaryToAppGroup()
        AWNotificationCenter.notifyMITMChanged()
    }
    
    func exportBinaryToAppGroup() {
        let data = MITMBinaryWriter.encode(enabled: enabled, ruleSets: liveRuleSets)
        if data != AWCore.getMITMData() {
            AWCore.setMITMData(data)
        }
    }
}

// MARK: - Binary serialization

/// On-disk layout of the MITM payload the host writes and the Network Extension
/// reads, mirroring the routing payload (see `RoutingBinaryFormat`): a compact
/// binary the NE mmaps, so it never opens the SwiftData store to read rules.
///
/// All integers little-endian; strings are length-prefixed UTF-8 (`str16` =
/// UInt16 length + bytes, `str32` = UInt32 length + bytes). Layout:
/// ```
/// magic     "AMR1"        4 bytes
/// version   UInt8         format version (= 1)
/// enabled   UInt8         master MITM toggle (0/1)
/// setCount  UInt32        number of (live) rule sets
/// sets      setCount × Set
///
/// Set:
///   id          [16]      raw UUID bytes
///   name        str16
///   enabled     UInt8
///   suffixCount UInt16
///   suffixes    suffixCount × str16
///   ruleCount   UInt32
///   rules       ruleCount × Rule
///
/// Rule:
///   phase      UInt8      0 httpRequest · 1 httpResponse
///   urlPattern str32
///   opKind     UInt8      operation discriminator (OpKind)
///   …operation-specific fields…
/// ```
/// `subscriptionURL`/`deletedAt` are intentionally omitted — they're sync-only
/// and the data path never reads them.
enum MITMBinaryFormat {
    static let magic: [UInt8] = [0x41, 0x4D, 0x52, 0x31]  // "AMR1"
    static let version: UInt8 = 1

    enum Phase: UInt8 { case httpRequest = 0, httpResponse = 1 }

    enum OpKind: UInt8 {
        case rewrite = 0, headerAdd = 1, headerDelete = 2, headerReplace = 3
        case script = 4, streamScript = 5, bodyReplace = 6, bodyJSON = 7
    }

    enum RewriteKind: UInt8 {
        case transparent = 0, redirect302 = 1, reject200Text = 2, reject200Gif = 3, reject200Data = 4
    }

    enum JSONAction: UInt8 {
        case add = 0, replace = 1, delete = 2, replaceRecursive = 3
        case deleteRecursive = 4, removeWhereKeyExists = 5, removeWhereFieldIn = 6
    }

    static func phaseByte(_ phase: MITMPhase) -> UInt8 {
        switch phase {
        case .httpRequest: return Phase.httpRequest.rawValue
        case .httpResponse: return Phase.httpResponse.rawValue
        }
    }
}

/// Layout must stay in sync with `RoutingBinaryWriter`.
struct MITMBinaryWriter {
    private var bytes: [UInt8] = []

    static func encode(enabled: Bool, ruleSets: [MITMRuleSet]) -> Data {
        var writer = MITMBinaryWriter()
        writer.append(MITMBinaryFormat.magic)
        writer.bytes.append(MITMBinaryFormat.version)
        writer.bytes.append(enabled ? 1 : 0)
        writer.u32(UInt32(ruleSets.count))
        for set in ruleSets { writer.encodeSet(set) }
        return Data(writer.bytes)
    }

    private mutating func encodeSet(_ set: MITMRuleSet) {
        append(withUnsafeBytes(of: set.id.uuid) { Array($0) })
        str16(set.name)
        bytes.append(set.enabled ? 1 : 0)
        let suffixes = set.domainSuffixes.prefix(Int(UInt16.max))
        u16(UInt16(suffixes.count))
        for suffix in suffixes { str16(suffix) }
        u32(UInt32(set.rules.count))
        for rule in set.rules { encodeRule(rule) }
    }

    private mutating func encodeRule(_ rule: MITMRule) {
        bytes.append(MITMBinaryFormat.phaseByte(rule.phase))
        str32(rule.urlPattern)
        encodeOperation(rule.operation)
    }

    private mutating func encodeOperation(_ operation: MITMOperation) {
        switch operation {
        case .rewrite(let action):
            bytes.append(MITMBinaryFormat.OpKind.rewrite.rawValue)
            encodeRewrite(action)
        case .headerAdd(let name, let value):
            bytes.append(MITMBinaryFormat.OpKind.headerAdd.rawValue)
            str16(name); str32(value)
        case .headerDelete(let name):
            bytes.append(MITMBinaryFormat.OpKind.headerDelete.rawValue)
            str16(name)
        case .headerReplace(let name, let value):
            bytes.append(MITMBinaryFormat.OpKind.headerReplace.rawValue)
            str16(name); str32(value)
        case .script(let scriptBase64):
            bytes.append(MITMBinaryFormat.OpKind.script.rawValue)
            str32(scriptBase64)
        case .streamScript(let scriptBase64):
            bytes.append(MITMBinaryFormat.OpKind.streamScript.rawValue)
            str32(scriptBase64)
        case .bodyReplace(let search, let replacement):
            bytes.append(MITMBinaryFormat.OpKind.bodyReplace.rawValue)
            str32(search); str32(replacement)
        case .bodyJSON(let json):
            bytes.append(MITMBinaryFormat.OpKind.bodyJSON.rawValue)
            encodeJSON(json)
        }
    }

    private mutating func encodeRewrite(_ action: MITMRewriteAction) {
        switch action {
        case .transparent(let url):
            bytes.append(MITMBinaryFormat.RewriteKind.transparent.rawValue); str32(url)
        case .redirect302(let url):
            bytes.append(MITMBinaryFormat.RewriteKind.redirect302.rawValue); str32(url)
        case .reject200Text(let content):
            bytes.append(MITMBinaryFormat.RewriteKind.reject200Text.rawValue); str32(content)
        case .reject200Gif:
            bytes.append(MITMBinaryFormat.RewriteKind.reject200Gif.rawValue)
        case .reject200Data(let base64):
            bytes.append(MITMBinaryFormat.RewriteKind.reject200Data.rawValue); str32(base64)
        }
    }

    private mutating func encodeJSON(_ operation: MITMJSONOperation) {
        switch operation {
        case .add(let path, let value):
            bytes.append(MITMBinaryFormat.JSONAction.add.rawValue); str32(path); str32(value)
        case .replace(let path, let value):
            bytes.append(MITMBinaryFormat.JSONAction.replace.rawValue); str32(path); str32(value)
        case .delete(let path):
            bytes.append(MITMBinaryFormat.JSONAction.delete.rawValue); str32(path)
        case .replaceRecursive(let key, let value):
            bytes.append(MITMBinaryFormat.JSONAction.replaceRecursive.rawValue); str32(key); str32(value)
        case .deleteRecursive(let key):
            bytes.append(MITMBinaryFormat.JSONAction.deleteRecursive.rawValue); str32(key)
        case .removeWhereKeyExists(let path, let key):
            bytes.append(MITMBinaryFormat.JSONAction.removeWhereKeyExists.rawValue); str32(path); str32(key)
        case .removeWhereFieldIn(let path, let field, let values):
            bytes.append(MITMBinaryFormat.JSONAction.removeWhereFieldIn.rawValue); str32(path); str32(field); str32(values)
        }
    }

    // MARK: Primitives

    private mutating func u16(_ v: UInt16) {
        bytes.append(UInt8(truncatingIfNeeded: v))
        bytes.append(UInt8(truncatingIfNeeded: v >> 8))
    }

    private mutating func u32(_ v: UInt32) {
        bytes.append(UInt8(truncatingIfNeeded: v))
        bytes.append(UInt8(truncatingIfNeeded: v >> 8))
        bytes.append(UInt8(truncatingIfNeeded: v >> 16))
        bytes.append(UInt8(truncatingIfNeeded: v >> 24))
    }

    private mutating func append(_ slice: [UInt8]) { bytes.append(contentsOf: slice) }

    /// UInt16-length-prefixed UTF-8; truncates at 65535 bytes (names/suffixes are short).
    private mutating func str16(_ string: String) {
        var utf8 = Array(string.utf8)
        if utf8.count > Int(UInt16.max) { utf8 = Array(utf8.prefix(Int(UInt16.max))) }
        u16(UInt16(utf8.count))
        bytes.append(contentsOf: utf8)
    }

    /// UInt32-length-prefixed UTF-8; for unbounded payloads (patterns, scripts, bodies).
    private mutating func str32(_ string: String) {
        let utf8 = Array(string.utf8)
        u32(UInt32(utf8.count))
        bytes.append(contentsOf: utf8)
    }
}
