//
//  MITMRule.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
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

/// A single rewrite operation. The associated values carry only the fields
/// that operation needs, keeping the editor UI and runtime engine from
/// threading optional fields around.
///
/// Note: ``urlReplace`` rewrites only the path-and-query. The
/// destination of the upstream connection lives on ``MITMRuleSet`` as
/// ``rewriteTarget``, so a single rule set always has a coherent
/// upstream.
enum MITMOperation: Equatable {
    case urlReplace(pattern: String, path: String)
    case headerAdd(name: String, value: String)
    case headerDelete(name: String)
    case headerReplace(pattern: String, name: String, value: String)
    case bodyReplace(pattern: String, body: String)
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
        case .bodyReplace:
            String(localized: "Body Replace")
        }
    }
}

extension MITMOperation: Codable {
    private enum Kind: String, Codable {
        case urlReplace
        case headerAdd
        case headerDelete
        case headerReplace
        case bodyReplace
    }

    private enum CodingKeys: String, CodingKey {
        case kind
        case name
        case value
        case pattern
        case replacement
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(Kind.self, forKey: .kind)
        switch kind {
        case .urlReplace:
            self = .urlReplace(
                pattern: try c.decode(String.self, forKey: .pattern),
                path: try c.decode(String.self, forKey: .replacement)
            )
        case .headerAdd:
            self = .headerAdd(
                name: try c.decode(String.self, forKey: .name),
                value: try c.decode(String.self, forKey: .value)
            )
        case .headerDelete:
            self = .headerDelete(name: try c.decode(String.self, forKey: .name))
        case .headerReplace:
            self = .headerReplace(
                pattern: try c.decode(String.self, forKey: .pattern),
                name: try c.decode(String.self, forKey: .name),
                value: try c.decode(String.self, forKey: .value)
            )
        case .bodyReplace:
            self = .bodyReplace(
                pattern: try c.decode(String.self, forKey: .pattern),
                body: try c.decode(String.self, forKey: .replacement)
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .urlReplace(let pattern, let replacement):
            try c.encode(Kind.urlReplace, forKey: .kind)
            try c.encode(pattern, forKey: .pattern)
            try c.encode(replacement, forKey: .replacement)
        case .headerAdd(let name, let value):
            try c.encode(Kind.headerAdd, forKey: .kind)
            try c.encode(name, forKey: .name)
            try c.encode(value, forKey: .value)
        case .headerDelete(let name):
            try c.encode(Kind.headerDelete, forKey: .kind)
            try c.encode(name, forKey: .name)
        case .headerReplace(let pattern, let name, let value):
            try c.encode(Kind.headerReplace, forKey: .kind)
            try c.encode(pattern, forKey: .pattern)
            try c.encode(name, forKey: .name)
            try c.encode(value, forKey: .value)
        case .bodyReplace(let pattern, let replacement):
            try c.encode(Kind.bodyReplace, forKey: .kind)
            try c.encode(pattern, forKey: .pattern)
            try c.encode(replacement, forKey: .replacement)
        }
    }
}

struct MITMRule: Codable, Equatable, Identifiable {
    var id = UUID()
    var phase: MITMPhase
    var operation: MITMOperation

    init(
        id: UUID = UUID(),
        phase: MITMPhase,
        operation: MITMOperation
    ) {
        self.id = id
        self.phase = phase
        self.operation = operation
    }

    private enum CodingKeys: String, CodingKey {
        case phase
        case operation
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = UUID()
        self.phase = try c.decode(MITMPhase.self, forKey: .phase)
        self.operation = try c.decode(MITMOperation.self, forKey: .operation)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(phase, forKey: .phase)
        try c.encode(operation, forKey: .operation)
    }
}

/// Action applied to traffic matched by a rule set. Three modes:
///
/// - ``transparent``: the outer leg is dialed to ``host``:``port`` instead
///   of the original destination, and request authority headers are
///   rewritten so the upstream sees the redirect target. The client still
///   sees the original SNI on the leaf certificate. ``port`` of nil keeps
///   the original port.
/// - ``redirect302``: no outer leg. The session synthesizes
///   `HTTP/1.1 302 Found` (or h2 equivalent) with
///   `Location: https://<host>[:<port>]<original-path-and-query>`.
/// - ``reject200``: no outer leg. The session synthesizes
///   `HTTP/1.1 200 OK` (or h2 equivalent) with the configured
///   ``rejectBody`` and an optional ``Content-Type`` override.
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

/// Canned response body for ``MITMRewriteAction/reject200``. Three input
/// shapes:
///
/// - ``text``: ``contents`` is plain UTF-8 text. Default Content-Type is
///   `text/plain; charset=utf-8`.
/// - ``gif``: a 43-byte 1×1 transparent GIF89a. ``contents`` is ignored.
///   Default Content-Type is `image/gif`.
/// - ``data``: ``contents`` is base64. Decoded at request time. Default
///   Content-Type is `application/octet-stream`.
///
/// ``contentType`` overrides the default for any kind. Empty / nil keeps
/// the default.
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
struct MITMRuleSet: Codable, Equatable, Identifiable {
    var id = UUID()
    var name: String
    var domainSuffixes: [String]
    var rewriteTarget: MITMRewriteTarget?
    var rules: [MITMRule]

    init(
        id: UUID = UUID(),
        name: String,
        domainSuffixes: [String] = [],
        rewriteTarget: MITMRewriteTarget? = nil,
        rules: [MITMRule] = []
    ) {
        self.id = id
        self.name = name
        self.domainSuffixes = domainSuffixes
        self.rewriteTarget = rewriteTarget
        self.rules = rules
    }

    private enum CodingKeys: String, CodingKey {
        case name
        case domainSuffix       // legacy: single-suffix shape predating named sets
        case domainSuffixes
        case rewriteTarget
        case rules
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = UUID()
        let legacySuffix = try c.decodeIfPresent(String.self, forKey: .domainSuffix)
        if let suffixes = try c.decodeIfPresent([String].self, forKey: .domainSuffixes) {
            self.domainSuffixes = suffixes
        } else if let legacySuffix {
            self.domainSuffixes = [legacySuffix]
        } else {
            self.domainSuffixes = []
        }
        self.name = try c.decodeIfPresent(String.self, forKey: .name) ?? legacySuffix ?? ""
        self.rewriteTarget = try c.decodeIfPresent(MITMRewriteTarget.self, forKey: .rewriteTarget)
        self.rules = try c.decode([MITMRule].self, forKey: .rules)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(name, forKey: .name)
        try c.encode(domainSuffixes, forKey: .domainSuffixes)
        try c.encodeIfPresent(rewriteTarget, forKey: .rewriteTarget)
        try c.encode(rules, forKey: .rules)
    }
}

/// Persisted shape for the MITM feature: master toggle plus the user's
/// rule sets. Owned by the app side via ``MITMRuleSetStore`` and read by the
/// network extension via ``LWIPStack/loadMITMSetting``.
struct MITMSnapshot: Codable, Equatable {
    var enabled: Bool
    var ruleSets: [MITMRuleSet]

    static let empty = MITMSnapshot(enabled: false, ruleSets: [])

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
