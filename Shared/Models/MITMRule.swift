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

/// Upstream destination for traffic matched by this rule set. ``port`` of
/// nil means "keep the original port", the port the client tried to connect
/// to.
struct MITMRewriteTarget: Codable, Equatable {
    var host: String
    var port: UInt16?
}

/// An ordered group of rewrite rules tied to one domain suffix. The optional
/// ``rewriteTarget`` is what gives the set a coherent upstream; if set,
/// every connection to a host matched by ``domainSuffix`` is redirected
/// to the target, regardless of which rule fires.
struct MITMRuleSet: Codable, Equatable, Identifiable {
    var id = UUID()
    var domainSuffix: String
    var rewriteTarget: MITMRewriteTarget?
    var rules: [MITMRule]

    init(
        id: UUID = UUID(),
        domainSuffix: String,
        rewriteTarget: MITMRewriteTarget? = nil,
        rules: [MITMRule] = []
    ) {
        self.id = id
        self.domainSuffix = domainSuffix
        self.rewriteTarget = rewriteTarget
        self.rules = rules
    }

    private enum CodingKeys: String, CodingKey {
        case domainSuffix
        case rewriteTarget
        case rules
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = UUID()
        self.domainSuffix = try c.decode(String.self, forKey: .domainSuffix)
        self.rewriteTarget = try c.decodeIfPresent(MITMRewriteTarget.self, forKey: .rewriteTarget)
        self.rules = try c.decode([MITMRule].self, forKey: .rules)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(domainSuffix, forKey: .domainSuffix)
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
