//
//  RoutingRuleSetStore.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Observation

private let logger = AnywhereLogger(category: "RoutingRuleSetStore")

struct RoutingRuleSet: Identifiable, Equatable {
    let id: String   // built-in: name, custom: UUID string
    let name: String
    var assignedConfigurationId: String?  // nil = default, "DIRECT" = bypass, "REJECT" = block, UUID string = proxy
    var isCustom: Bool = false
}

struct CustomRoutingRuleSet: Codable, Identifiable, Equatable {
    static let maxRuleCount = 100000

    let id: UUID
    var name: String
    var rules: [RoutingRule]
    /// When set, rules are sourced from a remote `.arrs` file and replaced on refresh.
    var subscriptionURL: URL?
    var deletedAt: Date? = nil

    init(name: String, rules: [RoutingRule] = [], subscriptionURL: URL? = nil) {
        self.id = UUID()
        self.name = name
        self.rules = rules
        self.subscriptionURL = subscriptionURL
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, rules, subscriptionURL, deletedAt
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(UUID.self, forKey: .id)
        self.name = try c.decode(String.self, forKey: .name)
        // A single corrupt rule shouldn't take down the whole set.
        self.rules = try c.decodeSkippingInvalid([RoutingRule].self, forKey: .rules)
        self.subscriptionURL = try c.decodeIfPresent(URL.self, forKey: .subscriptionURL)
        self.deletedAt = try c.decodeIfPresent(Date.self, forKey: .deletedAt)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encode(rules, forKey: .rules)
        try c.encodeIfPresent(subscriptionURL, forKey: .subscriptionURL)
        try c.encodeIfPresent(deletedAt, forKey: .deletedAt)
    }

    /// Returns a parsed http(s) URL whose path ends with `.arrs` (case-insensitive), or nil.
    static func validSubscriptionURL(from rawValue: String) -> URL? {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              url.path.lowercased().hasSuffix(".arrs") else { return nil }
        return url
    }
}

@MainActor
@Observable
class RoutingRuleSetStore {
    static let shared = RoutingRuleSetStore()

    private(set) var ruleSets: [RoutingRuleSet] = []
    private(set) var customRuleSets: [CustomRoutingRuleSet] = []
    private var customTombstones: [CustomRoutingRuleSet] = []
    /// Names of rule sets whose assigned proxy/chain was deleted, surfaced once for the UI.
    private(set) var orphanedRuleSetNames: [String] = []
    
    var bypassCountryCode: String {
        didSet {
            guard bypassCountryCode != oldValue else { return }
            AWCore.setBypassCountryCode(bypassCountryCode)
            scheduleSyncToAppGroup()
        }
    }

    /// Tail of the sync chain; each scheduled run awaits its predecessor.
    @ObservationIgnored private var queuedSync: Task<Void, Never>?

    private static let syncDebounceInterval: Duration = .seconds(2)

    var adBlockRuleSet: RoutingRuleSet? {
        ruleSets.first(where: { $0.name == "ADBlock" })
    }
    var builtInServiceRuleSets: [RoutingRuleSet] {
        ruleSets.filter { $0.name != "ADBlock" }
    }

    private static let builtIn: [String] = {
        serviceCatalog.supportedServices + ["ADBlock"]
    }()

    private static let serviceCatalog = ServiceCatalog.load()
    
    @ObservationIgnored private var loadedBlob: Data?

    private init() {
        bypassCountryCode = AWCore.getBypassCountryCode()
        let assignments = AWCore.getRuleSetAssignments()

        let data = JSONBlobStore.shared.load(.customRuleSets)
        loadedBlob = data
        let split = Self.decodeCustomSplit(from: data)
        customRuleSets = split.live
        customTombstones = split.tombstones

        rebuildRuleSets(assignments: assignments)
        scheduleSyncToAppGroup()
    }
    
    func reload() async {
        let previous = loadedBlob
        let outcome = await Task.detached(priority: .utility) {
            () -> (data: Data?, live: [CustomRoutingRuleSet], tombstones: [CustomRoutingRuleSet])? in
            let data = JSONBlobStore.shared.load(.customRuleSets)
            guard data != previous else { return nil }
            let split = Self.decodeCustomSplit(from: data)
            return (data, split.live, split.tombstones)
        }.value
        guard let outcome else { return }
        loadedBlob = outcome.data
        customRuleSets = outcome.live
        customTombstones = outcome.tombstones
        rebuildRuleSets()
        scheduleSyncToAppGroup()
    }

    private func rebuildRuleSets(assignments: [String: String]? = nil) {
        let assignmentsDict = assignments ?? AWCore.getRuleSetAssignments()

        var sets = Self.builtIn.map { name in
            RoutingRuleSet(id: name, name: name, assignedConfigurationId: assignmentsDict[name])
        }

        // Custom sets sit between Services and ADBlock for display only;
        // runtime match priority is enforced separately by DomainRouter.
        let insertionIndex = sets.firstIndex(where: { $0.id == "ADBlock" }) ?? sets.endIndex
        for (offset, custom) in customRuleSets.enumerated() {
            let id = custom.id.uuidString
            sets.insert(RoutingRuleSet(
                id: id,
                name: custom.name,
                assignedConfigurationId: assignmentsDict[id],
                isCustom: true
            ), at: insertionIndex + offset)
        }

        ruleSets = sets
    }

    // MARK: - Assignment

    func updateAssignment(_ ruleSet: RoutingRuleSet, configurationId: String?) {
        guard let index = ruleSets.firstIndex(where: { $0.id == ruleSet.id }) else { return }
        ruleSets[index].assignedConfigurationId = configurationId
        saveAssignments()
        scheduleSyncToAppGroup()
    }

    func resetAssignments() {
        for builtInServiceRuleSet in builtInServiceRuleSets {
            guard let index = ruleSets.firstIndex(where: { $0.id == builtInServiceRuleSet.id }) else { continue }
            ruleSets[index].assignedConfigurationId = nil
        }
        for customRuleSet in customRuleSets {
            guard let index = ruleSets.firstIndex(where: { $0.id == customRuleSet.id.uuidString }) else { continue }
            ruleSets[index].assignedConfigurationId = nil
        }
        saveAssignments()
        scheduleSyncToAppGroup()
    }

    /// Resets assignments referencing ids not in `availableIds`; returns the affected rule set names.
    func clearOrphanedAssignments(availableIds: Set<String>) -> [String] {
        var affected: [String] = []
        for (index, ruleSet) in ruleSets.enumerated() {
            guard let assignedId = ruleSet.assignedConfigurationId,
                  assignedId != "DIRECT",
                  assignedId != "REJECT",
                  !availableIds.contains(assignedId) else { continue }
            ruleSets[index].assignedConfigurationId = nil
            affected.append(ruleSet.name)
        }
        if !affected.isEmpty {
            saveAssignments()
        }
        return affected
    }

    // MARK: - Custom Rule Set CRUD

    func addCustomRuleSet(name: String) -> CustomRoutingRuleSet {
        let ruleSet = CustomRoutingRuleSet(name: name)
        customRuleSets.append(ruleSet)
        saveCustomRuleSets()
        rebuildRuleSets()
        return ruleSet
    }
    
    func addCustomRuleSet(_ ruleSet: CustomRoutingRuleSet, initialAssignment: String? = nil) {
        customTombstones.removeAll { $0.id == ruleSet.id }
        customRuleSets.append(ruleSet)
        saveCustomRuleSets()
        if let initialAssignment {
            var assignments = AWCore.getRuleSetAssignments()
            assignments[ruleSet.id.uuidString] = initialAssignment
            AWCore.setRuleSetAssignments(assignments)
        }
        rebuildRuleSets()
    }

    func removeCustomRuleSet(_ id: UUID) {
        if let removed = customRuleSets.first(where: { $0.id == id }) {
            recordTombstone(removed)
        }
        customRuleSets.removeAll { $0.id == id }
        saveCustomRuleSets()

        var assignments = AWCore.getRuleSetAssignments()
        assignments.removeValue(forKey: id.uuidString)
        AWCore.setRuleSetAssignments(assignments)

        rebuildRuleSets()
    }

    func updateCustomRuleSet(_ id: UUID, name: String? = nil, rules: [RoutingRule]? = nil) {
        guard let index = customRuleSets.firstIndex(where: { $0.id == id }) else { return }
        if let name { customRuleSets[index].name = name }
        if let rules { customRuleSets[index].rules = rules }
        saveCustomRuleSets()
        rebuildRuleSets()
    }

    /// Persists a user-driven reorder; order sets both display position and User-tier match priority.
    func reorderCustomRuleSets(_ ordered: [CustomRoutingRuleSet]) {
        guard Set(ordered.map(\.id)) == Set(customRuleSets.map(\.id)) else { return }
        customRuleSets = ordered
        saveCustomRuleSets()
        rebuildRuleSets()
    }

    /// Fetches and parses the subscription `.arrs` file, replacing the set's rules; the user-given name is preserved.
    func refreshCustomRuleSet(_ id: UUID) async throws {
        guard let index = customRuleSets.firstIndex(where: { $0.id == id }),
              let url = customRuleSets[index].subscriptionURL else {
            throw CustomRoutingRuleSetRefreshError.missingSubscriptionURL
        }

        let (data, response) = try await URLSession.shared.data(from: url)
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw CustomRoutingRuleSetRefreshError.invalidStatusCode(http.statusCode)
        }
        guard let body = String(data: data, encoding: .utf8) else {
            throw CustomRoutingRuleSetRefreshError.undecodableBody
        }

        let parsed = RoutingRuleSetParser.parse(body)
        guard parsed.rules.count <= CustomRoutingRuleSet.maxRuleCount else {
            throw CustomRoutingRuleSetRefreshError.tooManyRules
        }
        customRuleSets[index].rules = parsed.rules
        saveCustomRuleSets()
        rebuildRuleSets()
    }

    func customRuleSet(for id: UUID) -> CustomRoutingRuleSet? {
        customRuleSets.first { $0.id == id }
    }

    // MARK: - Rules

    /// Loads rules for a built-in rule set name. Thread-safe — no instance state accessed.
    static func loadRules(for name: String) -> [RoutingRule] {
        if name != "ADBlock" {
            return serviceCatalog.rules(for: name)
        }
        return RoutingRulesDatabase.shared.loadRules(for: name)
    }

    // MARK: - App Group Sync

    private func syncToAppGroup(configurations: [ProxyConfiguration], chains: [ProxyChain]) async {
        let snapshot = ruleSets
        let customSnapshot = customRuleSets
        
        var resolvedTargets: [String: ProxyConfiguration] = [:]
        for ruleSet in snapshot {
            guard let assignedId = ruleSet.assignedConfigurationId,
                  let id = UUID(uuidString: assignedId) else { continue }
            if let direct = configurations.first(where: { $0.id == id }) {
                resolvedTargets[assignedId] = direct
            } else if let chain = chains.first(where: { $0.id == id }),
                      let composite = chain.resolveComposite(from: configurations) {
                resolvedTargets[assignedId] = composite
            }
        }

        await Task.detached {
            var entries: [RoutingBinaryWriter.Entry] = []
            var configurationsDict: [String: Any] = [:]

            for ruleSet in snapshot {
                guard let assignedId = ruleSet.assignedConfigurationId else { continue }

                let rules: [RoutingRule]
                if ruleSet.isCustom,
                   let customId = UUID(uuidString: ruleSet.id),
                   let custom = customSnapshot.first(where: { $0.id == customId }) {
                    rules = custom.rules
                } else {
                    rules = await Self.loadRules(for: ruleSet.name)
                }
                guard !rules.isEmpty else { continue }
                
                let action: RoutingBinaryFormat.Action
                var configId: UUID?
                if assignedId == "DIRECT" {
                    action = .direct
                } else if assignedId == "REJECT" {
                    action = .reject
                } else if let configuration = resolvedTargets[assignedId], let id = UUID(uuidString: assignedId) {
                    action = .proxy
                    configId = id
                    var serialized = configuration.serializedConfiguration
                    if let resolvedIP = VPNViewModel.resolveServerAddress(configuration.serverAddress) {
                        serialized["resolvedIP"] = resolvedIP
                    }
                    configurationsDict[assignedId] = serialized
                } else {
                    continue
                }

                let tier: RoutingBinaryFormat.Tier = ruleSet.isCustom ? .user
                    : (ruleSet.name == "ADBlock" ? .adBlock : .builtIn)
                entries.append(.init(tier: tier, action: action, configId: configId, rules: rules))
            }

            let countryCode = AWCore.getBypassCountryCode()
            if !countryCode.isEmpty {
                let bypass = await CountryBypassCatalog.shared.rules(for: countryCode)
                if !bypass.isEmpty {
                    entries.append(.init(tier: .bypass, action: .direct, configId: nil, rules: bypass))
                }
            }
            
            let configurationData = (try? JSONSerialization.data(withJSONObject: configurationsDict, options: .sortedKeys))
                ?? Data([0x7B, 0x7D])  // "{}"
            let data = RoutingBinaryWriter.encode(configurationData: configurationData, entries: entries)

            if data != AWCore.getRoutingData() {
                AWCore.setRoutingData(data)
                AWCore.notifyRoutingChanged()
            }
        }.value
    }

    // MARK: - Persistence

    private func saveAssignments() {
        let dict = Dictionary(uniqueKeysWithValues: ruleSets.compactMap { rs in
            rs.assignedConfigurationId.map { (rs.id, $0) }
        })
        AWCore.setRuleSetAssignments(dict)
    }

    /// `nonisolated` so the remote-change refresh can decode off the main actor (see `reload`).
    nonisolated private static func decodeCustomSplit(from data: Data?) -> (live: [CustomRoutingRuleSet], tombstones: [CustomRoutingRuleSet]) {
        guard let data,
              let all = JSONDecoder().decodeSkippingInvalid([CustomRoutingRuleSet].self, from: data) else {
            return ([], [])
        }
        return Tombstone.split(all)
    }
    
    private func recordTombstone(_ ruleSet: CustomRoutingRuleSet) {
        var tomb = ruleSet
        tomb.deletedAt = .now
        customTombstones.removeAll { $0.id == ruleSet.id }
        customTombstones.append(tomb)
    }

    private func saveCustomRuleSets() {
        if let data = try? JSONEncoder().encode(customRuleSets + customTombstones) {
            JSONBlobStore.shared.save(.customRuleSets, data: data)
        }
        scheduleSyncToAppGroup()
    }
    
    func scheduleSyncToAppGroup() {
        let previous = queuedSync
        previous?.cancel()
        queuedSync = Task {
            try? await Task.sleep(for: Self.syncDebounceInterval)
            guard !Task.isCancelled else { return }
            await previous?.value
            // Superseded while waiting — the newer task carries the work.
            guard !Task.isCancelled else { return }
            await syncToAppGroup()
        }
    }
}

// MARK: - App Group Sync & Orphan Cleanup (convenience)

extension RoutingRuleSetStore {
    private func syncToAppGroup() async {
        await syncToAppGroup(configurations: ConfigurationStore.shared.configurations,
                             chains: ChainStore.shared.chains)
    }

    /// Clears assignments whose target proxy/chain no longer exists and records the affected names for the UI.
    func clearOrphans(configurations: [ProxyConfiguration], chains: [ProxyChain]) {
        let availableIds = Set(configurations.map { $0.id.uuidString })
            .union(chains.map { $0.id.uuidString })
        let affected = clearOrphanedAssignments(availableIds: availableIds)
        if !affected.isEmpty { orphanedRuleSetNames = affected }
    }

    /// Dismisses the orphaned-rule-set notice.
    func acknowledgeOrphans() {
        orphanedRuleSetNames = []
    }
}

private struct RoutingBinaryWriter {
    struct Entry {
        let tier: RoutingBinaryFormat.Tier
        let action: RoutingBinaryFormat.Action
        let configId: UUID?
        let rules: [RoutingRule]
    }

    private var bytes: [UInt8] = []

    static func encode(configurationData: Data, entries: [Entry]) -> Data {
        var w = RoutingBinaryWriter()
        w.bytes.reserveCapacity(configurationData.count + entries.reduce(0) { $0 + $1.rules.count * 24 } + 16)

        w.append(RoutingBinaryFormat.magic)
        w.u32(UInt32(configurationData.count))
        w.append(configurationData)
        w.u32(UInt32(entries.count))

        for entry in entries {
            w.bytes.append(entry.tier.rawValue)
            w.bytes.append(entry.action.rawValue)
            if entry.action == .proxy, let id = entry.configId {
                w.append(withUnsafeBytes(of: id.uuid) { Array($0) })
            }
            let ruleCountOffset = w.bytes.count
            w.u32(0)  // back-patched once the kept rules are counted
            var kept: UInt32 = 0
            for rule in entry.rules {
                // Case-fold domain values here, on the host: the extension stores
                // suffix rules straight from these bytes (no per-rule folding),
                // and folding once on the memory-rich host matches the lookup
                // path, which lowercases the queried host. CIDR values are
                // case-insensitive already and pass through untouched.
                let value: String
                switch rule.type {
                case .domainSuffix, .domainKeyword: value = rule.value.lowercased()
                case .ipCIDR, .ipCIDR6: value = rule.value
                }
                let utf8 = Array(value.utf8)
                guard utf8.count <= Int(UInt16.max) else { continue }
                w.bytes.append(UInt8(rule.type.rawValue))
                w.u16(UInt16(utf8.count))
                w.append(utf8)
                kept += 1
            }
            w.patchU32(at: ruleCountOffset, kept)
        }

        return Data(w.bytes)
    }

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
    private mutating func append(_ slice: Data) { bytes.append(contentsOf: slice) }

    private mutating func patchU32(at offset: Int, _ v: UInt32) {
        bytes[offset] = UInt8(truncatingIfNeeded: v)
        bytes[offset + 1] = UInt8(truncatingIfNeeded: v >> 8)
        bytes[offset + 2] = UInt8(truncatingIfNeeded: v >> 16)
        bytes[offset + 3] = UInt8(truncatingIfNeeded: v >> 24)
    }
}

enum CustomRoutingRuleSetRefreshError: LocalizedError {
    case missingSubscriptionURL
    case invalidStatusCode(Int)
    case undecodableBody
    case tooManyRules

    var errorDescription: String? {
        switch self {
        case .missingSubscriptionURL:
            return "This rule set has no subscription URL."
        case .invalidStatusCode(let code):
            return "HTTP \(code)"
        case .undecodableBody:
            return String(localized: "Unknown content.")
        case .tooManyRules:
            return String(localized: "Rule set is too large.")
        }
    }
}
