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
    static let maxRuleCount = 10000

    let id: UUID
    var name: String
    var rules: [RoutingRule]
    /// When set, rules are sourced from a remote `.arrs` file and replaced on refresh.
    var subscriptionURL: URL?

    init(name: String, rules: [RoutingRule] = [], subscriptionURL: URL? = nil) {
        self.id = UUID()
        self.name = name
        self.rules = rules
        self.subscriptionURL = subscriptionURL
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, rules, subscriptionURL
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(UUID.self, forKey: .id)
        self.name = try c.decode(String.self, forKey: .name)
        // A single corrupt rule shouldn't take down the whole set.
        self.rules = try c.decodeSkippingInvalid([RoutingRule].self, forKey: .rules)
        self.subscriptionURL = try c.decodeIfPresent(URL.self, forKey: .subscriptionURL)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encode(rules, forKey: .rules)
        try c.encodeIfPresent(subscriptionURL, forKey: .subscriptionURL)
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

    private init() {
        bypassCountryCode = AWCore.getBypassCountryCode()
        let assignments = AWCore.getRuleSetAssignments()

        if let data = JSONBlobStore.shared.load(.customRuleSets),
           let decoded = JSONDecoder().decodeSkippingInvalid([CustomRoutingRuleSet].self, from: data) {
            customRuleSets = decoded
        }

        rebuildRuleSets(assignments: assignments)
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

    func addCustomRuleSet(_ ruleSet: CustomRoutingRuleSet) {
        customRuleSets.append(ruleSet)
        saveCustomRuleSets()
        rebuildRuleSets()
    }

    func removeCustomRuleSet(_ id: UUID) {
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

    private func syncToAppGroup(configurations: [ProxyConfiguration], chains: [ProxyChain], serializeConfiguration: @escaping @Sendable (ProxyConfiguration) -> [String: Any]) async {
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
            var userRules: [[String: Any]] = []
            var adBlockRules: [[String: Any]] = []
            var builtInRules: [[String: Any]] = []
            var configurationsDict: [String: Any] = [:]

            for ruleSet in snapshot {
                guard let assignedId = ruleSet.assignedConfigurationId else { continue }

                let domainRules: [RoutingRule]
                if ruleSet.isCustom,
                   let customId = UUID(uuidString: ruleSet.id),
                   let custom = customSnapshot.first(where: { $0.id == customId }) {
                    domainRules = custom.rules
                } else {
                    domainRules = await Self.loadRules(for: ruleSet.name)
                }
                guard !domainRules.isEmpty else { continue }

                let domainRulesArray: [[String: Any]] = domainRules.compactMap {
                    switch $0.type {
                    case .domainSuffix, .domainKeyword:
                        return ["type": $0.type.rawValue, "value": $0.value]
                    case .ipCIDR, .ipCIDR6:
                        return nil
                    }
                }
                let ipRulesArray: [[String: Any]] = domainRules.compactMap {
                    switch $0.type {
                    case .ipCIDR, .ipCIDR6:
                        return ["type": $0.type.rawValue, "value": $0.value]
                    case .domainSuffix, .domainKeyword:
                        return nil
                    }
                }
                var ruleEntry: [String: Any] = ["domainRules": domainRulesArray]
                if !ipRulesArray.isEmpty {
                    ruleEntry["ipRules"] = ipRulesArray
                }

                if assignedId == "DIRECT" {
                    ruleEntry["action"] = "direct"
                } else if assignedId == "REJECT" {
                    ruleEntry["action"] = "reject"
                } else if let configuration = resolvedTargets[assignedId] {
                    ruleEntry["action"] = "proxy"
                    ruleEntry["configId"] = assignedId
                    var serialized = serializeConfiguration(configuration)
                    if let resolvedIP = VPNViewModel.resolveServerAddress(configuration.serverAddress) {
                        serialized["resolvedIP"] = resolvedIP
                    }
                    configurationsDict[assignedId] = serialized
                } else {
                    continue
                }

                if ruleSet.isCustom {
                    userRules.append(ruleEntry)
                } else if ruleSet.name == "ADBlock" {
                    adBlockRules.append(ruleEntry)
                } else {
                    builtInRules.append(ruleEntry)
                }
            }

            var bypassRules: [[String: Any]] = []
            let countryCode = AWCore.getBypassCountryCode()
            if !countryCode.isEmpty {
                let rules = await CountryBypassCatalog.shared.rules(for: countryCode)
                bypassRules = rules.map {
                    ["type": $0.type.rawValue, "value": $0.value]
                }
            }

            var routing: [String: Any] = ["configs": configurationsDict]
            if !userRules.isEmpty { routing["userRules"] = userRules }
            if !adBlockRules.isEmpty { routing["adBlockRules"] = adBlockRules }
            if !builtInRules.isEmpty { routing["builtInRules"] = builtInRules }
            if !bypassRules.isEmpty { routing["bypassRules"] = bypassRules }

            // sortedKeys makes the bytes deterministic, so an unchanged
            // payload is detected here and produces no write and no reload.
            if let data = try? JSONSerialization.data(withJSONObject: routing, options: .sortedKeys),
               data != AWCore.getRoutingData() {
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

    private func saveCustomRuleSets() {
        if let data = try? JSONEncoder().encode(customRuleSets) {
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
                             chains: ChainStore.shared.chains,
                             serializeConfiguration: Self.serializeConfiguration)
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

    // MARK: - Configuration Serialization

    /// Serializes a configuration into the `[String: Any]` shape the Network Extension's routing layer expects.
    nonisolated static func serializeConfiguration(_ configuration: ProxyConfiguration) -> [String: Any] {
        let vlessUUID: UUID
        let vlessEncryption: String
        let vlessFlow: String?
        if case .vless(let u, let enc, let fl, _, _, _, _) = configuration.outbound {
            vlessUUID = u; vlessEncryption = enc; vlessFlow = fl
        } else {
            vlessUUID = configuration.id; vlessEncryption = "none"; vlessFlow = nil
        }
        var configurationDict: [String: Any] = [
            "name": configuration.name,
            "serverAddress": configuration.serverAddress,
            "serverPort": configuration.serverPort,
            "uuid": vlessUUID.uuidString,
            "encryption": vlessEncryption,
            "flow": vlessFlow ?? "",
            "security": configuration.securityLayer.tag,
            "muxEnabled": configuration.muxEnabled,
            "xudpEnabled": configuration.xudpEnabled,
            "outboundProtocol": configuration.outboundProtocol.rawValue,
        ]

        switch configuration.outbound {
        case .vless: break
        case .hysteria(let password, let congestionControl, let uploadMbps, let downloadMbps, let portHopping, let sni):
            configurationDict["hysteriaPassword"] = password
            configurationDict["hysteriaCongestionControl"] = congestionControl.rawValue
            configurationDict["hysteriaUploadMbps"] = uploadMbps
            configurationDict["hysteriaDownloadMbps"] = downloadMbps
            if let portHopping {
                configurationDict["hysteriaPorts"] = portHopping.portsSpec
                configurationDict["hysteriaHopInterval"] = portHopping.intervalSeconds
            }
            configurationDict["hysteriaSNI"] = sni
        case .nowhere(let key):
            configurationDict["nowhereKey"] = key
        case .trojan(let password, let tls):
            configurationDict["trojanPassword"] = password
            configurationDict["trojanSNI"] = tls.serverName
            if let alpn = tls.alpn, !alpn.isEmpty {
                configurationDict["trojanALPN"] = alpn.joined(separator: ",")
            }
            configurationDict["trojanFingerprint"] = tls.fingerprint.rawValue
        case .anytls(let password, let ici, let it, let mis, let tls):
            configurationDict["anytlsPassword"] = password
            configurationDict["anytlsIdleCheckInterval"] = ici
            configurationDict["anytlsIdleTimeout"] = it
            configurationDict["anytlsMinIdleSession"] = mis
            configurationDict["anytlsSNI"] = tls.serverName
            if let alpn = tls.alpn, !alpn.isEmpty {
                configurationDict["anytlsALPN"] = alpn.joined(separator: ",")
            }
            configurationDict["anytlsFingerprint"] = tls.fingerprint.rawValue
        case .shadowsocks(let password, let method):
            configurationDict["ssPassword"] = password
            configurationDict["ssMethod"] = method
        case .socks5(let username, let password):
            if let username { configurationDict["socks5Username"] = username }
            if let password { configurationDict["socks5Password"] = password }
        case .sudoku(let sudoku):
            configurationDict["sudokuKey"] = sudoku.key
            configurationDict["sudokuAEADMethod"] = sudoku.aeadMethod.rawValue
            configurationDict["sudokuPaddingMin"] = sudoku.paddingMin
            configurationDict["sudokuPaddingMax"] = sudoku.paddingMax
            configurationDict["sudokuASCIIMode"] = sudoku.asciiMode.rawValue
            configurationDict["sudokuCustomTables"] = sudoku.customTables
            configurationDict["sudokuEnablePureDownlink"] = sudoku.enablePureDownlink
            configurationDict["sudokuHTTPMaskDisable"] = sudoku.httpMask.disable
            configurationDict["sudokuHTTPMaskMode"] = sudoku.httpMask.mode.rawValue
            configurationDict["sudokuHTTPMaskTLS"] = sudoku.httpMask.tls
            configurationDict["sudokuHTTPMaskHost"] = sudoku.httpMask.host
            configurationDict["sudokuHTTPMaskPathRoot"] = sudoku.httpMask.pathRoot
            configurationDict["sudokuHTTPMaskMultiplex"] = sudoku.httpMask.multiplex.rawValue
        case .http11(let username, let password):
            configurationDict["http11Username"] = username
            configurationDict["http11Password"] = password
        case .http2(let username, let password):
            configurationDict["http2Username"] = username
            configurationDict["http2Password"] = password
        case .http3(let username, let password):
            configurationDict["http3Username"] = username
            configurationDict["http3Password"] = password
        }

        if case .reality(let reality) = configuration.securityLayer {
            configurationDict["realityServerName"] = reality.serverName
            configurationDict["realityPublicKey"] = reality.publicKey.base64EncodedString()
            configurationDict["realityShortId"] = reality.shortId.map { String(format: "%02x", $0) }.joined()
            configurationDict["realityFingerprint"] = reality.fingerprint.rawValue
        }

        if case .tls(let tls) = configuration.securityLayer {
            configurationDict["tlsServerName"] = tls.serverName
            if let alpn = tls.alpn {
                configurationDict["tlsAlpn"] = alpn.joined(separator: ",")
            }
            configurationDict["tlsFingerprint"] = tls.fingerprint.rawValue
        }

        if configuration.outboundProtocol == .vless {
            configurationDict["transport"] = configuration.transportLayer.tag
            if case .ws(let ws) = configuration.transportLayer {
                configurationDict["wsHost"] = ws.host
                configurationDict["wsPath"] = ws.path
                if !ws.headers.isEmpty {
                    configurationDict["wsHeaders"] = ws.headers.map { "\($0.key):\($0.value)" }.joined(separator: ",")
                }
                configurationDict["wsMaxEarlyData"] = ws.maxEarlyData
                configurationDict["wsEarlyDataHeaderName"] = ws.earlyDataHeaderName
            }

            if case .httpUpgrade(let hu) = configuration.transportLayer {
                configurationDict["huHost"] = hu.host
                configurationDict["huPath"] = hu.path
                if !hu.headers.isEmpty {
                    configurationDict["huHeaders"] = hu.headers.map { "\($0.key):\($0.value)" }.joined(separator: ",")
                }
            }

            if case .grpc(let grpc) = configuration.transportLayer {
                configurationDict["grpcServiceName"] = grpc.serviceName
                configurationDict["grpcAuthority"] = grpc.authority
                configurationDict["grpcMultiMode"] = grpc.multiMode
                configurationDict["grpcUserAgent"] = grpc.userAgent
                configurationDict["grpcInitialWindowsSize"] = grpc.initialWindowsSize
                configurationDict["grpcIdleTimeout"] = grpc.idleTimeout
                configurationDict["grpcHealthCheckTimeout"] = grpc.healthCheckTimeout
                configurationDict["grpcPermitWithoutStream"] = grpc.permitWithoutStream
            }

            if case .xhttp(let xhttp) = configuration.transportLayer {
                configurationDict["xhttpHost"] = xhttp.host
                configurationDict["xhttpPath"] = xhttp.path
                configurationDict["xhttpMode"] = xhttp.mode.rawValue
                if !xhttp.headers.isEmpty {
                    configurationDict["xhttpHeaders"] = xhttp.headers.map { "\($0.key):\($0.value)" }.joined(separator: ",")
                }
                configurationDict["xhttpNoGRPCHeader"] = xhttp.noGRPCHeader
                // Carry downloadSettings as one JSON value (lossless) rather than flattening each field.
                if let ds = xhttp.downloadSettings,
                   let data = try? JSONEncoder().encode(ds),
                   let json = String(data: data, encoding: .utf8) {
                    configurationDict["xhttpDownloadSettings"] = json
                }
            }
        }

        if let chain = configuration.chain, !chain.isEmpty {
            configurationDict["chain"] = chain.map { Self.serializeConfiguration($0) }
        }

        return configurationDict
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
