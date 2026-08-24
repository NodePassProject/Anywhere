//
//  RoutingExportOperation.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

nonisolated struct RoutingSnapshot {
    let ruleSets: [RoutingRuleSet]
    let customRuleSets: [CustomRoutingRuleSet]
    let configurations: [ProxyConfiguration]
    let chains: [ProxyChain]
}

@MainActor
struct RoutingExportScheduler {
    let debouncer: Debouncer
    let ruleSetStore: RoutingRuleSetStore
    let configurationStore: ConfigurationStore
    let chainStore: ChainStore

    func schedule() {
        debouncer.schedule { [ruleSetStore, configurationStore, chainStore] in
            let snapshot = RoutingSnapshot(
                ruleSets: ruleSetStore.ruleSets,
                customRuleSets: ruleSetStore.customRuleSets,
                configurations: configurationStore.configurations,
                chains: chainStore.chains
            )
            await RoutingExportOperation(snapshot: snapshot).run()
        }
    }
}

@MainActor
struct RoutingExportOperation {
    let snapshot: RoutingSnapshot

    func run() async {
        let ruleSets = snapshot.ruleSets
        let customRuleSets = snapshot.customRuleSets
        let configurations = snapshot.configurations
        let chains = snapshot.chains

        let idsToResolve = ruleSets.compactMap(\.assignedConfigurationId)
        var resolvedTargets: [String: ProxyConfiguration] = [:]
        for assignedId in idsToResolve {
            guard resolvedTargets[assignedId] == nil,
                  let id = UUID(uuidString: assignedId) else { continue }
            if let direct = configurations.first(where: { $0.id == id }) {
                resolvedTargets[assignedId] = direct
            } else if let chain = chains.first(where: { $0.id == id }),
                      let composite = chain.resolveComposite(from: configurations) {
                resolvedTargets[assignedId] = composite
            }
        }

        var resolvedIPsByAddress: [String: String] = [:]
        for configuration in resolvedTargets.values {
            let address = configuration.serverAddress
            guard resolvedIPsByAddress[address] == nil else { continue }
            if let ip = await DNSResolver.shared.resolveHost(address) {
                resolvedIPsByAddress[address] = ip
            }
        }

        await Task.detached {
            var entries: [RoutingBinaryWriter.Entry] = []
            var configurationsById: [String: ProxyConfiguration] = [:]

            for ruleSet in ruleSets.reversed() {
                let explicitId = ruleSet.assignedConfigurationId
                if explicitId == nil, ruleSet.id == "ADBlock" { continue }

                let rules: [RoutingRule]
                if ruleSet.isCustom,
                   let customId = UUID(uuidString: ruleSet.id),
                   let custom = customRuleSets.first(where: { $0.id == customId }) {
                    rules = custom.rules
                } else {
                    rules = RoutingRuleSetStore.loadRules(for: ruleSet.name)
                }
                guard !rules.isEmpty else { continue }

                let action: RoutingBinaryFormat.Action
                var configId: UUID?
                if explicitId == nil {
                    action = .default
                } else if explicitId == "DIRECT" {
                    action = .direct
                } else if explicitId == "REJECT" {
                    action = .reject
                } else if let assignedId = explicitId,
                          let configuration = resolvedTargets[assignedId], let id = UUID(uuidString: assignedId) {
                    action = .proxy
                    configId = id
                    configurationsById[assignedId] = configuration.withResolvedIP(
                        resolvedIPsByAddress[configuration.serverAddress]
                    )
                } else {
                    continue
                }

                let tier: RoutingBinaryFormat.Tier
                if explicitId == nil {
                    tier = .neutral
                } else if ruleSet.isCustom {
                    tier = .user
                } else {
                    tier = ruleSet.name == "ADBlock" ? .adBlock : .builtIn
                }
                entries.append(.init(tier: tier, action: action, configId: configId, name: ruleSet.name, rules: rules))
            }

            let countryCode = AWCore.getBypassCountryCode()
            if !countryCode.isEmpty {
                let bypass = CountryBypassCatalog.shared.rules(for: countryCode)
                if !bypass.isEmpty {
                    entries.append(
                        .init(
                            tier: .bypass,
                            action: .direct,
                            configId: nil,
                            name: String(localized: "Country Bypass"),
                            rules: bypass
                        )
                    )
                }
            }

            let encoder = JSONEncoder()
            encoder.outputFormatting = .sortedKeys
            let configurationData = (try? encoder.encode(configurationsById)) ?? Data([0x7B, 0x7D])  // "{}"
            let data = RoutingBinaryWriter.encode(configurationData: configurationData, entries: entries)

            if data != AWCore.getRoutingData() {
                AWCore.setRoutingData(data)
                AWNotificationCenter.notifyRoutingChanged()
            }
        }.value
    }
}

nonisolated struct RoutingBinaryWriter {
    struct Entry {
        let tier: RoutingBinaryFormat.Tier
        let action: RoutingBinaryFormat.Action
        let configId: UUID?
        let name: String
        let rules: [RoutingRule]
    }

    private var bytes: [UInt8] = []

    static func encode(configurationData: Data, entries: [Entry]) -> Data {
        var writer = RoutingBinaryWriter()
        writer.bytes.reserveCapacity(configurationData.count + entries.reduce(0) { $0 + $1.rules.count * 24 } + 16)

        writer.append(RoutingBinaryFormat.magic)
        writer.u32(UInt32(configurationData.count))
        writer.append(configurationData)
        writer.u32(UInt32(entries.count))

        for entry in entries {
            writer.bytes.append(entry.tier.rawValue)
            writer.bytes.append(entry.action.rawValue)
            if entry.action == .proxy, let id = entry.configId {
                writer.append(withUnsafeBytes(of: id.uuid) { Array($0) })
            }
            let ruleCountOffset = writer.bytes.count
            writer.u32(0)  // back-patched once the kept rules are counted
            var kept: UInt32 = 0
            for rule in entry.rules {
                let value: String
                switch rule.type {
                case .domainSuffix, .domainKeyword: value = rule.value.lowercased()
                case .ipCIDR, .ipCIDR6: value = rule.value
                }
                let utf8 = Array(value.utf8)
                guard utf8.count <= Int(UInt16.max) else { continue }
                writer.bytes.append(UInt8(rule.type.rawValue))
                writer.u16(UInt16(utf8.count))
                writer.append(utf8)
                kept += 1
            }
            writer.patchU32(at: ruleCountOffset, kept)
        }
        
        writer.u32(UInt32(entries.count))
        for entry in entries {
            let utf8 = Array(entry.name.prefix(64).utf8)
            writer.u16(UInt16(utf8.count))
            writer.append(utf8)
        }

        return Data(writer.bytes)
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
