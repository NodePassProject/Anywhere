//
//  RouteAttributor.swift
//  Anywhere
//
//  Created by NodePassProject on 7/6/26.
//

import Foundation
import Observation

// MARK: - RouteRuleIndex
//
// The host app's parallel decision maker: the extension's own matching engine
// (TieredRouteMatcher, shared source) built straight from the rule-set stores
// so every match keeps the rule set it came from — identity the compiled
// routing payload erases (RoutingBinaryWriter folds rule sets into bare
// tier/action entries). The extension is never consulted or modified;
// RouteAttributor replays each logged decision here, purely to label it.
//
// The builder must mirror RoutingBinaryWriter's write path: domain values
// fold to lowercase, values longer than UInt16.max UTF-8 bytes are dropped,
// and rule sets stream in store order so insertion-order tie-breaks agree.

nonisolated struct RouteRuleIndex: Sendable {

    struct Match: Hashable, Sendable {
        let action: RouteTarget
        let ruleSetName: String
    }
    
    enum SourceTier: Int, CaseIterable, Sendable {
        case user = 0
        case adBlock = 1
        case builtIn = 2
        case bypass = 3
    }

    enum RulesSource: Sendable {
        case inline([RoutingRule])
        /// Loaded inside `build` via `RoutingRulesDatabase` (thread-safe), so
        /// the SQLite reads stay off the main actor.
        case database(String)
    }

    struct SourceEntry: Sendable {
        let tier: SourceTier
        let action: RouteTarget
        let ruleSetName: String
        let rules: RulesSource
    }

    private let matcher: TieredRouteMatcher<Match>
    /// Snapshot of the setting that gates the extension's resolved-IPv4
    /// second-chance match (`TunnelStack.resolveFakeIP`).
    let preventDNSLeak: Bool

    // MARK: - Build

    static func build(entries: [SourceEntry], preventDNSLeak: Bool) -> RouteRuleIndex {
        var matcher = TieredRouteMatcher<Match>(tierCount: SourceTier.allCases.count)
        // Suffix rules reference a shared byte buffer until finalize copies the
        // matched labels out — the same bulk path the extension feeds from its
        // mapped payload.
        var suffixBytes: [UInt8] = []

        for entry in entries {
            let rules: [RoutingRule]
            switch entry.rules {
            case .inline(let inline):
                rules = inline
            case .database(let source):
                rules = RoutingRulesDatabase.shared.loadRules(for: source)
            }
            guard !rules.isEmpty else { continue }

            let match = Match(action: entry.action, ruleSetName: entry.ruleSetName)
            let tierIndex = entry.tier.rawValue
            for rule in rules {
                switch rule.type {
                case .domainSuffix:
                    let folded = Array(rule.value.lowercased().utf8)
                    guard folded.count <= Int(UInt16.max) else { continue }
                    let offset = suffixBytes.count
                    suffixBytes.append(contentsOf: folded)
                    matcher.tiers[tierIndex].collectSuffix(offset: offset, length: folded.count, payload: match)
                case .domainKeyword:
                    let folded = rule.value.lowercased()
                    guard folded.utf8.count <= Int(UInt16.max) else { continue }
                    matcher.tiers[tierIndex].insertKeyword(folded, payload: match)
                case .ipCIDR:
                    if let parsed = RouteMatching.parseIPv4CIDR(rule.value) {
                        matcher.tiers[tierIndex].insertIPv4(network: parsed.network, prefixLen: parsed.prefixLen, payload: match)
                    }
                case .ipCIDR6:
                    if let parsed = RouteMatching.parseIPv6CIDR(rule.value) {
                        matcher.tiers[tierIndex].insertIPv6(network: parsed.network, prefixLen: parsed.prefixLen, payload: match)
                    }
                }
            }
        }

        suffixBytes.withUnsafeBufferPointer { matcher.finalize(base: $0) }
        return RouteRuleIndex(matcher: matcher, preventDNSLeak: preventDNSLeak)
    }

    private init(matcher: TieredRouteMatcher<Match>, preventDNSLeak: Bool) {
        self.matcher = matcher
        self.preventDNSLeak = preventDNSLeak
    }

    // MARK: - Matching
    
    static func isIPLiteral(_ host: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, host, &v4) == 1 { return true }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, host, &v6) == 1 { return true }
        return false
    }

    func matchDomain(_ domain: String) -> Match? {
        matcher.matchDomain(domain)
    }

    func matchIP(_ ip: String) -> Match? {
        matcher.matchIP(ip)
    }
}

// MARK: - RouteAttributor
//
// Labels request-log entries with the rule set behind each routing decision.
// The index rebuilds when the compiled routing payload's file stamp changes
// (the same signal that makes the extension reload), keeping the replica
// aligned with what the extension actually loaded. A label is shown only when
// the replayed action agrees with the extension-recorded target, so any drift
// (rules edited mid-log, matching skew) yields no label rather than a wrong one.

@MainActor
@Observable
class RouteAttributor {
    static let shared = RouteAttributor()

    enum Decision: Equatable, Sendable {
        case match(action: RouteTarget, ruleSetName: String)
        case unmatched
        /// Domain missed every domain rule; the IP second chance is waiting on
        /// `RuleResolver`'s background resolve — retried on later ticks.
        case awaitingIP
    }

    /// Replayed decision per logged host; observable so rows pick up labels
    /// as replays land.
    private(set) var decisions: [String: Decision] = [:]

    @ObservationIgnored private var index: RouteRuleIndex?
    @ObservationIgnored private var builtStamp: String?
    @ObservationIgnored private var hasBuilt = false
    @ObservationIgnored private var pendingHosts: Set<String> = []
    /// Hosts already handed to `RuleResolver.warm` for this index generation,
    /// so a never-resolving host isn't re-resolved every tick.
    @ObservationIgnored private var warmedHosts: Set<String> = []
    @ObservationIgnored private var replayTask: Task<Void, Never>?

    private init() {}

    // MARK: - View API

    /// Rule set behind `target` for `host`, or nil while unknown (the miss is
    /// queued and `decisions` changes once replayed). Default-routed entries
    /// carry no rule by definition.
    func ruleSetName(forHost host: String, target: RouteTarget, viaDefault: Bool) -> String? {
        guard !viaDefault else { return nil }
        switch decisions[host] {
        case .match(let action, let ruleSetName) where action == target:
            return ruleSetName
        case .match, .unmatched:
            return nil
        case .awaitingIP, nil:
            pendingHosts.insert(host)
            return nil
        }
    }

    func startReplaying() {
        guard replayTask == nil else { return }
        replayTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, !Task.isCancelled else { break }
                await self.tick()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    func stopReplaying() {
        replayTask?.cancel()
        replayTask = nil
    }

    // MARK: - Replay loop

    private func tick() async {
        await rebuildIfStale()
        await flushPending()
    }

    private func rebuildIfStale() async {
        let stamp = AWCore.getRoutingDataStamp()
        guard !hasBuilt || stamp != builtStamp else { return }

        let entries = Self.sourceEntries()
        let preventDNSLeak = AWCore.getPreventDNSLeak()
        let built = await Task.detached(priority: .utility) {
            RouteRuleIndex.build(entries: entries, preventDNSLeak: preventDNSLeak)
        }.value

        index = built
        builtStamp = stamp
        hasBuilt = true
        decisions = [:]
        warmedHosts = []
    }

    private func flushPending() async {
        guard let index else { return }

        var hosts = pendingHosts
        pendingHosts = []
        for (host, decision) in decisions where decision == .awaitingIP {
            hosts.insert(host)
        }
        guard !hosts.isEmpty else { return }

        // Hosts cycle out of the request log within minutes; a blown cap means
        // stale keys, so restart clean and let visible rows repopulate.
        if decisions.count > 512 {
            decisions.removeAll(keepingCapacity: true)
        }

        let hostList = Array(hosts)
        let replayed = await Task.detached(priority: .utility) {
            var results: [String: Decision] = [:]
            results.reserveCapacity(hostList.count)
            for host in hostList {
                results[host] = Self.replay(index: index, host: host)
            }
            return results
        }.value

        for (host, decision) in replayed {
            decisions[host] = decision
            if decision == .awaitingIP, !warmedHosts.contains(host) {
                warmedHosts.insert(host)
                RuleResolver.shared.warm(host)
            }
        }
    }

    /// One host through the replica, following the extension's order: IP
    /// literals against CIDR rules; domains against domain rules, then — like
    /// `TunnelStack.resolveFakeIP` — a second chance against CIDR rules via a
    /// locally resolved IPv4 unless Prevent DNS Leak is on.
    nonisolated private static func replay(index: RouteRuleIndex, host: String) -> Decision {
        if RouteRuleIndex.isIPLiteral(host) {
            guard let match = index.matchIP(host) else { return .unmatched }
            return .match(action: match.action, ruleSetName: match.ruleSetName)
        }
        if let match = index.matchDomain(host) {
            return .match(action: match.action, ruleSetName: match.ruleSetName)
        }
        if !index.preventDNSLeak {
            guard let resolvedIP = RuleResolver.shared.cachedIPv4(for: host) else { return .awaitingIP }
            if let match = index.matchIP(resolvedIP) {
                return .match(action: match.action, ruleSetName: match.ruleSetName)
            }
        }
        return .unmatched
    }

    // MARK: - Source snapshot
    
    private static func sourceEntries() -> [RouteRuleIndex.SourceEntry] {
        let store = RoutingRuleSetStore.shared
        let configurations = ConfigurationStore.shared.configurations
        let chains = ChainStore.shared.chains
        let defaultTargetId = (AWCore.getSelectedChainId() ?? AWCore.getSelectedConfigurationId())?.uuidString

        func resolvable(_ assignedId: String) -> Bool {
            guard let id = UUID(uuidString: assignedId) else { return false }
            if configurations.contains(where: { $0.id == id }) { return true }
            if let chain = chains.first(where: { $0.id == id }) {
                return chain.resolveComposite(from: configurations) != nil
            }
            return false
        }

        var entries: [RouteRuleIndex.SourceEntry] = []
        for ruleSet in store.ruleSets {
            guard let assignedId = ruleSet.assignedConfigurationId ?? defaultTargetId else { continue }

            let action: RouteTarget
            if assignedId == "DIRECT" {
                action = .direct
            } else if assignedId == "REJECT" {
                action = .reject
            } else if resolvable(assignedId), let id = UUID(uuidString: assignedId) {
                action = .proxy(id)
            } else {
                continue
            }

            let tier: RouteRuleIndex.SourceTier = ruleSet.isCustom ? .user
                : (ruleSet.name == "ADBlock" ? .adBlock : .builtIn)
            let rules: RouteRuleIndex.RulesSource
            if ruleSet.isCustom,
               let customId = UUID(uuidString: ruleSet.id),
               let custom = store.customRuleSets.first(where: { $0.id == customId }) {
                rules = .inline(custom.rules)
            } else {
                rules = .database(ruleSet.name)
            }
            entries.append(.init(tier: tier, action: action, ruleSetName: ruleSet.name, rules: rules))
        }

        let countryCode = store.bypassCountryCode
        if !countryCode.isEmpty {
            entries.append(.init(
                tier: .bypass,
                action: .direct,
                ruleSetName: String(localized: "Country Bypass"),
                rules: .database(countryCode)
            ))
        }
        return entries
    }
}
