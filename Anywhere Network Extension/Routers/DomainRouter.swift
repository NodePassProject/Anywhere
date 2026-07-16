//
//  DomainRouter.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "DomainRouter")

nonisolated class DomainRouter {

    // MARK: - Tier model
    //
    // Cross-source priority is tier query order (User > ADBlock > Built-in > Country
    // Bypass); within a tier, suffix beats keyword and deepest/longest match wins.
    // The matching machinery lives in TieredRouteMatcher (Shared). Payloads carry
    // the action plus the payload's entry index.

    private enum Tier: Int, CaseIterable {
        case user = 0
        case adBlock = 1
        case builtIn = 2
        case bypass = 3
    }

    /// Matcher payload: POD so hot-path lookups stay ARC-free. `entryIndex`
    /// resolves to a display name via `RoutingState.ruleSetNames`.
    private struct RulePayload: Hashable, Sendable {
        var action: RouteTarget
        var entryIndex: UInt16
    }

    /// A routing decision plus the rule set behind it. `ruleSetName` is nil when
    /// the loaded payload predates the names section.
    struct Match: Sendable {
        let action: RouteTarget
        let ruleSetName: String?
    }

    /// `matcher` + `configurationMap`, guarded as one unit (lookups run on both the lwIP and UDP
    /// queues); reloads hold the lock across the whole compile so a lookup never sees a half-built tier.
    private struct RoutingState {
        var matcher = TieredRouteMatcher<RulePayload>(tierCount: Tier.allCases.count)
        var configurationMap: [UUID: ProxyConfiguration] = [:]
        /// Rule-set display names by payload entry index; empty for older payloads.
        var ruleSetNames: [String] = []

        func match(resolving payload: RulePayload?) -> Match? {
            guard let payload else { return nil }
            let index = Int(payload.entryIndex)
            let name = index < ruleSetNames.count ? ruleSetNames[index] : nil
            return Match(action: payload.action, ruleSetName: (name?.isEmpty ?? true) ? nil : name)
        }

        // MARK: Streaming ingestion

        mutating func ingestConfigurations(_ slice: Data) {
            guard let configurations = try? JSONDecoder().decode([String: ProxyConfiguration].self, from: slice) else { return }
            for (key, configuration) in configurations {
                guard let configurationId = UUID(uuidString: key) else { continue }
                configurationMap[configurationId] = configuration
            }
        }

        mutating func reserveCIDRv4(tierIndex: Int, additionalPrefixes: Int) {
            matcher.tiers[tierIndex].reserveIPv4(additionalPrefixes: additionalPrefixes)
        }

        mutating func reserveCIDRv6(tierIndex: Int, additionalPrefixes: Int) {
            matcher.tiers[tierIndex].reserveIPv6(additionalPrefixes: additionalPrefixes)
        }

        mutating func ingestRule(tierIndex: Int, payload: RulePayload, type: RoutingRuleType,
                                 valueStart: Int, length: Int, base: UnsafeBufferPointer<UInt8>) {
            switch type {
            case .domainSuffix:
                matcher.tiers[tierIndex].collectSuffix(offset: valueStart, length: length, payload: payload)
            case .domainKeyword:
                matcher.tiers[tierIndex].insertKeyword(String(decoding: base[valueStart..<valueStart + length], as: UTF8.self), payload: payload)
            case .ipCIDR:
                if let parsed = RouteMatching.parseIPv4CIDR(String(decoding: base[valueStart..<valueStart + length], as: UTF8.self)) {
                    matcher.tiers[tierIndex].insertIPv4(network: parsed.network, prefixLen: parsed.prefixLen, payload: payload)
                }
            case .ipCIDR6:
                if let parsed = RouteMatching.parseIPv6CIDR(String(decoding: base[valueStart..<valueStart + length], as: UTF8.self)) {
                    matcher.tiers[tierIndex].insertIPv6(network: parsed.network, prefixLen: parsed.prefixLen, payload: payload)
                }
            }
        }
    }

    private let routingState = Mutex(RoutingState())

    // MARK: - Loading

    /// Clears all rules and configurations (e.g. when switching to global mode).
    func reset() {
        routingState.withLock { $0 = RoutingState() }
    }

    /// Compiles rules from the App Group routing file into per-tier matchers; the whole
    /// rebuild deliberately runs inside one critical section.
    func loadRoutingConfiguration() {
        routingState.withLock { state in
            Self.loadRoutingConfigurationLocked(into: &state)
        }
    }

    private static func loadRoutingConfigurationLocked(into state: inout RoutingState) {
        state = RoutingState()

        guard let data = AWCore.getRoutingData() else {
            logger.debug("[DomainRouter] No routing data available")
            return
        }

        do {
            try data.withUnsafeBytes { raw in
                let base = raw.bindMemory(to: UInt8.self)
                var reader = RoutingBinaryReader(bytes: base, data: data)
                try reader.run(state: &state)
                state.matcher.finalize(base: base)
            }
        } catch {
            state = RoutingState()
            logger.error("[DomainRouter] Routing payload parse failed: \(error)")
            return
        }

        let tiers = state.matcher.tiers
        logger.debug("[DomainRouter] Loaded tiers — user: \(tiers[Tier.user.rawValue].domainRuleCount)+\(tiers[Tier.user.rawValue].ipRuleCount), adBlock: \(tiers[Tier.adBlock.rawValue].domainRuleCount)+\(tiers[Tier.adBlock.rawValue].ipRuleCount), builtIn: \(tiers[Tier.builtIn.rawValue].domainRuleCount)+\(tiers[Tier.builtIn.rawValue].ipRuleCount), bypass: \(tiers[Tier.bypass.rawValue].domainRuleCount)+\(tiers[Tier.bypass.rawValue].ipRuleCount); \(state.configurationMap.count) configurations")
    }

    // MARK: - Payload reader

    private struct RoutingBinaryReader {
        enum ReadError: Error { case badMagic, truncated, malformed }

        let bytes: UnsafeBufferPointer<UInt8>
        let data: Data
        private var cursor = 0
        private var count: Int { bytes.count }

        init(bytes: UnsafeBufferPointer<UInt8>, data: Data) {
            self.bytes = bytes
            self.data = data
        }

        mutating func run(state: inout RoutingState) throws {
            try expectMagic()

            let configLength = Int(try u32())
            let configStart = cursor
            try advance(configLength)
            if configLength > 0 {
                state.ingestConfigurations(data.subdata(in: (data.startIndex + configStart)..<(data.startIndex + configStart + configLength)))
            }

            let entryCount = try u32()
            for entryIndex in 0..<entryCount {
                try readEntry(state: &state, entryIndex: UInt16(clamping: entryIndex))
            }

            // Trailing names section (newer payloads): u32 count == entry count,
            // then a u16-length-prefixed UTF-8 name per entry, in entry order.
            state.ruleSetNames = readNames(expectedCount: entryCount) ?? []
        }

        private mutating func readNames(expectedCount: UInt32) -> [String]? {
            guard cursor < count,
                  let nameCount = try? u32(), nameCount == expectedCount else { return nil }
            var names: [String] = []
            names.reserveCapacity(Int(nameCount))
            for _ in 0..<nameCount {
                guard let length = try? u16(), cursor + Int(length) <= count else { return nil }
                names.append(String(decoding: bytes[cursor..<cursor + Int(length)], as: UTF8.self))
                cursor += Int(length)
            }
            return names
        }

        private mutating func readEntry(state: inout RoutingState, entryIndex: UInt16) throws {
            guard let tier = RoutingBinaryFormat.Tier(rawValue: try u8()) else { throw ReadError.malformed }
            let action = try readAction()
            let payload = RulePayload(action: action, entryIndex: entryIndex)

            var remainingRules = try u32()
            // Upper bound on this entry's CIDR rules; reserving on the first of each family lets a bulk load
            // skip the doubling reallocations. Clamp to what the payload could hold (min rule = 3 bytes) so a
            // corrupt count can't drive a wild reserveCapacity.
            let reserveHint = min(Int(remainingRules), count / 3)
            var reservedV4 = false
            var reservedV6 = false
            while remainingRules > 0 {
                let typeByte = try u8()
                let length = Int(try u16())
                let valueStart = cursor
                try advance(length)
                if let type = RoutingRuleType(rawValue: Int(typeByte)) {
                    if type == .ipCIDR, !reservedV4 {
                        state.reserveCIDRv4(tierIndex: Int(tier.rawValue), additionalPrefixes: reserveHint)
                        reservedV4 = true
                    } else if type == .ipCIDR6, !reservedV6 {
                        state.reserveCIDRv6(tierIndex: Int(tier.rawValue), additionalPrefixes: reserveHint)
                        reservedV6 = true
                    }
                    state.ingestRule(tierIndex: Int(tier.rawValue), payload: payload, type: type,
                                     valueStart: valueStart, length: length, base: bytes)
                }
                remainingRules -= 1
            }
        }

        private mutating func readAction() throws -> RouteTarget {
            switch RoutingBinaryFormat.Action(rawValue: try u8()) {
            case .direct: return .direct
            case .reject: return .reject
            case .proxy: return .proxy(try readUUID())
            case nil: throw ReadError.malformed
            }
        }

        // MARK: Primitives

        private mutating func expectMagic() throws {
            let magic = RoutingBinaryFormat.magic
            guard cursor + magic.count <= count else { throw ReadError.truncated }
            for k in 0..<magic.count where bytes[cursor + k] != magic[k] { throw ReadError.badMagic }
            cursor += magic.count
        }

        private mutating func u8() throws -> UInt8 {
            guard cursor < count else { throw ReadError.truncated }
            defer { cursor += 1 }
            return bytes[cursor]
        }

        private mutating func u16() throws -> UInt16 {
            guard cursor + 2 <= count else { throw ReadError.truncated }
            defer { cursor += 2 }
            return UInt16(bytes[cursor]) | (UInt16(bytes[cursor + 1]) << 8)
        }

        private mutating func u32() throws -> UInt32 {
            guard cursor + 4 <= count else { throw ReadError.truncated }
            defer { cursor += 4 }
            return UInt32(bytes[cursor]) | (UInt32(bytes[cursor + 1]) << 8) | (UInt32(bytes[cursor + 2]) << 16) | (UInt32(bytes[cursor + 3]) << 24)
        }

        private mutating func advance(_ n: Int) throws {
            guard n >= 0, cursor + n <= count else { throw ReadError.truncated }
            cursor += n
        }

        private mutating func readUUID() throws -> UUID {
            guard cursor + 16 <= count else { throw ReadError.truncated }
            let u = UUID(uuid: (bytes[cursor], bytes[cursor + 1], bytes[cursor + 2], bytes[cursor + 3],
                                bytes[cursor + 4], bytes[cursor + 5], bytes[cursor + 6], bytes[cursor + 7],
                                bytes[cursor + 8], bytes[cursor + 9], bytes[cursor + 10], bytes[cursor + 11],
                                bytes[cursor + 12], bytes[cursor + 13], bytes[cursor + 14], bytes[cursor + 15]))
            cursor += 16
            return u
        }
    }

    // MARK: - Matching (public API)

    var hasRules: Bool {
        routingState.withLock { $0.matcher.hasRules }
    }

    /// Matches a domain by walking tiers in priority order. First hit wins.
    func matchDomain(_ domain: String) -> Match? {
        guard !domain.isEmpty else { return nil }
        // Lowercase once, outside the lock, and share the UTF-8 bytes across tiers.
        var lowered = RouteMatching.asciiLowercasedIfNeeded(domain)
        return routingState.withLock { state in
            let payload = lowered.withUTF8 { state.matcher.matchDomain(bytes: $0) }
            return state.match(resolving: payload)
        }
    }

    /// Matches an IP address against per-tier CIDR tries in priority order.
    func matchIP(_ ip: String) -> Match? {
        routingState.withLock { state in
            let payload = state.matcher.matchIP(ip)
            return state.match(resolving: payload)
        }
    }

    /// Returns nil for .direct/.reject or when the configuration UUID is unknown.
    func resolveConfiguration(action: RouteTarget) -> ProxyConfiguration? {
        switch action {
        case .direct, .reject:
            return nil
        case .proxy(let id):
            return routingState.withLock { $0.configurationMap[id] }
        }
    }
}
