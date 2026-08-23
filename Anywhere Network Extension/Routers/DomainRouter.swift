//
//  DomainRouter.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "DomainRouter")

nonisolated final class DomainRouter: Sendable {

    // MARK: - Tier model
    
    fileprivate enum Tier: Int, CaseIterable {
        case adBlock = 0
        case builtIn = 1
        case user = 2
        case neutral = 3
        case bypass = 4
    }

    fileprivate struct RulePayload: Hashable, Sendable {
        var action: RouteTarget
        var entryIndex: UInt16
    }

    struct Match: Sendable {
        let action: RouteTarget
        let ruleSetName: String?
    }

    fileprivate struct RoutingState: Sendable {
        var matcher = TieredRouteMatcher<RulePayload>(tierCount: Tier.allCases.count)
        var configurationMap: [UUID: ProxyConfiguration] = [:]
        var ruleSetNames: [String] = []
        var version: UInt64 = 1

        func match(resolving payload: RulePayload?) -> Match? {
            guard let payload else { return nil }
            let index = Int(payload.entryIndex)
            let name = index < ruleSetNames.count ? ruleSetNames[index] : nil
            return Match(action: payload.action, ruleSetName: (name?.isEmpty ?? true) ? nil : name)
        }

        // MARK: Streaming ingestion

        mutating func ingestConfigurations(_ slice: Data) throws(AnywhereError) {
            guard let configurations = try? JSONDecoder().decode([String: ProxyConfiguration].self, from: slice) else {
                throw AnywhereError.routing(.payloadCorrupted(.malformed))
            }
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

    var currentRulesVersion: UInt64 { routingState.withLock { $0.version } }

    // MARK: - Loading

    func reset() {
        routingState.withLock { state in
            let next = state.version &+ 1
            state = RoutingState()
            state.version = next
        }
    }

    func loadRoutingConfiguration() {
        let newState = Self.makeRoutingState()
        routingState.withLock { state in
            let next = state.version &+ 1
            state = newState
            state.version = next
        }
    }

    struct CompiledRouting: Sendable {
        fileprivate let state: RoutingState
    }

    @concurrent
    func compileRoutingConfiguration() async -> CompiledRouting {
        CompiledRouting(state: Self.makeRoutingState())
    }

    func install(_ compiled: CompiledRouting) {
        routingState.withLock { state in
            let next = state.version &+ 1
            state = compiled.state
            state.version = next
        }
    }

    private static func makeRoutingState() -> RoutingState {
        var state = RoutingState()
        guard let data = AWCore.getRoutingData() else {
            logger.debug("[DomainRouter] No routing data available")
            return state
        }

        do {
            try data.withUnsafeBytes { raw in
                let base = raw.bindMemory(to: UInt8.self)
                var reader = RoutingBinaryReader(bytes: base, data: data)
                try reader.run(state: &state)
                state.matcher.finalize(base: base)
            }
        } catch {
            logger.report("[DomainRouter] Routing payload parse failed", error: error)
            return RoutingState()
        }
        
        return state
    }

    // MARK: - Payload reader

    private struct RoutingBinaryReader {

        let bytes: UnsafeBufferPointer<UInt8>
        let data: Data
        private var cursor = 0
        private var count: Int { bytes.count }

        init(bytes: UnsafeBufferPointer<UInt8>, data: Data) {
            self.bytes = bytes
            self.data = data
        }

        mutating func run(state: inout RoutingState) throws(AnywhereError) {
            try expectMagic()

            let configLength = Int(try u32())
            let configStart = cursor
            try advance(configLength)
            if configLength > 0 {
                try state.ingestConfigurations(data.subdata(in: (data.startIndex + configStart)..<(data.startIndex + configStart + configLength)))
            }

            let entryCount = try u32()
            for entryIndex in 0..<entryCount {
                try readEntry(state: &state, entryIndex: UInt16(clamping: entryIndex))
            }
            
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

        private mutating func readEntry(state: inout RoutingState, entryIndex: UInt16) throws(AnywhereError) {
            guard let tier = RoutingBinaryFormat.Tier(rawValue: try u8()) else { throw AnywhereError.routing(.payloadCorrupted(.malformed)) }
            let action = try readAction()
            let payload = RulePayload(action: action, entryIndex: entryIndex)

            var remainingRules = try u32()
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

        private mutating func readAction() throws(AnywhereError) -> RouteTarget {
            switch RoutingBinaryFormat.Action(rawValue: try u8()) {
            case .direct: return .direct
            case .reject: return .reject
            case .proxy: return .proxy(try readUUID())
            case nil: throw AnywhereError.routing(.payloadCorrupted(.malformed))
            }
        }

        // MARK: Primitives

        private mutating func expectMagic() throws(AnywhereError) {
            let magic = RoutingBinaryFormat.magic
            guard cursor + magic.count <= count else { throw AnywhereError.routing(.payloadCorrupted(.truncated)) }
            for k in 0..<magic.count where bytes[cursor + k] != magic[k] { throw AnywhereError.routing(.payloadCorrupted(.badMagic)) }
            cursor += magic.count
        }

        private mutating func u8() throws(AnywhereError) -> UInt8 {
            guard cursor < count else { throw AnywhereError.routing(.payloadCorrupted(.truncated)) }
            defer { cursor += 1 }
            return bytes[cursor]
        }

        private mutating func u16() throws(AnywhereError) -> UInt16 {
            guard cursor + 2 <= count else { throw AnywhereError.routing(.payloadCorrupted(.truncated)) }
            defer { cursor += 2 }
            return UInt16(bytes[cursor]) | (UInt16(bytes[cursor + 1]) << 8)
        }

        private mutating func u32() throws(AnywhereError) -> UInt32 {
            guard cursor + 4 <= count else { throw AnywhereError.routing(.payloadCorrupted(.truncated)) }
            defer { cursor += 4 }
            return UInt32(bytes[cursor]) | (UInt32(bytes[cursor + 1]) << 8) | (UInt32(bytes[cursor + 2]) << 16) | (UInt32(bytes[cursor + 3]) << 24)
        }

        private mutating func advance(_ n: Int) throws(AnywhereError) {
            guard n >= 0, cursor + n <= count else { throw AnywhereError.routing(.payloadCorrupted(.truncated)) }
            cursor += n
        }

        private mutating func readUUID() throws(AnywhereError) -> UUID {
            guard cursor + 16 <= count else { throw AnywhereError.routing(.payloadCorrupted(.truncated)) }
            let uuid = UUID(uuid: (
                bytes[cursor], bytes[cursor + 1], bytes[cursor + 2], bytes[cursor + 3],
                bytes[cursor + 4], bytes[cursor + 5], bytes[cursor + 6], bytes[cursor + 7],
                bytes[cursor + 8], bytes[cursor + 9], bytes[cursor + 10], bytes[cursor + 11],
                bytes[cursor + 12], bytes[cursor + 13], bytes[cursor + 14], bytes[cursor + 15])
            )
            cursor += 16
            return uuid
        }
    }

    // MARK: - Matching (public API)

    var hasRules: Bool {
        routingState.withLock { $0.matcher.hasRules }
    }

    func matchDomain(_ domain: String) -> Match? {
        matchDomainVersioned(domain).match
    }

    func matchDomainVersioned(_ domain: String) -> (match: Match?, version: UInt64) {
        guard !domain.isEmpty else { return (nil, currentRulesVersion) }
        var lowered = RouteMatching.asciiLowercasedIfNeeded(domain)
        return routingState.withLock { state in
            let payload = lowered.withUTF8 { state.matcher.matchDomain(bytes: $0) }
            return (state.match(resolving: payload), state.version)
        }
    }

    func matchIP(_ ip: String) -> Match? {
        routingState.withLock { state in
            let payload = state.matcher.matchIP(ip)
            return state.match(resolving: payload)
        }
    }

    func resolveConfiguration(action: RouteTarget) -> ProxyConfiguration? {
        switch action {
        case .direct, .reject:
            return nil
        case .proxy(let id):
            return routingState.withLock { $0.configurationMap[id] }
        }
    }
}
