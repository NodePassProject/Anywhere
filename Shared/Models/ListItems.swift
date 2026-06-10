//
//  ListItems.swift
//  Anywhere
//
//  Created by NodePassProject on 6/5/26.
//

import Foundation
import Observation

/// Observable row model for a proxy: a stable instance mutated in place so a
/// single-field change re-renders just the affected row.
@MainActor
@Observable
final class ProxyListItem: Identifiable {
    nonisolated let id: UUID
    nonisolated let subscriptionId: UUID?   // grouping key; never changes for a proxy
    var name: String
    var protocolName: String
    var transportTag: String?   // uppercased; nil unless VLESS with a non-empty transport
    var securityTag: String?    // uppercased; nil when "none"
    var isVision: Bool
    var isSelected: Bool
    var latency: LatencyResult?

    var tags: [String] {
        var result = [protocolName]
        if let transportTag { result.append(transportTag) }
        if let securityTag { result.append(securityTag) }
        if isVision { result.append("Vision") }
        return result
    }

    init(_ configuration: ProxyConfiguration, isSelected: Bool, latency: LatencyResult?) {
        id = configuration.id
        subscriptionId = configuration.subscriptionId
        let d = Self.derive(configuration)
        name = configuration.name
        protocolName = d.protocolName
        transportTag = d.transportTag
        securityTag = d.securityTag
        isVision = d.isVision
        self.isSelected = isSelected
        self.latency = latency
    }

    /// Assigns only changed fields so observation fires for exactly what moved.
    func update(_ configuration: ProxyConfiguration, isSelected: Bool, latency: LatencyResult?) {
        let d = Self.derive(configuration)
        if name != configuration.name { name = configuration.name }
        if protocolName != d.protocolName { protocolName = d.protocolName }
        if transportTag != d.transportTag { transportTag = d.transportTag }
        if securityTag != d.securityTag { securityTag = d.securityTag }
        if isVision != d.isVision { isVision = d.isVision }
        if self.isSelected != isSelected { self.isSelected = isSelected }
        if self.latency != latency { self.latency = latency }
    }

    private static func derive(_ configuration: ProxyConfiguration) -> (protocolName: String, transportTag: String?, securityTag: String?, isVision: Bool) {
        let transportTag: String?
        if configuration.outboundProtocol == .vless {
            let tag = configuration.transportLayer.tag
            transportTag = tag.isEmpty ? nil : tag.uppercased()
        } else {
            transportTag = nil
        }
        let security = configuration.securityLayer.tag.uppercased()
        let securityTag = security == "NONE" ? nil : security
        let isVision: Bool
        if case .vless(_, _, let flow?, _, _, _, _) = configuration.outbound {
            isVision = flow.uppercased().contains("VISION")
        } else {
            isVision = false
        }
        return (configuration.outboundProtocol.name, transportTag, securityTag, isVision)
    }
}

/// Observable row model for a chain: a stable instance mutated in place so a
/// single-field change re-renders just the affected row.
@MainActor
@Observable
final class ChainListItem: Identifiable {
    nonisolated let id: UUID
    var name: String
    var proxyNames: [String]
    var isValid: Bool
    var entryAddress: String?
    var exitAddress: String?
    var isSelected: Bool
    var latency: LatencyResult?

    var infoText: String {
        var text = String(localized: "\(proxyNames.count) proxie(s)")
        if let entryAddress, let exitAddress {
            text += " · \(entryAddress) → \(exitAddress)"
        }
        return text
    }

    init(_ chain: ProxyChain, configurations: [ProxyConfiguration], isSelected: Bool, latency: LatencyResult?) {
        let d = Self.derive(chain, configurations)
        id = chain.id
        name = chain.name
        proxyNames = d.names
        isValid = d.isValid
        entryAddress = d.entry
        exitAddress = d.exit
        self.isSelected = isSelected
        self.latency = latency
    }

    /// Assigns only changed fields so observation fires for exactly what moved.
    func update(_ chain: ProxyChain, configurations: [ProxyConfiguration], isSelected: Bool, latency: LatencyResult?) {
        let d = Self.derive(chain, configurations)
        if name != chain.name { name = chain.name }
        if proxyNames != d.names { proxyNames = d.names }
        if isValid != d.isValid { isValid = d.isValid }
        if entryAddress != d.entry { entryAddress = d.entry }
        if exitAddress != d.exit { exitAddress = d.exit }
        if self.isSelected != isSelected { self.isSelected = isSelected }
        if self.latency != latency { self.latency = latency }
    }

    private static func derive(_ chain: ProxyChain, _ configurations: [ProxyConfiguration]) -> (names: [String], isValid: Bool, entry: String?, exit: String?) {
        let proxies = chain.resolveProxies(from: configurations)
        let isValid = proxies.count == chain.proxyIds.count && proxies.count >= 2
        let entry = proxies.count >= 2 ? proxies.first?.serverAddress : nil
        let exit = proxies.count >= 2 ? proxies.last?.serverAddress : nil
        return (proxies.map(\.name), isValid, entry, exit)
    }
}
