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
        name = configuration.name
        protocolName = configuration.outboundProtocol.name
        transportTag = configuration.displayTransportTag
        securityTag = configuration.displaySecurityTag
        isVision = configuration.hasVisionFlow
        self.isSelected = isSelected
        self.latency = latency
    }

    /// Assigns only changed fields so observation fires for exactly what moved.
    func update(_ configuration: ProxyConfiguration, isSelected: Bool, latency: LatencyResult?) {
        if name != configuration.name { name = configuration.name }
        if protocolName != configuration.outboundProtocol.name { protocolName = configuration.outboundProtocol.name }
        if transportTag != configuration.displayTransportTag { transportTag = configuration.displayTransportTag }
        if securityTag != configuration.displaySecurityTag { securityTag = configuration.displaySecurityTag }
        if isVision != configuration.hasVisionFlow { isVision = configuration.hasVisionFlow }
        if self.isSelected != isSelected { self.isSelected = isSelected }
        if self.latency != latency { self.latency = latency }
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
        let d = chain.listDisplayInfo(configurations: configurations)
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
        let d = chain.listDisplayInfo(configurations: configurations)
        if name != chain.name { name = chain.name }
        if proxyNames != d.names { proxyNames = d.names }
        if isValid != d.isValid { isValid = d.isValid }
        if entryAddress != d.entry { entryAddress = d.entry }
        if exitAddress != d.exit { exitAddress = d.exit }
        if self.isSelected != isSelected { self.isSelected = isSelected }
        if self.latency != latency { self.latency = latency }
    }

}
