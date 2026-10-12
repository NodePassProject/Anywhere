//
//  ProxyConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated enum OutboundProtocol: String, Codable, CaseIterable {
    case nowhere
    case vless
    case hysteria
    case sudoku
    case trojan
    case anytls
    case shadowsocks
    case socks5
    case rfc

    enum InitialDataPolicy: Equatable {
        case none
        case unbounded

        func prefixLength(for availableBytes: Int) -> Int {
            switch self {
            case .none: return 0
            case .unbounded: return availableBytes
            }
        }
    }
    
    var initialDataPolicy: InitialDataPolicy {
        switch self {
        case .nowhere, .vless, .sudoku:
            return .unbounded
        case .hysteria, .trojan, .anytls, .shadowsocks, .socks5, .rfc:
            return .none
        }
    }
    
    func upstreamNetwork(for downstream: ProxyNetwork) -> ProxyNetwork? {
        switch self {
        case .nowhere, .hysteria:
            return .udp
        case .vless, .trojan, .anytls, .socks5:
            return .tcp
        case .shadowsocks:
            return downstream
        case .sudoku, .rfc:
            return downstream == .tcp ? .tcp : nil
        }
    }

    var name: String {
        switch self {
        case .nowhere:
            "Nowhere"
        case .vless:
            "VLESS"
        case .hysteria:
            "Hysteria"
        case .sudoku:
            "Sudoku"
        case .trojan:
            "Trojan"
        case .anytls:
            "AnyTLS"
        case .shadowsocks:
            "Shadowsocks"
        case .socks5:
            "SOCKS5"
        case .rfc:
            "RFC"
        }
    }
}

// MARK: - Outbound Protocol Configuration

nonisolated enum Outbound: Hashable, Sendable {
    case nowhere(NowhereConfiguration)
    case vless(VLESSConfiguration)
    case hysteria(HysteriaConfiguration)
    case sudoku(SudokuConfiguration)
    case trojan(TrojanConfiguration)
    case anytls(AnyTLSConfiguration)
    case shadowsocks(ShadowsocksConfiguration)
    case socks5(SOCKS5Configuration)
    case rfc(RFCConfiguration)

    var outboundProtocol: OutboundProtocol {
        switch self {
        case .nowhere:      .nowhere
        case .vless:        .vless
        case .hysteria:     .hysteria
        case .sudoku:       .sudoku
        case .trojan:       .trojan
        case .anytls:       .anytls
        case .shadowsocks:  .shadowsocks
        case .socks5:       .socks5
        case .rfc:          .rfc
        }
    }
}

// MARK: - Generic Security Layer Configuration

nonisolated enum GenericSecurityLayer: Hashable, Sendable {
    case tls(TLSConfiguration)
    case none
    
    var tag: String {
        switch self {
        case .tls:  "tls"
        case .none: "none"
        }
    }
    
    var tlsConfiguration: TLSConfiguration? {
        if case .tls(let tls) = self { return tls }
        return nil
    }
}

nonisolated extension GenericSecurityLayer: Codable {
    private enum CodingKeys: String, CodingKey {
        case type, tls
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        switch type {
        case "tls":     self = .tls(try container.decode(TLSConfiguration.self, forKey: .tls))
        case "none":    self = .none
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: container,
                debugDescription: "Unsupported security layer: \(type)"
            )
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(tag, forKey: .type)
        if case .tls(let tls) = self {
            try container.encode(tls, forKey: .tls)
        }
    }
}

// MARK: - ProxyConfiguration

nonisolated struct ProxyConfiguration: Identifiable, Hashable, Codable, Sendable, SoftDeletable {
    let id: UUID
    let name: String
    let serverAddress: String
    let serverPort: UInt16
    let resolvedIP: String?
    let subscriptionId: UUID?
    let outbound: Outbound
    let chain: [ProxyConfiguration]?
    var updatedAt: Date
    var deletedAt: Date? = nil

    var connectAddress: String { resolvedIP ?? serverAddress }

    var outboundProtocol: OutboundProtocol { outbound.outboundProtocol }
    
    var genericSecurityLayer: GenericSecurityLayer {
        switch outbound {
        case .nowhere:                       .tls(NowhereConfiguration.tlsConfiguration(for: serverAddress))
        case .trojan(let configuration):    configuration.securityLayer
        case .anytls(let configuration):    configuration.securityLayer
        case .rfc(let configuration):       configuration.securityLayer
        default:                            .none
        }
    }
    
    var displayNetworkTag: String? {
        let tag: String?
        switch outboundProtocol {
        case .nowhere:
            tag = nowhereNetwork.rawValue.uppercased()
        case .vless:
            tag = vless?.displayNetworkTag
        case .hysteria:         tag = "UDP"
        case .sudoku:           tag = "TCP"
        case .trojan:           tag = "TCP"
        case .anytls:           tag = "TCP"
        case .shadowsocks:      tag = nil
        case .socks5:           tag = nil
        case .rfc:              tag = "TCP"
        }
        return tag
    }

    var displayTransportLayerTag: String? {
        vless?.displayTransportLayerTag
    }

    var displaySecurityLayerTag: String? {
        let tag: String?
        switch outboundProtocol {
        case .nowhere:
            tag = "TLS"
        case .vless:
            tag = vless?.displaySecurityLayerTag
        case .hysteria:         tag = "TLS"
        case .trojan, .anytls, .rfc:
            switch genericSecurityLayer {
            case .none:         tag = nil
            case .tls:          tag = "TLS"
            }
        default:                tag = nil
        }
        return tag
    }
    
    var nowhereNetwork: NowhereNetwork {
        if case .nowhere(let configuration) = outbound { return configuration.network }
        return .tcp
    }

    var nowhereMorph: Bool {
        if case .nowhere(let configuration) = outbound { return configuration.morph }
        return false
    }
    
    var vless: VLESSConfiguration? {
        if case .vless(let configuration) = outbound { return configuration }
        return nil
    }

    var anytls: AnyTLSConfiguration? {
        if case .anytls(let configuration) = outbound { return configuration }
        return nil
    }

    var hasVisionFlow: Bool { vless?.hasVisionFlow ?? false }
    
    var xrayTransportLayer: XrayTransportLayer { vless?.transport ?? .raw }

    var xraySecurityLayer: XraySecurityLayer { vless?.security ?? .none }

    var isXHTTPOverHTTP3: Bool { vless?.isXHTTPOverHTTP3 ?? false }
    
    var isQUICTransport: Bool {
        switch outbound {
        case .nowhere(let configuration):
            configuration.network == .udp
        case .hysteria:
            true
        case .vless(let configuration):
            configuration.isXHTTPOverHTTP3
        case .sudoku, .trojan, .anytls, .shadowsocks, .socks5, .rfc:
            false
        }
    }

    func upstreamNetwork(for downstream: ProxyNetwork) -> ProxyNetwork? {
        if isXHTTPOverHTTP3 { return .udp }
        if outboundProtocol == .nowhere {
            return nowhereNetwork == .udp ? .udp : .tcp
        }
        return outboundProtocol.upstreamNetwork(for: downstream)
    }

    init(
        id: UUID = UUID(),
        name: String,
        serverAddress: String,
        serverPort: UInt16,
        resolvedIP: String? = nil,
        subscriptionId: UUID? = nil,
        outbound: Outbound,
        chain: [ProxyConfiguration]? = nil,
        updatedAt: Date = .now
    ) {
        self.id = id
        self.name = name
        self.serverAddress = serverAddress
        self.serverPort = serverPort
        self.resolvedIP = resolvedIP
        self.subscriptionId = subscriptionId
        self.outbound = outbound
        self.chain = chain
        self.updatedAt = updatedAt
    }

    func withChain(_ chain: [ProxyConfiguration]?) -> ProxyConfiguration {
        ProxyConfiguration(
            id: id, name: name, serverAddress: serverAddress, serverPort: serverPort,
            resolvedIP: resolvedIP, subscriptionId: subscriptionId,
            outbound: outbound, chain: chain, updatedAt: updatedAt
        )
    }

    func withResolvedIP(_ resolvedIP: String?) -> ProxyConfiguration {
        ProxyConfiguration(
            id: id, name: name, serverAddress: serverAddress, serverPort: serverPort,
            resolvedIP: resolvedIP, subscriptionId: subscriptionId,
            outbound: outbound, chain: chain, updatedAt: updatedAt
        )
    }
    
    func contentEquals(_ other: ProxyConfiguration) -> Bool {
        name == other.name &&
        serverAddress == other.serverAddress &&
        serverPort == other.serverPort &&
        outbound == other.outbound &&
        chain == other.chain
    }

    // MARK: - Codable

    private enum CodingKeys: String, CodingKey {
        case id, name, serverAddress, serverPort, resolvedIP, subscriptionId
        case outbound
        case chain
        case updatedAt
        case deletedAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        serverAddress = try container.decode(String.self, forKey: .serverAddress)
        serverPort = try container.decode(UInt16.self, forKey: .serverPort)
        resolvedIP = try container.decodeIfPresent(String.self, forKey: .resolvedIP)
        subscriptionId = try container.decodeIfPresent(UUID.self, forKey: .subscriptionId)

        if let outbound = try container.decodeIfPresent(Outbound.self, forKey: .outbound) {
            self.outbound = outbound
        } else {
            self.outbound = try Outbound(
                legacyFrom: decoder,
                serverAddress: serverAddress,
                serverPort: serverPort
            )
        }

        chain = try container.decodeIfPresent([ProxyConfiguration].self, forKey: .chain)
        deletedAt = try container.decodeIfPresent(Date.self, forKey: .deletedAt)
        updatedAt = try container.decodeIfPresent(Date.self, forKey: .updatedAt) ?? deletedAt ?? .distantPast
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(serverAddress, forKey: .serverAddress)
        try container.encode(serverPort, forKey: .serverPort)
        try container.encodeIfPresent(resolvedIP, forKey: .resolvedIP)
        try container.encodeIfPresent(subscriptionId, forKey: .subscriptionId)

        try container.encode(outbound, forKey: .outbound)

        try container.encodeIfPresent(chain, forKey: .chain)
        try container.encode(updatedAt, forKey: .updatedAt)
        try container.encodeIfPresent(deletedAt, forKey: .deletedAt)
    }
}
