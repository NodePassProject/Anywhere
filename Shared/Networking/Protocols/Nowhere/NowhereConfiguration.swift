//
//  NowhereConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation

enum NowhereNetwork: String, Codable, CaseIterable {
    case udp
    case tcp
}

enum NowherePool {
    static let validRange = 0...9
    static let sliderRange = 1...9
    static let enabledDefault = 5
}

struct NowhereConfiguration: Hashable {
    let proxyHost: String
    let proxyPort: UInt16
    let key: String
    let spec: String?
    let net: NowhereNetwork
    let pool: Int
    let tls: TLSConfiguration
    let protocolSpec: NowhereProtocol.EffectiveSpec

    init(
        proxyHost: String,
        proxyPort: UInt16,
        key: String,
        spec: String?,
        net: NowhereNetwork,
        pool: Int,
        tls: TLSConfiguration
    ) throws {
        guard NowherePool.validRange.contains(pool) else {
            throw ProxyError.protocolError("Invalid Nowhere pool value")
        }
        let effectiveSpec = spec.flatMap { $0.isEmpty ? nil : $0 } ?? NowhereProtocol.defaultSpec
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort
        self.key = key
        self.spec = effectiveSpec
        self.net = net
        self.pool = pool
        self.tls = tls
        self.protocolSpec = try NowhereProtocol.buildEffectiveSpec(
            key: key,
            spec: effectiveSpec,
            alpn: tls.alpn?.first
        )
    }
}
