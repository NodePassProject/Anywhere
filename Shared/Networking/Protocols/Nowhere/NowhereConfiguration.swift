//
//  NowhereConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation

/// Configuration for a Nowhere QUIC session.
struct NowhereConfiguration: Hashable {
    let proxyHost: String
    let proxyPort: UInt16
    let key: String
    let spec: String?
    let tls: TLSConfiguration
    let protocolSpec: NowhereProtocol.EffectiveSpec

    init(proxyHost: String, proxyPort: UInt16, key: String, spec: String?, tls: TLSConfiguration) throws {
        let effectiveSpec = spec.flatMap { $0.isEmpty ? nil : $0 } ?? NowhereProtocol.defaultSpec
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort
        self.key = key
        self.spec = effectiveSpec
        self.tls = tls
        self.protocolSpec = try NowhereProtocol.buildEffectiveSpec(
            key: key,
            spec: effectiveSpec,
            alpn: tls.alpn?.first
        )
    }
}
