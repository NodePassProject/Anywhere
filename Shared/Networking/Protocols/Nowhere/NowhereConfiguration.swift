//
//  NowhereConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation

nonisolated enum NowhereNetwork: String, Codable, CaseIterable, Sendable {
    case tcp
    case udp
}

nonisolated enum NowhereMorphPrelude: String, Codable, CaseIterable, Sendable {
    case full8
    case low7

    var displayName: String {
        switch self {
        case .full8: String(localized: "8-bit Random")
        case .low7: String(localized: "7-bit Random")
        }
    }
}

nonisolated struct NowhereConfiguration: Codable, Hashable, Sendable {
    let key: String
    let network: NowhereNetwork
    let morph: Bool
    let morphPrelude: NowhereMorphPrelude

    init(
        key: String,
        network: NowhereNetwork = .tcp,
        morph: Bool = true,
        morphPrelude: NowhereMorphPrelude = .full8
    ) {
        self.key = key
        self.network = network
        self.morph = morph
        self.morphPrelude = morphPrelude
    }

    private enum CodingKeys: String, CodingKey {
        case key, network, morph, morphPrelude
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            key: try container.decode(String.self, forKey: .key),
            network: try container.decodeIfPresent(NowhereNetwork.self, forKey: .network) ?? .tcp,
            morph: try container.decodeIfPresent(Bool.self, forKey: .morph) ?? true,
            morphPrelude: try container.decodeIfPresent(NowhereMorphPrelude.self, forKey: .morphPrelude) ?? .full8
        )
    }

    static func tlsConfiguration(for host: String) -> TLSConfiguration {
        TLSConfiguration(
            serverName: host,
            alpn: [NowhereProtocol.applicationProtocol],
            minVersion: .tls13,
            maxVersion: .tls13
        )
    }
}

nonisolated struct NowhereRuntimeConfiguration: Hashable, Sendable {
    let proxyHost: String
    let proxyPort: UInt16
    let key: String
    let network: NowhereNetwork
    let morph: Bool
    let morphPrelude: NowhereMorphPrelude
    let authKey: NowhereProtocol.AuthKey
    let morphKeys: NowhereMorph.Keys?

    init(proxyHost: String, proxyPort: UInt16, configuration: NowhereConfiguration) throws {
        guard proxyPort != 0 else {
            throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Invalid Nowhere port"))
        }
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort
        key = configuration.key
        network = configuration.network
        morph = configuration.morph
        morphPrelude = configuration.morphPrelude
        authKey = NowhereProtocol.deriveAuthKey(sharedKey: configuration.key)
        morphKeys = configuration.morph ? NowhereMorph.deriveKeys(sharedKey: configuration.key) : nil
    }

    var tlsConfiguration: TLSConfiguration {
        NowhereConfiguration.tlsConfiguration(for: proxyHost)
    }
}
