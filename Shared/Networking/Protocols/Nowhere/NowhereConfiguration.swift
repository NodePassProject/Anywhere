//
//  NowhereConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation

/// Per-new-flow routing policy. Existing TCP flows keep the lanes chosen in FLOWOPEN.
struct NowhereRoutePolicy: Hashable {
    var tcpUpload: NowhereProtocol.LaneKind
    var tcpDownload: NowhereProtocol.LaneKind
    var muxEnabled: Bool

    static let `default` = NowhereRoutePolicy(
        tcpUpload: .quic,
        tcpDownload: .quic,
        muxEnabled: true
    )

    var usesTCPLane: Bool {
        tcpUpload == .tcp || tcpDownload == .tcp
    }

    static func lane(from value: String?) -> NowhereProtocol.LaneKind? {
        switch value?.lowercased() {
        case "quic", "udp": return .quic
        case "tcp": return .tcp
        default: return nil
        }
    }

    static func mux(from value: String?) -> Bool? {
        switch value?.lowercased() {
        case "1", "true", "yes", "on": return true
        case "0", "false", "no", "off": return false
        default: return nil
        }
    }
}

/// Configuration for a Nowhere QUIC session.
struct NowhereConfiguration: Hashable {
    let proxyHost: String
    let proxyPort: UInt16
    let key: String
    let spec: String?
    let tls: TLSConfiguration
    let route: NowhereRoutePolicy
    let protocolSpec: NowhereProtocol.EffectiveSpec

    init(
        proxyHost: String,
        proxyPort: UInt16,
        key: String,
        spec: String?,
        tls: TLSConfiguration,
        route: NowhereRoutePolicy = .default
    ) throws {
        let effectiveSpec = spec.flatMap { $0.isEmpty ? nil : $0 }
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort
        self.key = key
        self.spec = effectiveSpec
        self.tls = tls
        self.route = route
        self.protocolSpec = try NowhereProtocol.buildEffectiveSpec(
            key: key,
            spec: effectiveSpec,
            alpn: tls.alpn?.first
        )
    }
}
