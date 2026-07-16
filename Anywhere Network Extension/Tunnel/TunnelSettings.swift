//
//  TunnelSettings.swift
//  Anywhere
//
//  Created by NodePassProject on 7/12/26.
//

import Foundation

nonisolated struct TunnelSettings: Equatable {
    var baseProxyMode: ProxyMode = .rule
    var trustedSSIDs: Set<String> = []
    var alwaysTrustCellular = false
    var alwaysUntrustCellular = false
    var blockUDP = false
    var quicPolicy: QUICPolicy = .blocked
    var blockWebRTC = true
    var preventDNSLeak = false
    var reflectionEnabled = false
    var reflectionAddresses: [String] = []
    var hideVPNIcon = false
    var tunnelIncludedRoutes: [String] = []
    var tunnelExcludedRoutes: [String] = []
    var advertiseIPv6ToApps = false
    
    static func load() -> TunnelSettings {
        TunnelSettings(
            baseProxyMode: AWCore.getProxyMode(),
            trustedSSIDs: Set(AWCore.getTrustedSSIDs()),
            alwaysTrustCellular: AWCore.getAlwaysTrustCellular(),
            alwaysUntrustCellular: AWCore.getAlwaysUntrustCellular(),
            blockUDP: AWCore.getBlockUDP(),
            quicPolicy: AWCore.getQUICPolicy(),
            blockWebRTC: AWCore.getBlockWebRTC(),
            preventDNSLeak: AWCore.getPreventDNSLeak(),
            reflectionEnabled: AWCore.getReflectionEnabled(),
            reflectionAddresses: AWCore.getReflectionAddresses(),
            hideVPNIcon: AWCore.getHideVPNIcon(),
            tunnelIncludedRoutes: AWCore.getTunnelIncludedRoutes(),
            tunnelExcludedRoutes: AWCore.getTunnelExcludedRoutes(),
            advertiseIPv6ToApps: AWCore.getAdvertiseIPv6ToApps()
        )
    }
}
