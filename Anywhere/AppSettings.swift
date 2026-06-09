//
//  AppSettings.swift
//  Anywhere
//
//  Created by NodePassProject on 6/9/26.
//

import Foundation
import Observation

@MainActor
@Observable
final class AppSettings {
    static let shared = AppSettings()

    // MARK: - Persist only

    var experimentalEnabled: Bool {
        didSet { AWCore.setExperimentalEnabled(experimentalEnabled) }
    }

    var remnawaveHWIDEnabled: Bool {
        didSet { AWCore.setRemnawaveHWIDEnabled(remnawaveHWIDEnabled) }
    }

    // MARK: - Persist + notify the tunnel

    var advertiseIPv6ToApps: Bool {
        didSet {
            AWCore.setAdvertiseIPv6ToApps(advertiseIPv6ToApps)
            AWCore.notifyTunnelSettingsChanged()
        }
    }

    var blockWebRTC: Bool {
        didSet {
            AWCore.setBlockWebRTC(blockWebRTC)
            AWCore.notifyTunnelSettingsChanged()
        }
    }

    var encryptedDNSEnabled: Bool {
        didSet {
            AWCore.setEncryptedDNSEnabled(encryptedDNSEnabled)
            AWCore.notifyTunnelSettingsChanged()
        }
    }

    var encryptedDNSProtocol: String {
        didSet {
            AWCore.setEncryptedDNSProtocol(encryptedDNSProtocol)
            AWCore.notifyTunnelSettingsChanged()
        }
    }
    
    var encryptedDNSServer: String {
        didSet {
            AWCore.setEncryptedDNSServer(encryptedDNSServer)
            AWCore.notifyTunnelSettingsChanged()
        }
    }
    
    var hideVPNIcon: Bool {
        didSet {
            AWCore.setHideVPNIcon(hideVPNIcon)
            if hideVPNIcon, advertiseIPv6ToApps {
                advertiseIPv6ToApps = false
            } else {
                AWCore.notifyTunnelSettingsChanged()
            }
        }
    }
    
    var isGlobalMode: Bool {
        get { proxyMode == .global }
        set { proxyMode = newValue ? .global : .rule }
    }

    var proxyMode: ProxyMode {
        didSet {
            AWCore.setProxyMode(proxyMode)
            AWCore.notifyTunnelSettingsChanged()
        }
    }

    var quicPolicy: QUICPolicy {
        didSet {
            AWCore.setQUICPolicy(quicPolicy)
            AWCore.notifyTunnelSettingsChanged()
        }
    }
    
    var reflectionAddresses: [String] {
        didSet {
            AWCore.setReflectionAddresses(reflectionAddresses)
            AWCore.notifyTunnelSettingsChanged()
        }
    }

    var reflectionEnabled: Bool {
        didSet {
            AWCore.setReflectionEnabled(reflectionEnabled)
            AWCore.notifyTunnelSettingsChanged()
        }
    }

    // MARK: - Persist + certificate policy

    var allowInsecure: Bool {
        didSet {
            AWCore.setAllowInsecure(allowInsecure)
            AWCore.notifyCertificatePolicyChanged()
        }
    }

    // MARK: - Persist + reconnect the tunnel

    var alwaysOnEnabled: Bool {
        didSet {
            AWCore.setAlwaysOnEnabled(alwaysOnEnabled)
            VPNViewModel.shared.reconnectVPN()
        }
    }

    var includeAllNetworks: Bool {
        didSet {
            AWCore.setTunnelIncludeAllNetworks(includeAllNetworks)
            VPNViewModel.shared.reconnectVPN()
        }
    }

    var includeAPNs: Bool {
        didSet {
            AWCore.setTunnelIncludeAPNs(includeAPNs)
            VPNViewModel.shared.reconnectVPN()
        }
    }

    var includeCellularServices: Bool {
        didSet {
            AWCore.setTunnelIncludeCellularServices(includeCellularServices)
            VPNViewModel.shared.reconnectVPN()
        }
    }

    var includeLocalNetworks: Bool {
        didSet {
            AWCore.setTunnelIncludeLocalNetworks(includeLocalNetworks)
            VPNViewModel.shared.reconnectVPN()
        }
    }

    private init() {
        experimentalEnabled = AWCore.getExperimentalEnabled()
        remnawaveHWIDEnabled = AWCore.getRemnawaveHWIDEnabled()

        advertiseIPv6ToApps = AWCore.getAdvertiseIPv6ToApps()
        blockWebRTC = AWCore.getBlockWebRTC()
        encryptedDNSEnabled = AWCore.getEncryptedDNSEnabled()
        encryptedDNSProtocol = AWCore.getEncryptedDNSProtocol()
        encryptedDNSServer = AWCore.getEncryptedDNSServer()
        hideVPNIcon = AWCore.getHideVPNIcon()
        proxyMode = AWCore.getProxyMode()
        quicPolicy = AWCore.getQUICPolicy()
        reflectionAddresses = AWCore.getReflectionAddresses()
        reflectionEnabled = AWCore.getReflectionEnabled()

        allowInsecure = AWCore.getAllowInsecure()

        alwaysOnEnabled = AWCore.getAlwaysOnEnabled()
        includeAllNetworks = AWCore.getTunnelIncludeAllNetworks()
        includeAPNs = AWCore.getTunnelIncludeAPNs()
        includeCellularServices = AWCore.getTunnelIncludeCellularServices()
        includeLocalNetworks = AWCore.getTunnelIncludeLocalNetworks()
    }
}
