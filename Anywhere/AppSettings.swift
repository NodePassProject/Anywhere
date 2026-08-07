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
    @ObservationIgnored var onTunnelBehaviorChange: (() -> Void)?

    // MARK: - Persist only

    var experimentalEnabled: Bool {
        didSet { AWCore.setExperimentalEnabled(experimentalEnabled) }
    }

    var iCloudSyncEnabled: Bool {
        didSet { AWCore.setICloudSyncEnabled(iCloudSyncEnabled) }
    }
    
    var showVoyagerCard: Bool {
        didSet { AWCore.setShowVoyagerCard(showVoyagerCard) }
    }

    var homeColorScheme: HomeColorScheme {
        didSet { AWCore.setHomeColorScheme(homeColorScheme.rawValue) }
    }

    var connectedBackgroundStartData: Data? {
        didSet { AWCore.setThemeColorData(.connectedBackgroundStart, connectedBackgroundStartData) }
    }

    var connectedBackgroundEndData: Data? {
        didSet { AWCore.setThemeColorData(.connectedBackgroundEnd, connectedBackgroundEndData) }
    }

    var disconnectedBackgroundStartData: Data? {
        didSet { AWCore.setThemeColorData(.disconnectedBackgroundStart, disconnectedBackgroundStartData) }
    }

    var disconnectedBackgroundEndData: Data? {
        didSet { AWCore.setThemeColorData(.disconnectedBackgroundEnd, disconnectedBackgroundEndData) }
    }
    
    var subscriptionDNSMode: DNSMode {
        didSet {
            AWCore.setSubscriptionDNSMode(subscriptionDNSMode)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var subscriptionDNSPlainServer: String {
        didSet {
            AWCore.setSubscriptionDNSPlainServer(subscriptionDNSPlainServer)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var subscriptionDNSDoHURL: String {
        didSet {
            AWCore.setSubscriptionDNSDoHURL(subscriptionDNSDoHURL)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var remnawaveHWIDEnabled: Bool {
        didSet { AWCore.setRemnawaveHWIDEnabled(remnawaveHWIDEnabled) }
    }

    // MARK: - Persist + notify the tunnel

    var tunnelExcludedRoutes: [String] {
        didSet {
            AWCore.setTunnelExcludedRoutes(tunnelExcludedRoutes)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var tunnelIncludedRoutes: [String] {
        didSet {
            AWCore.setTunnelIncludedRoutes(tunnelIncludedRoutes)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }
    
    var proxyMode: ProxyMode {
        didSet {
            AWCore.setProxyMode(proxyMode)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }
    
    var isGlobalMode: Bool {
        get { proxyMode == .global }
        set { proxyMode = newValue ? .global : .rule }
    }
    
    var blockUDP: Bool {
        didSet {
            AWCore.setBlockUDP(blockUDP)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }
    
    var quicPolicy: QUICPolicy {
        didSet {
            AWCore.setQUICPolicy(quicPolicy)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var blockWebRTC: Bool {
        didSet {
            AWCore.setBlockWebRTC(blockWebRTC)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }
    
    var preventDNSLeak: Bool {
        didSet {
            AWCore.setPreventDNSLeak(preventDNSLeak)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }
    
    var alwaysTrustCellular: Bool {
        didSet {
            AWCore.setAlwaysTrustCellular(alwaysTrustCellular)
            if alwaysTrustCellular, alwaysUntrustCellular {
                alwaysUntrustCellular = false
            }
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }
    
    var alwaysUntrustCellular: Bool {
        didSet {
            AWCore.setAlwaysUntrustCellular(alwaysUntrustCellular)
            if alwaysUntrustCellular, alwaysTrustCellular {
                alwaysTrustCellular = false
            }
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }
    
    var trustedSSIDs: [String] {
        didSet {
            AWCore.setTrustedSSIDs(trustedSSIDs)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }
    
    var hideVPNIcon: Bool {
        didSet {
            AWCore.setHideVPNIcon(hideVPNIcon)
            if hideVPNIcon, advertiseIPv6ToApps {
                advertiseIPv6ToApps = false
            } else {
                AWNotificationCenter.notifyTunnelSettingsChanged()
            }
        }
    }
    
    var reflectionAddresses: [String] {
        didSet {
            AWCore.setReflectionAddresses(reflectionAddresses)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var reflectionEnabled: Bool {
        didSet {
            AWCore.setReflectionEnabled(reflectionEnabled)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var ipRuleDNSMode: DNSMode {
        didSet {
            AWCore.setIPRuleDNSMode(ipRuleDNSMode)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var ipRuleDNSPlainServer: String {
        didSet {
            AWCore.setIPRuleDNSPlainServer(ipRuleDNSPlainServer)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var ipRuleDNSDoHURL: String {
        didSet {
            AWCore.setIPRuleDNSDoHURL(ipRuleDNSDoHURL)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }
    
    var proxyDNSMode: DNSMode {
        didSet {
            AWCore.setProxyDNSMode(proxyDNSMode)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var proxyDNSPlainServer: String {
        didSet {
            AWCore.setProxyDNSPlainServer(proxyDNSPlainServer)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var proxyDNSDoHURL: String {
        didSet {
            AWCore.setProxyDNSDoHURL(proxyDNSDoHURL)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var echDNSMode: DNSMode {
        didSet {
            AWCore.setECHDNSMode(echDNSMode)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var echDNSPlainServer: String {
        didSet {
            AWCore.setECHDNSPlainServer(echDNSPlainServer)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var echDNSDoHURL: String {
        didSet {
            AWCore.setECHDNSDoHURL(echDNSDoHURL)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var fallbackDNSMode: FallbackDNSMode {
        didSet {
            AWCore.setFallbackDNSMode(fallbackDNSMode)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    var fallbackDNSServer: String {
        didSet {
            AWCore.setFallbackDNSServer(fallbackDNSServer)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }
    
    var advertiseIPv6ToApps: Bool {
        didSet {
            AWCore.setAdvertiseIPv6ToApps(advertiseIPv6ToApps)
            AWNotificationCenter.notifyTunnelSettingsChanged()
        }
    }

    // MARK: - Persist + certificate policy

    var allowInsecure: Bool {
        didSet {
            AWCore.setAllowInsecure(allowInsecure)
            AWNotificationCenter.notifyCertificatePolicyChanged()
        }
    }

    // MARK: - Persist + reconnect the tunnel

    var alwaysOnEnabled: Bool {
        didSet {
            AWCore.setAlwaysOnEnabled(alwaysOnEnabled)
            onTunnelBehaviorChange?()
        }
    }

    var includeAllNetworks: Bool {
        didSet {
            AWCore.setTunnelIncludeAllNetworks(includeAllNetworks)
            onTunnelBehaviorChange?()
        }
    }

    var includeAPNs: Bool {
        didSet {
            AWCore.setTunnelIncludeAPNs(includeAPNs)
            onTunnelBehaviorChange?()
        }
    }

    var includeCellularServices: Bool {
        didSet {
            AWCore.setTunnelIncludeCellularServices(includeCellularServices)
            onTunnelBehaviorChange?()
        }
    }

    var includeLocalNetworks: Bool {
        didSet {
            AWCore.setTunnelIncludeLocalNetworks(includeLocalNetworks)
            onTunnelBehaviorChange?()
        }
    }

    init() {
        experimentalEnabled = AWCore.getExperimentalEnabled()
        iCloudSyncEnabled = AWCore.getICloudSyncEnabled()
        homeColorScheme = AWCore.getHomeColorScheme().flatMap(HomeColorScheme.init(rawValue:)) ?? .dark
        connectedBackgroundStartData = AWCore.getThemeColorData(.connectedBackgroundStart)
        connectedBackgroundEndData = AWCore.getThemeColorData(.connectedBackgroundEnd)
        disconnectedBackgroundStartData = AWCore.getThemeColorData(.disconnectedBackgroundStart)
        disconnectedBackgroundEndData = AWCore.getThemeColorData(.disconnectedBackgroundEnd)
        remnawaveHWIDEnabled = AWCore.getRemnawaveHWIDEnabled()
        showVoyagerCard = AWCore.getShowVoyagerCard()
        subscriptionDNSMode = AWCore.getSubscriptionDNSMode()
        subscriptionDNSPlainServer = AWCore.getSubscriptionDNSPlainServer()
        subscriptionDNSDoHURL = AWCore.getSubscriptionDNSDoHURL()

        advertiseIPv6ToApps = AWCore.getAdvertiseIPv6ToApps()
        alwaysTrustCellular = AWCore.getAlwaysTrustCellular()
        alwaysUntrustCellular = AWCore.getAlwaysUntrustCellular()
        blockUDP = AWCore.getBlockUDP()
        blockWebRTC = AWCore.getBlockWebRTC()
        echDNSMode = AWCore.getECHDNSMode()
        echDNSPlainServer = AWCore.getECHDNSPlainServer()
        echDNSDoHURL = AWCore.getECHDNSDoHURL()
        fallbackDNSMode = AWCore.getFallbackDNSMode()
        fallbackDNSServer = AWCore.getFallbackDNSServer()
        hideVPNIcon = AWCore.getHideVPNIcon()
        ipRuleDNSMode = AWCore.getIPRuleDNSMode()
        ipRuleDNSPlainServer = AWCore.getIPRuleDNSPlainServer()
        ipRuleDNSDoHURL = AWCore.getIPRuleDNSDoHURL()
        preventDNSLeak = AWCore.getPreventDNSLeak()
        proxyDNSMode = AWCore.getProxyDNSMode()
        proxyDNSPlainServer = AWCore.getProxyDNSPlainServer()
        proxyDNSDoHURL = AWCore.getProxyDNSDoHURL()
        proxyMode = AWCore.getProxyMode()
        quicPolicy = AWCore.getQUICPolicy()
        reflectionAddresses = AWCore.getReflectionAddresses()
        reflectionEnabled = AWCore.getReflectionEnabled()
        trustedSSIDs = AWCore.getTrustedSSIDs()
        tunnelExcludedRoutes = AWCore.getTunnelExcludedRoutes()
        tunnelIncludedRoutes = AWCore.getTunnelIncludedRoutes()

        allowInsecure = AWCore.getAllowInsecure()

        alwaysOnEnabled = AWCore.getAlwaysOnEnabled()
        includeAllNetworks = AWCore.getTunnelIncludeAllNetworks()
        includeAPNs = AWCore.getTunnelIncludeAPNs()
        includeCellularServices = AWCore.getTunnelIncludeCellularServices()
        includeLocalNetworks = AWCore.getTunnelIncludeLocalNetworks()
    }
}
