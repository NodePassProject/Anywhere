//
//  AWCore.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "AWCore")

nonisolated final class AWCore {
    
    // MARK: - Identifiers

    enum Identifier {
        static let appGroupSuite = "group.\(bundle)"
        static let bundle = "com.argsment.Anywhere"
        static let errorDomain = bundle
        static let iCloudContainer = "iCloud.\(bundle)"
        static let lwipQueue = "\(bundle).lwip"
    }
    
    static var isHostApp: Bool {
        Bundle.main.bundleIdentifier == Identifier.bundle
    }
    
    nonisolated(unsafe) private static let userDefaults: UserDefaults = {
        let defaults = UserDefaults(suiteName: Identifier.appGroupSuite)!
        defaults.register(defaults: [
            UserDefaultsKey.blockWebRTC: true,
            UserDefaultsKey.bypassCountryCode: "",
            UserDefaultsKey.echDNSDoHURL: DNSUpstream.defaultDoHURL,
            UserDefaultsKey.echDNSPlainServer: DNSUpstream.defaultPlainServer,
            UserDefaultsKey.fallbackDNSServer: DNSUpstream.defaultPlainServer,
            UserDefaultsKey.ipRuleDNSDoHURL: DNSUpstream.defaultDoHURL,
            UserDefaultsKey.ipRuleDNSPlainServer: DNSUpstream.defaultPlainServer,
            UserDefaultsKey.proxyDNSDoHURL: DNSUpstream.defaultDoHURL,
            UserDefaultsKey.proxyDNSPlainServer: DNSUpstream.defaultPlainServer,
            UserDefaultsKey.proxyMode: ProxyMode.rule.rawValue,
            UserDefaultsKey.quicPolicy: QUICPolicy.automatic.rawValue,
            UserDefaultsKey.reflectionAddresses: ["10.7.0.1"],
            UserDefaultsKey.remnawaveHWID: UUID().uuidString,
            UserDefaultsKey.showVoyagerCard: true,
            UserDefaultsKey.subscriptionDNSDoHURL: DNSUpstream.defaultDoHURL,
            UserDefaultsKey.subscriptionDNSPlainServer: DNSUpstream.defaultPlainServer,
            UserDefaultsKey.trustedCertificateSHA256s: [],
            UserDefaultsKey.trustedSSIDs: [],
        ])
        return defaults
    }()

    // MARK: - UserDefaults Keys

    private enum UserDefaultsKey {
        static let advertiseIPv6ToApps = "advertiseIPv6ToApps"
        static let allowInsecure = "allowInsecure"
        static let alwaysOnEnabled = "alwaysOnEnabled"
        static let alwaysTrustCellular = "alwaysTrustCellular"
        static let alwaysUntrustCellular = "alwaysUntrustCellular"
        static let blockUDP = "blockUDP"
        static let blockWebRTC = "blockWebRTC"
        static let bypassCountryCode = "bypassCountryCode"
        static let chainLatencyResults = "chainLatencyResults"
        static let detailRevealed = "detailRevealed"
        static let echDNSDoHURL = "echDNSDoHURL"
        static let echDNSMode = "echDNSMode"
        static let echDNSPlainServer = "echDNSPlainServer"
        static let experimentalEnabled = "experimentalEnabled"
        static let fallbackDNSMode = "fallbackDNSMode"
        static let fallbackDNSServer = "fallbackDNSServer"
        static let hideVPNIcon = "hideVPNIcon"
        static let homeColorScheme = "homeColorScheme"
        static let iCloudSyncEnabled = "iCloudSyncEnabled"
        static let identifier = "identifier"
        static let ipRuleDNSDoHURL = "ipRuleDNSDoHURL"
        static let ipRuleDNSMode = "ipRuleDNSMode"
        static let ipRuleDNSPlainServer = "ipRuleDNSPlainServer"
        static let lastConfigurationData = "lastConfigurationData"
        static let latencyResults = "latencyResults"
        static let mitmEnabled = "mitmEnabled"
        static let onboardingCompleted = "onboardingCompleted"
        static let preventDNSLeak = "preventDNSLeak"
        static let proxiesPageProxyType = "proxiesPageProxyType"
        static let proxyDNSDoHURL = "proxyDNSDoHURL"
        static let proxyDNSMode = "proxyDNSMode"
        static let proxyDNSPlainServer = "proxyDNSPlainServer"
        static let proxyMode = "proxyMode"
        static let quicPolicy = "quicPolicy"
        static let reflectionAddresses = "reflectionAddresses"
        static let reflectionEnabled = "reflectionEnabled"
        static let remnawaveHWID = "remnawaveHWID"
        static let remnawaveHWIDEnabled = "remnawaveHWIDEnabled"
        static let ruleSetAssignments = "ruleSetAssignments"
        static let selectedChainId = "selectedChainId"
        static let selectedConfigurationId = "selectedConfigurationId"
        static let showVoyagerCard = "showVoyagerCard"
        static let subscriptionDNSDoHURL = "subscriptionDNSDoHURL"
        static let subscriptionDNSMode = "subscriptionDNSMode"
        static let subscriptionDNSPlainServer = "subscriptionDNSPlainServer"
        static let trustedCertificateSHA256s = "trustedCertificateSHA256s"
        static let trustedSSIDs = "trustedSSIDs"
        static let tunnelExcludeAPNs = "tunnelExcludeAPNs"
        static let tunnelExcludeCellularServices = "tunnelExcludeCellularServices"
        static let tunnelExcludeDeviceCommunication = "tunnelExcludeDeviceCommunication"
        static let tunnelExcludedRoutes = "tunnelExcludedRoutes"
        static let tunnelExcludeLocalNetworks = "tunnelExcludeLocalNetworks"
        static let tunnelIncludeAllNetworks = "tunnelIncludeAllNetworks"
        static let tunnelIncludedRoutes = "tunnelIncludedRoutes"
        static let voyagerMembership = "voyagerMembership"
    }

    static func migrateToAppGroup(fileName: String) {
        let fileManager = FileManager.default
        let oldURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent(fileName)
        guard let container = fileManager.containerURL(forSecurityApplicationGroupIdentifier: Identifier.appGroupSuite) else { return }
        let newURL = container.appendingPathComponent(fileName)
        guard fileManager.fileExists(atPath: oldURL.path), !fileManager.fileExists(atPath: newURL.path) else { return }
        do {
            try fileManager.moveItem(at: oldURL, to: newURL)
        } catch {
            logger.report(AnywhereError.store(.migrationFailed(file: fileName, underlying: error)))
        }
    }

    // MARK: - Typed UserDefaults Accessors
    
    // App
    static func getOnboardingCompleted() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.onboardingCompleted)
    }

    static func setOnboardingCompleted(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.onboardingCompleted)
    }

    static func getDetailRevealed() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.detailRevealed)
    }

    static func setDetailRevealed(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.detailRevealed)
    }

    static func getProxiesPageProxyType() -> String? {
        userDefaults.string(forKey: UserDefaultsKey.proxiesPageProxyType)
    }

    static func setProxiesPageProxyType(_ rawValue: String) {
        userDefaults.set(rawValue, forKey: UserDefaultsKey.proxiesPageProxyType)
    }
    
    static func getICloudSyncEnabled() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.iCloudSyncEnabled)
    }

    static func setICloudSyncEnabled(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.iCloudSyncEnabled)
    }
    
    // Voyager
    static func getVoyagerMembership() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.voyagerMembership)
    }

    static func setVoyagerMembership(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.voyagerMembership)
    }

    static func clearVoyagerMembership() {
        userDefaults.removeObject(forKey: UserDefaultsKey.voyagerMembership)
    }

    static func getShowVoyagerCard() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.showVoyagerCard)
    }

    static func setShowVoyagerCard(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.showVoyagerCard)
    }

    enum ThemeColorSlot: String {
        case connectedBackgroundStart
        case connectedBackgroundEnd
        case disconnectedBackgroundStart
        case disconnectedBackgroundEnd
    }
    
    static func getHomeColorScheme() -> String? {
        userDefaults.string(forKey: UserDefaultsKey.homeColorScheme)
    }

    static func setHomeColorScheme(_ rawValue: String) {
        userDefaults.set(rawValue, forKey: UserDefaultsKey.homeColorScheme)
    }
    
    static func getThemeColorData(_ slot: ThemeColorSlot) -> Data? {
        userDefaults.data(forKey: "themeColor.\(slot.rawValue)")
    }

    static func setThemeColorData(_ slot: ThemeColorSlot, _ data: Data?) {
        let key = "themeColor.\(slot.rawValue)"
        if let data {
            userDefaults.set(data, forKey: key)
        } else {
            userDefaults.removeObject(forKey: key)
        }
    }

    // Tunnel
    static func getLastConfigurationData() -> Data? {
        userDefaults.data(forKey: UserDefaultsKey.lastConfigurationData)
    }

    static func setLastConfigurationData(_ data: Data) {
        userDefaults.set(data, forKey: UserDefaultsKey.lastConfigurationData)
    }
    
    static func getSelectedConfigurationId() -> UUID? {
        userDefaults.string(forKey: UserDefaultsKey.selectedConfigurationId).flatMap(UUID.init(uuidString:))
    }
    
    static func setSelectedConfigurationId(_ id: UUID?) {
        if let id {
            userDefaults.set(id.uuidString, forKey: UserDefaultsKey.selectedConfigurationId)
        } else {
            userDefaults.removeObject(forKey: UserDefaultsKey.selectedConfigurationId)
        }
    }

    static func getSelectedChainId() -> UUID? {
        userDefaults.string(forKey: UserDefaultsKey.selectedChainId).flatMap(UUID.init(uuidString:))
    }
    
    static func setSelectedChainId(_ id: UUID?) {
        if let id {
            userDefaults.set(id.uuidString, forKey: UserDefaultsKey.selectedChainId)
        } else {
            userDefaults.removeObject(forKey: UserDefaultsKey.selectedChainId)
        }
    }

    // Latency
    static func getLatencyResultsData() -> Data? {
        userDefaults.data(forKey: UserDefaultsKey.latencyResults)
    }

    static func setLatencyResultsData(_ data: Data) {
        userDefaults.set(data, forKey: UserDefaultsKey.latencyResults)
    }

    static func getChainLatencyResultsData() -> Data? {
        userDefaults.data(forKey: UserDefaultsKey.chainLatencyResults)
    }

    static func setChainLatencyResultsData(_ data: Data) {
        userDefaults.set(data, forKey: UserDefaultsKey.chainLatencyResults)
    }

    // Settings
    static func getProxyMode() -> ProxyMode {
        ProxyMode(rawValue: userDefaults.string(forKey: UserDefaultsKey.proxyMode)!) ?? .rule
    }
    
    static func setProxyMode(_ proxyMode: ProxyMode) {
        userDefaults.set(proxyMode.rawValue, forKey: UserDefaultsKey.proxyMode)
    }
    
    static func getAlwaysOnEnabled() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.alwaysOnEnabled)
    }

    static func setAlwaysOnEnabled(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.alwaysOnEnabled)
    }
    
    static func getBlockUDP() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.blockUDP)
    }

    static func setBlockUDP(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.blockUDP)
    }

    static func getQUICPolicy() -> QUICPolicy {
        userDefaults.string(forKey: UserDefaultsKey.quicPolicy).flatMap(QUICPolicy.init(rawValue:)) ?? .blocked
    }

    static func setQUICPolicy(_ value: QUICPolicy) {
        userDefaults.set(value.rawValue, forKey: UserDefaultsKey.quicPolicy)
    }

    static func getBlockWebRTC() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.blockWebRTC)
    }

    static func setBlockWebRTC(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.blockWebRTC)
    }

    static func getPreventDNSLeak() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.preventDNSLeak)
    }

    static func setPreventDNSLeak(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.preventDNSLeak)
    }

    static func getBypassCountryCode() -> String {
        userDefaults.string(forKey: UserDefaultsKey.bypassCountryCode)!
    }

    static func setBypassCountryCode(_ value: String) {
        userDefaults.set(value, forKey: UserDefaultsKey.bypassCountryCode)
    }
    
    static func getRuleSetAssignments() -> [String: String] {
        userDefaults.dictionary(forKey: UserDefaultsKey.ruleSetAssignments) as? [String: String] ?? [:]
    }

    static func setRuleSetAssignments(_ assignments: [String: String]) {
        userDefaults.set(assignments, forKey: UserDefaultsKey.ruleSetAssignments)
    }

    static func getAllowInsecure() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.allowInsecure)
    }

    static func setAllowInsecure(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.allowInsecure)
    }

    static func getTrustedCertificateFingerprints() -> [String] {
        userDefaults.stringArray(forKey: UserDefaultsKey.trustedCertificateSHA256s)!
    }

    static func setTrustedCertificateFingerprints(_ fingerprints: [String]) {
        userDefaults.set(fingerprints, forKey: UserDefaultsKey.trustedCertificateSHA256s)
    }

    static func getTrustedSSIDs() -> [String] {
        userDefaults.stringArray(forKey: UserDefaultsKey.trustedSSIDs) ?? []
    }

    static func setTrustedSSIDs(_ ssids: [String]) {
        userDefaults.set(ssids, forKey: UserDefaultsKey.trustedSSIDs)
    }

    static func getAlwaysTrustCellular() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.alwaysTrustCellular)
    }

    static func setAlwaysTrustCellular(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.alwaysTrustCellular)
    }

    static func getAlwaysUntrustCellular() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.alwaysUntrustCellular)
    }

    static func setAlwaysUntrustCellular(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.alwaysUntrustCellular)
    }

    static func getExperimentalEnabled() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.experimentalEnabled)
    }

    static func setExperimentalEnabled(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.experimentalEnabled)
    }

    static func getHideVPNIcon() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.hideVPNIcon)
    }

    static func setHideVPNIcon(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.hideVPNIcon)
    }
    
    static func getTunnelIncludeAllNetworks() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.tunnelIncludeAllNetworks)
    }

    static func setTunnelIncludeAllNetworks(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.tunnelIncludeAllNetworks)
    }

    static func getTunnelExcludeLocalNetworks() -> Bool {
        if let value = userDefaults.object(forKey: UserDefaultsKey.tunnelExcludeLocalNetworks) as? Bool {
            return value
        }
        return true
    }

    static func setTunnelExcludeLocalNetworks(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.tunnelExcludeLocalNetworks)
    }

    static func getTunnelExcludeAPNs() -> Bool {
        if let value = userDefaults.object(forKey: UserDefaultsKey.tunnelExcludeAPNs) as? Bool {
            return value
        }
        return true
    }

    static func setTunnelExcludeAPNs(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.tunnelExcludeAPNs)
    }

    static func getTunnelExcludeCellularServices() -> Bool {
        if let value = userDefaults.object(forKey: UserDefaultsKey.tunnelExcludeCellularServices) as? Bool {
            return value
        }
        return true
    }

    static func setTunnelExcludeCellularServices(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.tunnelExcludeCellularServices)
    }

    static func getTunnelExcludeDeviceCommunication() -> Bool {
        if let value = userDefaults.object(forKey: UserDefaultsKey.tunnelExcludeDeviceCommunication) as? Bool {
            return value
        }
        return true
    }

    static func setTunnelExcludeDeviceCommunication(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.tunnelExcludeDeviceCommunication)
    }

    static func getTunnelIncludedRoutes() -> [String] {
        userDefaults.stringArray(forKey: UserDefaultsKey.tunnelIncludedRoutes) ?? []
    }

    static func setTunnelIncludedRoutes(_ routes: [String]) {
        userDefaults.set(routes, forKey: UserDefaultsKey.tunnelIncludedRoutes)
    }

    static func getTunnelExcludedRoutes() -> [String] {
        userDefaults.stringArray(forKey: UserDefaultsKey.tunnelExcludedRoutes) ?? []
    }

    static func setTunnelExcludedRoutes(_ routes: [String]) {
        userDefaults.set(routes, forKey: UserDefaultsKey.tunnelExcludedRoutes)
    }

    static func getReflectionEnabled() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.reflectionEnabled)
    }

    static func setReflectionEnabled(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.reflectionEnabled)
    }

    static func getReflectionAddresses() -> [String] {
        userDefaults.stringArray(forKey: UserDefaultsKey.reflectionAddresses) ?? []
    }

    static func setReflectionAddresses(_ addresses: [String]) {
        userDefaults.set(addresses, forKey: UserDefaultsKey.reflectionAddresses)
    }

    static func getSubscriptionDNSMode() -> DNSMode {
        userDefaults.string(forKey: UserDefaultsKey.subscriptionDNSMode).flatMap(DNSMode.init(rawValue:)) ?? .default
    }

    static func setSubscriptionDNSMode(_ value: DNSMode) {
        userDefaults.set(value.rawValue, forKey: UserDefaultsKey.subscriptionDNSMode)
    }

    static func getSubscriptionDNSPlainServer() -> String {
        userDefaults.string(forKey: UserDefaultsKey.subscriptionDNSPlainServer)!
    }

    static func setSubscriptionDNSPlainServer(_ value: String) {
        userDefaults.set(value, forKey: UserDefaultsKey.subscriptionDNSPlainServer)
    }

    static func getSubscriptionDNSDoHURL() -> String {
        userDefaults.string(forKey: UserDefaultsKey.subscriptionDNSDoHURL)!
    }

    static func setSubscriptionDNSDoHURL(_ value: String) {
        userDefaults.set(value, forKey: UserDefaultsKey.subscriptionDNSDoHURL)
    }

    static func getIPRuleDNSMode() -> DNSMode {
        userDefaults.string(forKey: UserDefaultsKey.ipRuleDNSMode).flatMap(DNSMode.init(rawValue:)) ?? .default
    }

    static func setIPRuleDNSMode(_ value: DNSMode) {
        userDefaults.set(value.rawValue, forKey: UserDefaultsKey.ipRuleDNSMode)
    }

    static func getIPRuleDNSPlainServer() -> String {
        userDefaults.string(forKey: UserDefaultsKey.ipRuleDNSPlainServer)!
    }

    static func setIPRuleDNSPlainServer(_ value: String) {
        userDefaults.set(value, forKey: UserDefaultsKey.ipRuleDNSPlainServer)
    }

    static func getIPRuleDNSDoHURL() -> String {
        userDefaults.string(forKey: UserDefaultsKey.ipRuleDNSDoHURL)!
    }

    static func setIPRuleDNSDoHURL(_ value: String) {
        userDefaults.set(value, forKey: UserDefaultsKey.ipRuleDNSDoHURL)
    }

    static func getFallbackDNSMode() -> FallbackDNSMode {
        userDefaults.string(forKey: UserDefaultsKey.fallbackDNSMode).flatMap(FallbackDNSMode.init(rawValue:)) ?? .default
    }

    static func setFallbackDNSMode(_ value: FallbackDNSMode) {
        userDefaults.set(value.rawValue, forKey: UserDefaultsKey.fallbackDNSMode)
    }

    static func getFallbackDNSServer() -> String {
        userDefaults.string(forKey: UserDefaultsKey.fallbackDNSServer)!
    }

    static func setFallbackDNSServer(_ value: String) {
        userDefaults.set(value, forKey: UserDefaultsKey.fallbackDNSServer)
    }

    static func getProxyDNSMode() -> DNSMode {
        userDefaults.string(forKey: UserDefaultsKey.proxyDNSMode).flatMap(DNSMode.init(rawValue:)) ?? .default
    }

    static func setProxyDNSMode(_ value: DNSMode) {
        userDefaults.set(value.rawValue, forKey: UserDefaultsKey.proxyDNSMode)
    }

    static func getProxyDNSPlainServer() -> String {
        userDefaults.string(forKey: UserDefaultsKey.proxyDNSPlainServer)!
    }

    static func setProxyDNSPlainServer(_ value: String) {
        userDefaults.set(value, forKey: UserDefaultsKey.proxyDNSPlainServer)
    }

    static func getProxyDNSDoHURL() -> String {
        userDefaults.string(forKey: UserDefaultsKey.proxyDNSDoHURL)!
    }

    static func setProxyDNSDoHURL(_ value: String) {
        userDefaults.set(value, forKey: UserDefaultsKey.proxyDNSDoHURL)
    }

    static func getECHDNSMode() -> DNSMode {
        userDefaults.string(forKey: UserDefaultsKey.echDNSMode).flatMap(DNSMode.init(rawValue:)) ?? .default
    }

    static func setECHDNSMode(_ value: DNSMode) {
        userDefaults.set(value.rawValue, forKey: UserDefaultsKey.echDNSMode)
    }

    static func getECHDNSPlainServer() -> String {
        userDefaults.string(forKey: UserDefaultsKey.echDNSPlainServer)!
    }

    static func setECHDNSPlainServer(_ value: String) {
        userDefaults.set(value, forKey: UserDefaultsKey.echDNSPlainServer)
    }

    static func getECHDNSDoHURL() -> String {
        userDefaults.string(forKey: UserDefaultsKey.echDNSDoHURL)!
    }

    static func setECHDNSDoHURL(_ value: String) {
        userDefaults.set(value, forKey: UserDefaultsKey.echDNSDoHURL)
    }

    static func getSubscriptionDNSUpstream() -> DNSUpstream {
        DNSUpstream(
            mode: getSubscriptionDNSMode(),
            plainServer: getSubscriptionDNSPlainServer(),
            dohURL: getSubscriptionDNSDoHURL()
        )
    }
    
    static func getIPRuleDNSUpstream() -> DNSUpstream {
        DNSUpstream(
            mode: getIPRuleDNSMode(),
            plainServer: getIPRuleDNSPlainServer(),
            dohURL: getIPRuleDNSDoHURL()
        )
    }
    
    static func getFallbackDNSUpstream() -> DNSUpstream {
        switch getFallbackDNSMode() {
        case .default: return .defaultPlain
        case .plain: return DNSUpstream.parsePlain(getFallbackDNSServer()) ?? .defaultPlain
        }
    }

    static func getProxyDNSUpstream() -> DNSUpstream {
        DNSUpstream(
            mode: getProxyDNSMode(),
            plainServer: getProxyDNSPlainServer(),
            dohURL: getProxyDNSDoHURL()
        )
    }

    static func getECHDNSUpstream() -> DNSUpstream {
        DNSUpstream(
            mode: getECHDNSMode(),
            plainServer: getECHDNSPlainServer(),
            dohURL: getECHDNSDoHURL()
        )
    }

    static func getAdvertiseIPv6ToApps() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.advertiseIPv6ToApps)
    }

    static func setAdvertiseIPv6ToApps(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.advertiseIPv6ToApps)
    }

    static func getRemnawaveHWIDEnabled() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.remnawaveHWIDEnabled)
    }

    static func setRemnawaveHWIDEnabled(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.remnawaveHWIDEnabled)
    }
    
    static func getRemnawaveHWID() -> String {
        userDefaults.string(forKey: UserDefaultsKey.remnawaveHWID)!
    }

    // MARK: - Routing Data

    private static let routingDataURL = FileManager.default
        .containerURL(forSecurityApplicationGroupIdentifier: Identifier.appGroupSuite)!
        .appendingPathComponent("routing.bin")
    
    static func getRoutingData() -> Data? {
        try? Data(contentsOf: routingDataURL, options: .mappedIfSafe)
    }

    static func setRoutingData(_ data: Data) {
        do {
            try data.write(to: routingDataURL, options: [.atomic, .noFileProtection])
            // Drop the obsolete UserDefaults copy now that routing lives in a file.
            userDefaults.removeObject(forKey: "routingData")
        } catch {
            logger.report(AnywhereError.store(.saveFailed(.routingPayload, underlying: error)))
        }
    }

    // MARK: - MITM Data

    private static let mitmDataURL = FileManager.default
        .containerURL(forSecurityApplicationGroupIdentifier: Identifier.appGroupSuite)!
        .appendingPathComponent("mitm.bin")

    static func getMITMData() -> Data? {
        try? Data(contentsOf: mitmDataURL, options: .mappedIfSafe)
    }

    static func setMITMData(_ data: Data) {
        do {
            try data.write(to: mitmDataURL, options: [.atomic, .noFileProtection])
        } catch {
            logger.report(AnywhereError.store(.saveFailed(.mitmPayload, underlying: error)))
        }
    }
    
    static func getMITMEnabled() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.mitmEnabled)
    }

    static func setMITMEnabled(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.mitmEnabled)
    }

    /// False until the toggle has been written locally at least once — the cue for the
    /// one-time migration off the synced blob (see `MITMRuleSetStore.init`).
    static func hasMITMEnabled() -> Bool {
        userDefaults.object(forKey: UserDefaultsKey.mitmEnabled) != nil
    }
}
