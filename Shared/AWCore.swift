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
        static let bundle = "com.argsment.Anywhere"
        static let appGroupSuite = "group.\(bundle)"
        static let iCloudContainer = "iCloud.\(bundle)"
        static let errorDomain = bundle
        static let pathMonitorQueue = "\(bundle).path-monitor"
        static let lwipQueue = "\(bundle).lwip"
        static let mitmScriptQueue = "\(bundle).mitm-script"
        static let udpQueue = "\(bundle).udp"
        static let outputQueue = "\(bundle).output"

        // MARK: Proxy socket & protocol queue labels
        //
        // Per-socket/per-session queues deliberately share one label per role.

        static let rawTCPSocketQueue = "\(bundle).raw-tcp-socket"
        static let rawUDPSocketQueue = "\(bundle).raw-udp-socket"
        static let quicQueue = "\(bundle).quic"
        static let http11Queue = "\(bundle).http11"
        static let http2SessionQueue = "\(bundle).http2-session"
        static let http3PoolCleanupQueue = "\(bundle).http3-pool-cleanup"
        static let anyTLSIdleQueue = "\(bundle).anytls-idle-cleanup"
        static let anyTLSSessionTimerQueue = "\(bundle).anytls-session-timer"

        static let sudokuTCPReadQueue = "\(bundle).sudoku.tcp.read"
        static let sudokuTCPWriteQueue = "\(bundle).sudoku.tcp.write"
        static let sudokuMuxReadQueue = "\(bundle).sudoku.mux.read"
        static let sudokuMuxWriteQueue = "\(bundle).sudoku.mux.write"
        static let sudokuUDPReadQueue = "\(bundle).sudoku.udp.read"
        static let sudokuUDPWriteQueue = "\(bundle).sudoku.udp.write"

        // MARK: MITM supervisor queue labels
        //
        // A supervisor must run off the worker queue it watches; one shared
        // monitor queue hosts every hard-cap check.

        static let mitmMonitorQueue = "\(bundle).mitm-monitor"
        static let mitmBodyWatchdogQueue = "\(bundle).mitm-body-watchdog"
        static let mitmGateMatchQueue = "\(bundle).mitm-gate-match"
    }
    
    static var isHostApp: Bool {
        Bundle.main.bundleIdentifier == Identifier.bundle
    }
    
    private static let userDefaults: UserDefaults = {
        let defaults = UserDefaults(suiteName: Identifier.appGroupSuite)!
        defaults.register(defaults: registeredDefaults)
        return defaults
    }()
    
    private static let registeredDefaults: [String: Any] = [
        UserDefaultsKey.blockWebRTC: true,
        UserDefaultsKey.bypassCountryCode: "",
        UserDefaultsKey.encryptedDNSProtocol: "doh",
        UserDefaultsKey.encryptedDNSServer: "https://cloudflare-dns.com/dns-query",
        UserDefaultsKey.identifier: UUID().uuidString,
        UserDefaultsKey.proxyMode: ProxyMode.rule.rawValue,
        UserDefaultsKey.quicPolicy: QUICPolicy.automatic.rawValue,
        UserDefaultsKey.reflectionAddresses: ["10.7.0.1"],
        UserDefaultsKey.trustedCertificateSHA256s: [],
        UserDefaultsKey.trustedSSIDs: [],
    ]

    // MARK: - UserDefaults Keys

    private enum UserDefaultsKey {
        static let advertiseIPv6ToApps = "advertiseIPv6ToApps"
        static let allowInsecure = "allowInsecure"
        static let alwaysOnEnabled = "alwaysOnEnabled"
        static let alwaysUntrustCellular = "alwaysUntrustCellular"
        static let blockWebRTC = "blockWebRTC"
        static let bypassCountryCode = "bypassCountryCode"
        static let encryptedDNSEnabled = "encryptedDNSEnabled"
        static let encryptedDNSProtocol = "encryptedDNSProtocol"
        static let encryptedDNSServer = "encryptedDNSServer"
        static let experimentalEnabled = "experimentalEnabled"
        static let hiddenSettingsItems = "hiddenSettingsItems"
        static let hideVPNIcon = "hideVPNIcon"
        static let homeColorScheme = "homeColorScheme"
        static let iCloudSyncEnabled = "iCloudSyncEnabled"
        static let identifier = "identifier"
        static let lastConfigurationData = "lastConfigurationData"
        static let onboardingCompleted = "onboardingCompleted"
        static let proxyMode = "proxyMode"
        static let quicPolicy = "quicPolicy"
        static let reflectionAddresses = "reflectionAddresses"
        static let reflectionEnabled = "reflectionEnabled"
        static let remnawaveHWIDEnabled = "remnawaveHWIDEnabled"
        static let ruleSetAssignments = "ruleSetAssignments"
        static let selectedChainId = "selectedChainId"
        static let selectedConfigurationId = "selectedConfigurationId"
        static let trustedCertificateSHA256s = "trustedCertificateSHA256s"
        static let trustedSSIDs = "trustedSSIDs"
        static let tunnelIncludeAllNetworks = "tunnelIncludeAllNetworks"
        static let tunnelIncludeAPNs = "tunnelIncludeAPNs"
        static let tunnelIncludeCellularServices = "tunnelIncludeCellularServices"
        static let tunnelIncludeLocalNetworks = "tunnelIncludeLocalNetworks"
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
            print("Failed to migrate \(fileName): \(error)")
        }
    }

    // MARK: - Typed UserDefaults Accessors
    
    // App
    static func getIdentifier() -> String {
        userDefaults.string(forKey: UserDefaultsKey.identifier)!
    }
    
    static func getOnboardingCompleted() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.onboardingCompleted)
    }

    static func setOnboardingCompleted(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.onboardingCompleted)
    }
    
    static func getICloudSyncEnabled() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.iCloudSyncEnabled)
    }

    static func setICloudSyncEnabled(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.iCloudSyncEnabled)
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
    
    // Settings
    static func getAlwaysOnEnabled() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.alwaysOnEnabled)
    }

    static func setAlwaysOnEnabled(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.alwaysOnEnabled)
    }
    
    static func getProxyMode() -> ProxyMode {
        ProxyMode(rawValue: userDefaults.string(forKey: UserDefaultsKey.proxyMode)!) ?? .rule
    }
    
    static func setProxyMode(_ proxyMode: ProxyMode) {
        userDefaults.set(proxyMode.rawValue, forKey: UserDefaultsKey.proxyMode)
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

    static func getHiddenSettingsItems() -> [String] {
        userDefaults.stringArray(forKey: UserDefaultsKey.hiddenSettingsItems) ?? []
    }

    static func setHiddenSettingsItems(_ value: [String]) {
        userDefaults.set(value, forKey: UserDefaultsKey.hiddenSettingsItems)
    }

    static func getHideVPNIcon() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.hideVPNIcon)
    }

    static func setHideVPNIcon(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.hideVPNIcon)
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
    
    static func getAdvertiseIPv6ToApps() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.advertiseIPv6ToApps)
    }

    static func setAdvertiseIPv6ToApps(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.advertiseIPv6ToApps)
    }

    static func getEncryptedDNSEnabled() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.encryptedDNSEnabled)
    }
    
    static func setEncryptedDNSEnabled(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.encryptedDNSEnabled)
    }
    
    static func getEncryptedDNSProtocol() -> String {
        userDefaults.string(forKey: UserDefaultsKey.encryptedDNSProtocol)!
    }
    
    static func setEncryptedDNSProtocol(_ value: String) {
        userDefaults.set(value, forKey: UserDefaultsKey.encryptedDNSProtocol)
    }
    
    static func getEncryptedDNSServer() -> String {
        userDefaults.string(forKey: UserDefaultsKey.encryptedDNSServer)!
    }
    
    static func setEncryptedDNSServer(_ value: String) {
        userDefaults.set(value, forKey: UserDefaultsKey.encryptedDNSServer)
    }
    
    static func getRemnawaveHWIDEnabled() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.remnawaveHWIDEnabled)
    }

    static func setRemnawaveHWIDEnabled(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.remnawaveHWIDEnabled)
    }

    static func getTunnelIncludeAllNetworks() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.tunnelIncludeAllNetworks)
    }

    static func setTunnelIncludeAllNetworks(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.tunnelIncludeAllNetworks)
    }

    static func getTunnelIncludeLocalNetworks() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.tunnelIncludeLocalNetworks)
    }

    static func setTunnelIncludeLocalNetworks(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.tunnelIncludeLocalNetworks)
    }

    static func getTunnelIncludeAPNs() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.tunnelIncludeAPNs)
    }

    static func setTunnelIncludeAPNs(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.tunnelIncludeAPNs)
    }

    static func getTunnelIncludeCellularServices() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.tunnelIncludeCellularServices)
    }

    static func setTunnelIncludeCellularServices(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.tunnelIncludeCellularServices)
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
            logger.error("Failed to write routing data: \(error)")
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
            logger.error("Failed to write MITM data: \(error)")
        }
    }

    // MARK: - Darwin Notification Names

    enum Notification {
        static let tunnelSettingsChanged = "\(Identifier.bundle).tunnelSettingsChanged" as CFString
        static let routingChanged = "\(Identifier.bundle).routingChanged" as CFString
        static let certificatePolicyChanged = "\(Identifier.bundle).certificatePolicyChanged" as CFString
        static let mitmChanged = "\(Identifier.bundle).mitmChanged" as CFString
    }

    private static var lastPostTimes = [CFNotificationName: CFAbsoluteTime]()
    private static var pendingWorkItems = [CFNotificationName: DispatchWorkItem]()
    private static let postLock = NSLock()
    private static let throttleInterval: CFAbsoluteTime = 1.0

    private static func postThrottled(_ name: CFNotificationName) {
        postLock.lock()
        let now = CFAbsoluteTimeGetCurrent()
        let lastTime = lastPostTimes[name] ?? 0
        let elapsed = now - lastTime

        pendingWorkItems[name]?.cancel()

        if elapsed >= throttleInterval {
            lastPostTimes[name] = now
            postLock.unlock()
            CFNotificationCenterPostNotification(
                CFNotificationCenterGetDarwinNotifyCenter(), name, nil, nil, true
            )
        } else {
            let delay = throttleInterval - elapsed
            let item = DispatchWorkItem {
                postLock.lock()
                lastPostTimes[name] = CFAbsoluteTimeGetCurrent()
                pendingWorkItems[name] = nil
                postLock.unlock()
                CFNotificationCenterPostNotification(
                    CFNotificationCenterGetDarwinNotifyCenter(), name, nil, nil, true
                )
            }
            pendingWorkItems[name] = item
            postLock.unlock()
            DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: item)
        }
    }

    static func notifyTunnelSettingsChanged() {
        postThrottled(CFNotificationName(Notification.tunnelSettingsChanged))
    }

    static func notifyRoutingChanged() {
        postThrottled(CFNotificationName(Notification.routingChanged))
    }

    static func notifyCertificatePolicyChanged() {
        postThrottled(CFNotificationName(Notification.certificatePolicyChanged))
    }

    static func notifyMITMChanged() {
        postThrottled(CFNotificationName(Notification.mitmChanged))
    }
}
