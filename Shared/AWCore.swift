//
//  AWCore.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

enum ProxyMode: String, CaseIterable {
    case rule
    case global
}

final class AWCore {
    // MARK: - Identifiers

    enum Identifier {
        /// Bundle identifier prefix for the Anywhere app family.
        static let bundle = "com.argsment.Anywhere"
        /// App Group suite shared between the app and Network Extension.
        static let appGroupSuite = "group.\(bundle)"
        /// Error domain for `NSError` returned by the tunnel provider.
        static let errorDomain = bundle
        /// Dispatch queue label for the VPN path monitor.
        static let pathMonitorQueue = "\(bundle).path-monitor"
        /// Dispatch queue label for the serial lwIP queue.
        static let lwipQueue = "\(bundle).lwip"
        /// Dispatch queue label for writes back to the TUN interface.
        static let outputQueue = "\(bundle).output"
    }

    /// App Group `UserDefaults` shared between the app and Network Extension.
    /// Prefer the typed `getX` / `setX` accessors below over direct access.
    private static let userDefaults = UserDefaults(suiteName: Identifier.appGroupSuite)!

    // MARK: - UserDefaults Keys

    private enum UserDefaultsKey {
        static let allowInsecure = "allowInsecure"
        static let alwaysOnEnabled = "alwaysOnEnabled"
        static let bypassCountryCode = "bypassCountryCode"
        static let chains = "store.chains"
        static let customRuleSets = "customRuleSets"
        static let encryptedDNSEnabled = "encryptedDNSEnabled"
        static let encryptedDNSProtocol = "encryptedDNSProtocol"
        static let encryptedDNSServer = "encryptedDNSServer"
        static let experimentalEnabled = "experimentalEnabled"
        static let hideVPNIcon = "hideVPNIcon"
        static let lastConfigurationData = "lastConfigurationData"
        static let identifier = "identifier"
        static let ipv6DNSEnabled = "ipv6DNSEnabled"
        static let onboardingCompleted = "onboardingCompleted"
        static let proxyMode = "proxyMode"
        static let proxyServerAddresses = "proxyServerAddresses"
        static let remnawaveHWIDEnabled = "remnawaveHWIDEnabled"
        static let routingData = "routingData"
        static let ruleSetAssignments = "ruleSetAssignments"
        static let selectedConfigurationId = "selectedConfigurationId"
        static let selectedChainId = "selectedChainId"
        static let subscriptions = "store.subscriptions"
        static let trustedCertificateSHA256s = "trustedCertificateSHA256s"
    }

    /// One-time migration of a JSON file from the per-app documents directory
    /// into the App Group container shared with the Network Extension.
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
        if let identifier = userDefaults.string(forKey: UserDefaultsKey.identifier) {
            return identifier
        } else {
            let newIdentifier = UUID().uuidString
            userDefaults.set(newIdentifier, forKey: UserDefaultsKey.identifier)
            return newIdentifier
        }
    }
    
    static func getOnboardingCompleted() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.onboardingCompleted)
    }

    static func setOnboardingCompleted(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.onboardingCompleted)
    }
    
    // tvOS
    static func getSubscriptionsData() -> Data? {
        userDefaults.data(forKey: UserDefaultsKey.subscriptions)
    }

    static func setSubscriptionsData(_ data: Data) {
        userDefaults.set(data, forKey: UserDefaultsKey.subscriptions)
    }

    static func getChainsData() -> Data? {
        userDefaults.data(forKey: UserDefaultsKey.chains)
    }

    static func setChainsData(_ data: Data) {
        userDefaults.set(data, forKey: UserDefaultsKey.chains)
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
    
    static func getProxyServerAddressesData() -> Data? {
        userDefaults.data(forKey: UserDefaultsKey.proxyServerAddresses)
    }

    static func setProxyServerAddressesData(_ data: Data) {
        userDefaults.set(data, forKey: UserDefaultsKey.proxyServerAddresses)
    }
    
    static func getRoutingData() -> Data? {
        userDefaults.data(forKey: UserDefaultsKey.routingData)
    }

    static func setRoutingData(_ data: Data) {
        userDefaults.set(data, forKey: UserDefaultsKey.routingData)
    }

    // Settings
    static func getAlwaysOnEnabled() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.alwaysOnEnabled)
    }

    static func setAlwaysOnEnabled(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.alwaysOnEnabled)
    }
    
    static func getProxyMode() -> ProxyMode {
        userDefaults.string(forKey: UserDefaultsKey.proxyMode).flatMap(ProxyMode.init) ?? .rule
    }
    
    static func setProxyMode(_ proxyMode: ProxyMode) {
        userDefaults.set(proxyMode.rawValue, forKey: UserDefaultsKey.proxyMode)
    }

    static func getBypassCountryCode() -> String {
        userDefaults.string(forKey: UserDefaultsKey.bypassCountryCode) ?? ""
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

    static func getCustomRuleSetsData() -> Data? {
        userDefaults.data(forKey: UserDefaultsKey.customRuleSets)
    }

    static func setCustomRuleSetsData(_ data: Data) {
        userDefaults.set(data, forKey: UserDefaultsKey.customRuleSets)
    }

    static func getAllowInsecure() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.allowInsecure)
    }

    static func setAllowInsecure(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.allowInsecure)
    }

    static func getTrustedCertificateFingerprints() -> [String] {
        userDefaults.stringArray(forKey: UserDefaultsKey.trustedCertificateSHA256s) ?? []
    }

    static func setTrustedCertificateFingerprints(_ fingerprints: [String]) {
        userDefaults.set(fingerprints, forKey: UserDefaultsKey.trustedCertificateSHA256s)
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
    
    static func getIPv6DNSEnabled() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.ipv6DNSEnabled)
    }

    static func setIPv6DNSEnabled(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.ipv6DNSEnabled)
    }

    static func getEncryptedDNSEnabled() -> Bool {
        userDefaults.bool(forKey: UserDefaultsKey.encryptedDNSEnabled)
    }
    
    static func setEncryptedDNSEnabled(_ value: Bool) {
        userDefaults.set(value, forKey: UserDefaultsKey.encryptedDNSEnabled)
    }
    
    static func getEncryptedDNSProtocol() -> String {
        userDefaults.string(forKey: UserDefaultsKey.encryptedDNSProtocol) ?? "doh"
    }
    
    static func setEncryptedDNSProtocol(_ value: String) {
        userDefaults.set(value, forKey: UserDefaultsKey.encryptedDNSProtocol)
    }
    
    static func getEncryptedDNSServer() -> String {
        userDefaults.string(forKey: UserDefaultsKey.encryptedDNSServer) ?? "https://cloudflare-dns.com/dns-query"
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
    
    // MARK: - Darwin Notification Names

    enum Notification {
        static let tunnelSettingsChanged = "\(Identifier.bundle).tunnelSettingsChanged" as CFString
        static let routingChanged = "\(Identifier.bundle).routingChanged" as CFString
        static let certificatePolicyChanged = "\(Identifier.bundle).certificatePolicyChanged" as CFString
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
}
