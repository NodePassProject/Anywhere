//
//  VPNViewModel.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import NetworkExtension
import Combine
import SwiftUI

/// ViewModel managing VPN connection state and operations
@Observable @MainActor
class VPNViewModel {
    var vpnStatus: NEVPNStatus = .disconnected
    var selectedConfiguration: VLESSConfiguration? {
        didSet {
            if let selectedConfiguration {
                APCore.userDefaults.set(selectedConfiguration.id.uuidString, forKey: Self.selectedConfigurationIdKey)
            } else {
                APCore.userDefaults.removeObject(forKey: Self.selectedConfigurationIdKey)
            }
            // If VPN is connected, push new configuration to the tunnel
            if vpnStatus == .connected, let selectedConfiguration {
                sendConfigurationToTunnel(selectedConfiguration)
            }
        }
    }
    private(set) var configurations: [VLESSConfiguration] = []
    private(set) var subscriptions: [Subscription] = []
    var latencyResults: [UUID: LatencyResult] = [:]
    var startError: String?
    var orphanedRuleSetNames: [String] = []
    var bytesIn: Int64 = 0
    var bytesOut: Int64 = 0

    private let store = ConfigurationStore.shared
    private let subscriptionStore = SubscriptionStore.shared
    let ruleSetStore = RuleSetStore.shared
    private var vpnManager: NETunnelProviderManager?
    private var statusObserver: AnyCancellable?
    private var storeCancellable: AnyCancellable?
    private var subscriptionStoreCancellable: AnyCancellable?
    private var statsTask: Task<Void, Never>?

    private static let selectedConfigurationIdKey = "selectedConfigurationId"

    init() {
        configurations = store.configurations
        subscriptions = subscriptionStore.subscriptions

        // Restore selected configuration from UserDefaults
        if let savedConfigurationIdSrting = APCore.userDefaults.string(forKey: Self.selectedConfigurationIdKey),
           let savedConfigurationId = UUID(uuidString: savedConfigurationIdSrting),
           let configuration = configurations.first(where: { $0.id == savedConfigurationId }) {
            selectedConfiguration = configuration
        } else {
            selectedConfiguration = configurations.first
        }

        storeCancellable = store.$configurations
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newConfigurations in
                guard let self else { return }
                self.configurations = newConfigurations
                // Keep selection valid
                if let selected = self.selectedConfiguration,
                   !newConfigurations.contains(where: { $0.id == selected.id }) {
                    self.selectedConfiguration = newConfigurations.first
                }
                if self.selectedConfiguration == nil {
                    self.selectedConfiguration = newConfigurations.first
                }
                // Reset routing rules that reference deleted configs
                let validIds = Set(newConfigurations.map { $0.id.uuidString })
                let affected = self.ruleSetStore.clearOrphanedAssignments(availableConfigIds: validIds)
                if !affected.isEmpty {
                    self.orphanedRuleSetNames = affected
                    self.syncRoutingConfigurationToNE()
                }
            }

        subscriptionStoreCancellable = subscriptionStore.$subscriptions
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newSubscriptions in
                self?.subscriptions = newSubscriptions
            }

        setupStatusObserver()
        setupVPNManager()
    }

    // MARK: - Computed Properties

    var hasConfigurations: Bool {
        !configurations.isEmpty
    }

    var statusColor: Color {
        switch vpnStatus {
        case .connected:
            return .green
        case .connecting, .reasserting:
            return .yellow
        case .disconnecting:
            return .orange
        case .disconnected, .invalid:
            return .red
        @unknown default:
            return .gray
        }
    }

    var statusText: String {
        switch vpnStatus {
        case .connected:
            return String(localized: "Connected")
        case .connecting:
            return String(localized: "Connecting...")
        case .disconnecting:
            return String(localized: "Disconnecting...")
        case .reasserting:
            return String(localized: "Reconnecting...")
        case .disconnected:
            return String(localized: "Disconnected")
        case .invalid:
            return String(localized: "Not Configured")
        @unknown default:
            return String(localized: "Unknown")
        }
    }

    var isButtonDisabled: Bool {
        !hasConfigurations || (vpnStatus != .connected && vpnStatus != .disconnected)
    }

    // MARK: - Configuration CRUD

    func addConfiguration(_ configuration: VLESSConfiguration) {
        store.add(configuration)
        if selectedConfiguration == nil {
            selectedConfiguration = configuration
        }
    }

    func updateConfiguration(_ configuration: VLESSConfiguration) {
        store.update(configuration)
        if selectedConfiguration?.id == configuration.id {
            selectedConfiguration = configuration
        }
    }

    func deleteConfiguration(_ configuration: VLESSConfiguration) {
        store.delete(configuration)
    }

    // MARK: - Subscription CRUD

    func addSubscription(configurations newConfigurations: [VLESSConfiguration], subscription: Subscription) {
        for configuration in newConfigurations {
            let tagged = VLESSConfiguration(
                id: configuration.id, name: configuration.name, serverAddress: configuration.serverAddress,
                serverPort: configuration.serverPort, uuid: configuration.uuid, encryption: configuration.encryption,
                transport: configuration.transport, flow: configuration.flow, security: configuration.security,
                tls: configuration.tls, reality: configuration.reality, websocket: configuration.websocket,
                httpUpgrade: configuration.httpUpgrade, xhttp: configuration.xhttp, testseed: configuration.testseed,
                muxEnabled: configuration.muxEnabled, xudpEnabled: configuration.xudpEnabled,
                subscriptionId: subscription.id
            )
            store.add(tagged)
        }
        subscriptionStore.add(subscription)
        if selectedConfiguration == nil {
            selectedConfiguration = store.configurations.last
        }
    }

    func updateSubscription(_ subscription: Subscription) async throws {
        let result = try await SubscriptionFetcher.fetch(url: subscription.url)

        // Check if selection pointed to a configuration in this subscription
        let selectedWasInSubscription = selectedConfiguration.flatMap { $0.subscriptionId == subscription.id } ?? false

        // Match new configurations against old ones by content to preserve IDs (and routing rules)
        let oldConfigurations = configurations(for: subscription)
        var usedOldIds = Set<UUID>()
        var newConfigurations: [VLESSConfiguration] = []

        for configuration in result.configurations {
            let matchedOld = oldConfigurations.first { old in
                !usedOldIds.contains(old.id) && old.contentEquals(configuration)
            }
            let id: UUID
            if let matched = matchedOld {
                id = matched.id
                usedOldIds.insert(id)
            } else {
                id = configuration.id
            }
            newConfigurations.append(VLESSConfiguration(
                id: id, name: configuration.name, serverAddress: configuration.serverAddress,
                serverPort: configuration.serverPort, uuid: configuration.uuid, encryption: configuration.encryption,
                transport: configuration.transport, flow: configuration.flow, security: configuration.security,
                tls: configuration.tls, reality: configuration.reality, websocket: configuration.websocket,
                httpUpgrade: configuration.httpUpgrade, xhttp: configuration.xhttp, testseed: configuration.testseed,
                muxEnabled: configuration.muxEnabled, xudpEnabled: configuration.xudpEnabled,
                subscriptionId: subscription.id
            ))
        }

        // Replace old configurations with new ones
        store.deleteConfigurations(for: subscription.id)
        for configuration in newConfigurations {
            store.add(configuration)
        }

        // Update subscription metadata
        var updated = subscription
        updated.lastUpdate = Date()
        updated.upload = result.upload ?? subscription.upload
        updated.download = result.download ?? subscription.download
        updated.total = result.total ?? subscription.total
        updated.expire = result.expire ?? subscription.expire
        if let name = result.name {
            updated.name = name
        }
        subscriptionStore.update(updated)

        // Fix selection if it was pointing to a deleted configuration
        if selectedWasInSubscription {
            selectedConfiguration = configurations(for: subscription).first ?? configurations.first
        }
    }

    func deleteSubscription(_ subscription: Subscription) {
        store.deleteConfigurations(for: subscription.id)
        subscriptionStore.delete(subscription, configurationStore: store)
    }

    /// Returns the subscription that owns this configuration, if any.
    func subscription(for configuration: VLESSConfiguration) -> Subscription? {
        guard let subId = configuration.subscriptionId else { return nil }
        return subscriptions.first { $0.id == subId }
    }

    /// Returns all configurations belonging to a subscription.
    func configurations(for subscription: Subscription) -> [VLESSConfiguration] {
        configurations.filter { $0.subscriptionId == subscription.id }
    }

    // MARK: - Latency Testing

    private var latencyTask: Task<Void, Never>?

    func testLatency(for configuration: VLESSConfiguration) {
        latencyTask?.cancel()
        let configurationId = configuration.id
        latencyResults[configurationId] = .testing
        latencyTask = Task.detached { [configuration] in
            let result = await LatencyTester.test(configuration)
            await MainActor.run { [weak self] in
                self?.latencyResults[configurationId] = result
            }
        }
    }

    func testAllLatencies() {
        latencyTask?.cancel()
        let allConfigurations = configurations
        for configuration in allConfigurations {
            latencyResults[configuration.id] = .testing
        }
        latencyTask = Task.detached {
            for await (id, result) in LatencyTester.testAll(allConfigurations) {
                await MainActor.run { [weak self] in
                    self?.latencyResults[id] = result
                }
            }
        }
    }

    // MARK: - Setup

    private func setupStatusObserver() {
        statusObserver = NotificationCenter.default
            .publisher(for: .NEVPNStatusDidChange)
            .compactMap { $0.object as? NEVPNConnection }
            .receive(on: DispatchQueue.main)
            .sink { [weak self] connection in
                guard let self else { return }
                // Only react to our VPN manager's connection
                guard connection === self.vpnManager?.connection else { return }
                self.vpnStatus = connection.status
                if connection.status == .connected {
                    self.startStatsPolling()
                } else {
                    self.stopStatsPolling()
                    if connection.status == .disconnected || connection.status == .invalid {
                        self.bytesIn = 0
                        self.bytesOut = 0
                    }
                }
            }
    }

    private func startStatsPolling() {
        guard statsTask == nil else { return }
        statsTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard let self, !Task.isCancelled else { break }
                await self.pollStats()
            }
        }
    }

    private func stopStatsPolling() {
        statsTask?.cancel()
        statsTask = nil
    }

    private func pollStats() async {
        guard let session = vpnManager?.connection as? NETunnelProviderSession else { return }
        let message: [String: String] = ["type": "stats"]
        guard let data = try? JSONSerialization.data(withJSONObject: message) else { return }

        let response: Data? = await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(data) { response in
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }

        guard let response,
              let dict = try? JSONSerialization.jsonObject(with: response) as? [String: Any] else { return }
        self.bytesIn = (dict["bytesIn"] as? NSNumber)?.int64Value ?? 0
        self.bytesOut = (dict["bytesOut"] as? NSNumber)?.int64Value ?? 0
    }

    private func setupVPNManager() {
        Task {
            let managers = try? await NETunnelProviderManager.loadAllFromPreferences()
            if let manager = managers?.first {
                self.vpnManager = manager
                self.vpnStatus = manager.connection.status
                if manager.connection.status == .connected {
                    self.startStatsPolling()
                }
            } else {
                self.vpnManager = NETunnelProviderManager()
            }
        }
    }

    // MARK: - Actions

    func toggleVPN() {
        switch vpnStatus {
        case .connected, .connecting:
            disconnectVPN()
        case .disconnected, .invalid:
            connectVPN()
        default:
            break
        }
    }

    func connectVPN() {
        guard let manager = vpnManager,
              let configuration = selectedConfiguration else { return }

        // Sync routing rules to App Group before starting tunnel
        syncRoutingConfigurationToNE()

        // Resolve domain to IP before tunnel starts (avoids DNS-over-tunnel loop)
        let resolvedIP = Self.resolveServerAddress(configuration.serverAddress)

        // Configure the VPN
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = "com.argsment.Anywhere.Network-Extension"
        tunnelProtocol.serverAddress = "Anywhere"

        manager.protocolConfiguration = tunnelProtocol
        manager.localizedDescription = "Anywhere"
        manager.isEnabled = true

        let alwaysOn = APCore.userDefaults.bool(forKey: "alwaysOnEnabled")
        if alwaysOn {
            let rule = NEOnDemandRuleConnect()
            rule.interfaceTypeMatch = .any
            manager.onDemandRules = [rule]
            manager.isOnDemandEnabled = true
        } else {
            manager.isOnDemandEnabled = false
            manager.onDemandRules = nil
        }

        manager.saveToPreferences { [weak self] error in
            guard let self else { return }
            if let error {
                Task { @MainActor in self.startError = error.localizedDescription }
                return
            }

            manager.loadFromPreferences { error in
                if let error {
                    Task { @MainActor in self.startError = error.localizedDescription }
                    return
                }

                do {
                    var configurationDict = self.serializeConfiguration(configuration)
                    if let resolvedIP {
                        configurationDict["resolvedIP"] = resolvedIP
                    }
                    try manager.connection.startVPNTunnel(options: ["config": configurationDict as NSObject])
                } catch {
                    Task { @MainActor in self.startError = error.localizedDescription }
                }
            }
        }
    }

    func disconnectVPN() {
        guard let manager = vpnManager else { return }
        if manager.isOnDemandEnabled {
            manager.isOnDemandEnabled = false
            manager.saveToPreferences { _ in
                manager.connection.stopVPNTunnel()
            }
        } else {
            manager.connection.stopVPNTunnel()
        }
    }

    // MARK: - Configuration Switching

    /// Sends the new configuration to the running tunnel extension via app message.
    private func sendConfigurationToTunnel(_ configuration: VLESSConfiguration) {
        guard let session = vpnManager?.connection as? NETunnelProviderSession else { return }
        var configurationDict = serializeConfiguration(configuration)
        // Resolve domain to IP so the tunnel can use it for socket connections
        if let resolvedIP = Self.resolveServerAddress(configuration.serverAddress) {
            configurationDict["resolvedIP"] = resolvedIP
        }
        guard let data = try? JSONSerialization.data(withJSONObject: configurationDict) else { return }
        try? session.sendProviderMessage(data) { _ in }
    }

    // MARK: - DNS Resolution

    /// Resolves a server address to an IP string.
    /// If the address is already an IP (v4 or v6), returns it as-is.
    /// If it's a domain, resolves via `getaddrinfo` (system DNS, before tunnel is up).
    /// Returns `nil` on resolution failure.
    nonisolated static func resolveServerAddress(_ address: String) -> String? {
        // Strip brackets from IPv6 addresses (e.g. "[::1]" → "::1")
        let bare = address.hasPrefix("[") && address.hasSuffix("]")
            ? String(address.dropFirst().dropLast())
            : address

        // Check if already an IPv4 address
        var sa4 = sockaddr_in()
        if inet_pton(AF_INET, bare, &sa4.sin_addr) == 1 { return bare }

        // Check if already an IPv6 address
        var sa6 = sockaddr_in6()
        if inet_pton(AF_INET6, bare, &sa6.sin6_addr) == 1 { return bare }

        // Resolve domain → IP via getaddrinfo
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(bare, nil, &hints, &result) == 0, let res = result else {
            return nil
        }
        defer { freeaddrinfo(res) }

        // Extract the first resolved IP as a string
        var current: UnsafeMutablePointer<addrinfo>? = res
        while let info = current {
            let family = info.pointee.ai_family
            if family == AF_INET {
                var addr = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &addr.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                    return String(cString: buf)
                }
            } else if family == AF_INET6 {
                var addr = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                if inet_ntop(AF_INET6, &addr.sin6_addr, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    return String(cString: buf)
                }
            }
            current = info.pointee.ai_next
        }

        return nil
    }

    // MARK: - Routing Sync

    /// Builds routing configuration from rulesets and writes to App Group for the NE.
    func syncRoutingConfigurationToNE() {
        ruleSetStore.syncToAppGroup(configurations: configurations, serializeConfiguration: serializeConfiguration)
    }

    // MARK: - Configuration Serialization

    private func serializeConfiguration(_ configuration: VLESSConfiguration) -> [String: Any] {
        var configurationDict: [String: Any] = [
            "name": configuration.name,
            "serverAddress": configuration.serverAddress,
            "serverPort": configuration.serverPort,
            "uuid": configuration.uuid.uuidString,
            "encryption": configuration.encryption,
            "flow": configuration.flow ?? "",
            "security": configuration.security,
            "muxEnabled": configuration.muxEnabled,
            "xudpEnabled": configuration.xudpEnabled,
        ]

        // Add Reality configuration if present
        if let reality = configuration.reality {
            configurationDict["realityServerName"] = reality.serverName
            configurationDict["realityPublicKey"] = reality.publicKey.base64EncodedString()
            configurationDict["realityShortId"] = reality.shortId.map { String(format: "%02x", $0) }.joined()
            configurationDict["realityFingerprint"] = reality.fingerprint.rawValue
        }

        // Add TLS configuration if present
        if let tls = configuration.tls {
            configurationDict["tlsServerName"] = tls.serverName
            if let alpn = tls.alpn {
                configurationDict["tlsAlpn"] = alpn.joined(separator: ",")
            }
            configurationDict["tlsAllowInsecure"] = tls.allowInsecure
            configurationDict["tlsFingerprint"] = tls.fingerprint.rawValue
        }

        // Add transport and WebSocket configuration
        configurationDict["transport"] = configuration.transport
        if let ws = configuration.websocket {
            configurationDict["wsHost"] = ws.host
            configurationDict["wsPath"] = ws.path
            if !ws.headers.isEmpty {
                configurationDict["wsHeaders"] = ws.headers.map { "\($0.key):\($0.value)" }.joined(separator: ",")
            }
            configurationDict["wsMaxEarlyData"] = ws.maxEarlyData
            configurationDict["wsEarlyDataHeaderName"] = ws.earlyDataHeaderName
        }

        // Add HTTP upgrade configuration
        if let hu = configuration.httpUpgrade {
            configurationDict["huHost"] = hu.host
            configurationDict["huPath"] = hu.path
            if !hu.headers.isEmpty {
                configurationDict["huHeaders"] = hu.headers.map { "\($0.key):\($0.value)" }.joined(separator: ",")
            }
        }

        // Add XHTTP configuration
        if let xhttp = configuration.xhttp {
            configurationDict["xhttpHost"] = xhttp.host
            configurationDict["xhttpPath"] = xhttp.path
            configurationDict["xhttpMode"] = xhttp.mode.rawValue
            if !xhttp.headers.isEmpty {
                configurationDict["xhttpHeaders"] = xhttp.headers.map { "\($0.key):\($0.value)" }.joined(separator: ",")
            }
            configurationDict["xhttpNoGRPCHeader"] = xhttp.noGRPCHeader
        }

        return configurationDict
    }
}
