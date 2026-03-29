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
@MainActor
class VPNViewModel: ObservableObject {
    static let shared = VPNViewModel()

    @Published var vpnStatus: NEVPNStatus = .disconnected
    @Published var selectedConfiguration: ProxyConfiguration? {
        didSet {
            if !_suppressSelectionPersistence {
                // Direct proxy selection — clear any chain selection
                selectedChainId = nil
                AWCore.userDefaults.removeObject(forKey: Self.selectedChainIdKey)
                if let selectedConfiguration {
                    AWCore.userDefaults.set(selectedConfiguration.id.uuidString, forKey: Self.selectedConfigurationIdKey)
                } else {
                    AWCore.userDefaults.removeObject(forKey: Self.selectedConfigurationIdKey)
                }
            }
            // If VPN is connected, push new configuration to the tunnel
            if vpnStatus == .connected, let selectedConfiguration {
                sendConfigurationToTunnel(selectedConfiguration)
            }
        }
    }
    @Published private(set) var configurations: [ProxyConfiguration] = []
    @Published private(set) var subscriptions: [Subscription] = []
    @Published private(set) var chains: [ProxyChain] = []
    /// Non-nil when a chain is the active selection.
    @Published private(set) var selectedChainId: UUID?
    @Published var latencyResults: [UUID: LatencyResult] = [:]
    @Published var chainLatencyResults: [UUID: LatencyResult] = [:]
    @Published var startError: String?
    @Published var orphanedRuleSetNames: [String] = []
    @Published var proxyMode: String = AWCore.userDefaults.string(forKey: "proxyMode") ?? "rule" {
        didSet {
            AWCore.userDefaults.set(proxyMode, forKey: "proxyMode")
            notifySettingsChanged()
        }
    }

    private let store = ConfigurationStore.shared
    private let subscriptionStore = SubscriptionStore.shared
    private let chainStore = ChainStore.shared
    private let ruleSetStore = RuleSetStore.shared
    @Published private(set) var isManagerReady = false
    private var vpnManager: NETunnelProviderManager?
    private var statusObserver: AnyCancellable?
    private var storeCancellable: AnyCancellable?
    private var subscriptionStoreCancellable: AnyCancellable?
    private var chainStoreCancellable: AnyCancellable?
    @Published private(set) var pendingReconnect = false
    /// Suppresses UserDefaults persistence in `selectedConfiguration.didSet`
    /// so that `selectChain` can set the chain ID without the didSet clearing it.
    private var _suppressSelectionPersistence = false

    private static let selectedConfigurationIdKey = "selectedConfigurationId"
    private static let selectedChainIdKey = "selectedChainId"

    init() {
        configurations = store.configurations
        subscriptions = subscriptionStore.subscriptions
        chains = chainStore.chains

        // Restore selection from UserDefaults — chain takes priority
        if let savedChainIdString = AWCore.userDefaults.string(forKey: Self.selectedChainIdKey),
           let savedChainId = UUID(uuidString: savedChainIdString),
           let chain = chains.first(where: { $0.id == savedChainId }),
           let resolved = resolveChain(chain) {
            selectedChainId = savedChainId
            _suppressSelectionPersistence = true
            selectedConfiguration = resolved
            _suppressSelectionPersistence = false
        } else if let savedConfigurationIdString = AWCore.userDefaults.string(forKey: Self.selectedConfigurationIdKey),
                  let savedConfigurationId = UUID(uuidString: savedConfigurationIdString),
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

                if self.selectedChainId != nil {
                    // Re-resolve chain in case underlying proxies changed
                    self.reResolveSelectedChain()
                } else {
                    // Keep selection valid and refreshed
                    if let selected = self.selectedConfiguration {
                        if let refreshed = newConfigurations.first(where: { $0.id == selected.id }) {
                            if refreshed != selected {
                                self.selectedConfiguration = refreshed
                            }
                        } else {
                            self.selectedConfiguration = newConfigurations.first
                        }
                    }
                    if self.selectedConfiguration == nil {
                        self.selectedConfiguration = newConfigurations.first
                    }
                }

                // Reset routing rules that reference deleted configs
                let validIds = Set(newConfigurations.map { $0.id.uuidString })
                let affected = self.ruleSetStore.clearOrphanedAssignments(availableConfigIds: validIds)
                if !affected.isEmpty {
                    self.orphanedRuleSetNames = affected
                    Task { await self.syncRoutingConfigurationToNE() }
                }

            }

        subscriptionStoreCancellable = subscriptionStore.$subscriptions
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newSubscriptions in
                self?.subscriptions = newSubscriptions
            }

        chainStoreCancellable = chainStore.$chains
            .receive(on: DispatchQueue.main)
            .sink { [weak self] newChains in
                guard let self else { return }
                self.chains = newChains
                // If selected chain was deleted, fall back to first proxy
                if let chainId = self.selectedChainId,
                   !newChains.contains(where: { $0.id == chainId }) {
                    self.selectedChainId = nil
                    AWCore.userDefaults.removeObject(forKey: Self.selectedChainIdKey)
                    self.selectedConfiguration = self.configurations.first
                }
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
        !isManagerReady || !hasConfigurations || (vpnStatus != .connected && vpnStatus != .disconnected)
    }

    // MARK: - Configuration CRUD

    func addConfiguration(_ configuration: ProxyConfiguration) {
        store.add(configuration)
        if selectedConfiguration == nil {
            selectedConfiguration = configuration
        }
    }

    func updateConfiguration(_ configuration: ProxyConfiguration) {
        store.update(configuration)
        if selectedConfiguration?.id == configuration.id {
            selectedConfiguration = configuration
        }
    }

    func deleteConfiguration(_ configuration: ProxyConfiguration) {
        store.delete(configuration)
    }

    // MARK: - Chain CRUD & Selection

    func addChain(_ chain: ProxyChain) {
        chainStore.add(chain)
    }

    func updateChain(_ chain: ProxyChain) {
        chainStore.update(chain)
        // Re-resolve if this is the active chain
        if selectedChainId == chain.id {
            if let resolved = resolveChain(chain) {
                _suppressSelectionPersistence = true
                selectedConfiguration = resolved
                _suppressSelectionPersistence = false
            }
        }
    }

    func deleteChain(_ chain: ProxyChain) {
        chainStore.delete(chain)
    }

    /// Selects a chain as the working configuration.
    func selectChain(_ chain: ProxyChain) {
        guard let resolved = resolveChain(chain) else { return }
        selectedChainId = chain.id
        AWCore.userDefaults.set(chain.id.uuidString, forKey: Self.selectedChainIdKey)
        AWCore.userDefaults.removeObject(forKey: Self.selectedConfigurationIdKey)
        _suppressSelectionPersistence = true
        selectedConfiguration = resolved
        _suppressSelectionPersistence = false
    }

    /// Resolves a chain into a composite ProxyConfiguration.
    ///
    /// The last proxy becomes the main config; preceding proxies fill the `chain` field.
    func resolveChain(_ chain: ProxyChain) -> ProxyConfiguration? {
        let configs = chain.proxyIds.compactMap { id in configurations.first(where: { $0.id == id }) }
        guard configs.count == chain.proxyIds.count, configs.count >= 2 else { return nil }
        let exitProxy = configs.last!
        let chainProxies = Array(configs.dropLast())
        return ProxyConfiguration(
            name: chain.name,
            serverAddress: exitProxy.serverAddress,
            serverPort: exitProxy.serverPort,
            outbound: exitProxy.outbound,
            transportLayer: exitProxy.transportLayer,
            securityLayer: exitProxy.securityLayer,
            testseed: exitProxy.testseed,
            muxEnabled: exitProxy.muxEnabled,
            xudpEnabled: exitProxy.xudpEnabled,
            chain: chainProxies
        )
    }

    /// Re-resolves the currently selected chain after underlying configs change.
    private func reResolveSelectedChain() {
        guard let chainId = selectedChainId,
              let chain = chains.first(where: { $0.id == chainId }) else {
            // Chain itself was deleted — handled by chain store sink
            return
        }
        if let resolved = resolveChain(chain) {
            _suppressSelectionPersistence = true
            selectedConfiguration = resolved
            _suppressSelectionPersistence = false
        } else {
            // Chain is broken (proxies deleted), fall back
            selectedChainId = nil
            AWCore.userDefaults.removeObject(forKey: Self.selectedChainIdKey)
            selectedConfiguration = configurations.first
        }
    }

    /// All items available for the Home picker (proxies + chains).
    var allPickerItems: [PickerItem] {
        var items: [PickerItem] = []
        for chain in chains {
            let proxies = chain.proxyIds.compactMap { id in configurations.first(where: { $0.id == id }) }
            guard proxies.count == chain.proxyIds.count, proxies.count >= 2 else { continue }
            items.append(PickerItem(id: chain.id, name: chain.name))
        }
        let standaloneConfigurations: [ProxyConfiguration] = configurations.filter { $0.subscriptionId == nil }
        for configuration in standaloneConfigurations {
            items.append(PickerItem(id: configuration.id, name: configuration.name))
        }
        let subscribedGroups: [(Subscription, [ProxyConfiguration])] = subscriptions.compactMap { subscription in
            let configurations = configurations(for: subscription)
            return configurations.isEmpty ? nil : (subscription, configurations)
        }
        for (_, configurations) in subscribedGroups {
            for configuration in configurations {
                items.append(PickerItem(id: configuration.id, name: configuration.name))
            }
        }
        return items
    }

    // MARK: - Subscription CRUD

    func addSubscription(configurations newConfigurations: [ProxyConfiguration], subscription: Subscription) {
        // Persist subscription first so an interrupted import never leaves orphan proxies.
        subscriptionStore.add(subscription)

        let tagged = newConfigurations.map { configuration in
            ProxyConfiguration(
                id: configuration.id, name: configuration.name,
                serverAddress: configuration.serverAddress, serverPort: configuration.serverPort,
                subscriptionId: subscription.id,
                outbound: configuration.outbound, transportLayer: configuration.transportLayer,
                securityLayer: configuration.securityLayer, testseed: configuration.testseed,
                muxEnabled: configuration.muxEnabled, xudpEnabled: configuration.xudpEnabled
            )
        }
        // Single batch write + single @Published emission.
        store.replaceConfigurations(for: subscription.id, with: tagged)

        if selectedConfiguration == nil {
            selectedConfiguration = store.configurations.last
        }
    }

    func updateSubscription(_ subscription: Subscription) async throws {
        let result = try await SubscriptionFetcher.fetch(url: subscription.url)

        // Check if selection pointed to a configuration in this subscription
        let selectedWasInSubscription = selectedConfiguration.flatMap { $0.subscriptionId == subscription.id } ?? false

        // Match new configurations against old ones by name to preserve IDs (and routing rules).
        // When multiple configs share the same name, they are matched positionally within that group.
        let oldConfigurations = configurations(for: subscription)

        // Group old configs by name, preserving order within each group
        var oldByName: [String: [ProxyConfiguration]] = [:]
        for old in oldConfigurations {
            oldByName[old.name, default: []].append(old)
        }
        // Track how many old configs per name have been consumed
        var oldNameCursor: [String: Int] = [:]

        var newConfigurations: [ProxyConfiguration] = []

        for configuration in result.configurations {
            let name = configuration.name
            let cursor = oldNameCursor[name, default: 0]
            let id: UUID
            if let group = oldByName[name], cursor < group.count {
                id = group[cursor].id
                oldNameCursor[name] = cursor + 1
            } else {
                id = configuration.id
            }
            newConfigurations.append(ProxyConfiguration(
                id: id, name: configuration.name,
                serverAddress: configuration.serverAddress, serverPort: configuration.serverPort,
                subscriptionId: subscription.id,
                outbound: configuration.outbound, transportLayer: configuration.transportLayer,
                securityLayer: configuration.securityLayer, testseed: configuration.testseed,
                muxEnabled: configuration.muxEnabled, xudpEnabled: configuration.xudpEnabled
            ))
        }

        // Atomically replace old configurations with new ones (single publisher emission)
        store.replaceConfigurations(for: subscription.id, with: newConfigurations)

        // Update subscription metadata
        var updated = subscription
        updated.lastUpdate = Date()
        updated.upload = result.upload ?? subscription.upload
        updated.download = result.download ?? subscription.download
        updated.total = result.total ?? subscription.total
        updated.expire = result.expire ?? subscription.expire
        if let name = result.name, !updated.isNameCustomized {
            updated.name = name
        }
        subscriptionStore.update(updated)

        // Fix selection if it was pointing to a configuration in this subscription
        if selectedWasInSubscription {
            if let selectedId = selectedConfiguration?.id,
               let preserved = newConfigurations.first(where: { $0.id == selectedId }) {
                selectedConfiguration = preserved
            } else {
                selectedConfiguration = newConfigurations.first ?? configurations.first
            }
        }
    }

    func toggleSubscriptionCollapsed(_ subscription: Subscription) {
        var updated = subscription
        updated.collapsed.toggle()
        subscriptionStore.update(updated)
    }

    func renameSubscription(_ subscription: Subscription, to newName: String) {
        var updated = subscription
        updated.name = newName
        updated.isNameCustomized = true
        subscriptionStore.update(updated)
    }

    func deleteSubscription(_ subscription: Subscription) {
        subscriptionStore.delete(subscription, configurationStore: store)
    }

    /// Returns the subscription that owns this configuration, if any.
    func subscription(for configuration: ProxyConfiguration) -> Subscription? {
        guard let subId = configuration.subscriptionId else { return nil }
        return subscriptions.first { $0.id == subId }
    }

    /// Returns all configurations belonging to a subscription.
    func configurations(for subscription: Subscription) -> [ProxyConfiguration] {
        configurations.filter { $0.subscriptionId == subscription.id }
    }

    // MARK: - Latency Testing

    private var latencyTask: Task<Void, Never>?

    func testLatency(for configuration: ProxyConfiguration) {
        latencyTask?.cancel()
        let configurationId = configuration.id
        latencyResults[configurationId] = .testing
        latencyTask = Task.detached { [weak self] in
            let resolved = LatencyTester.resolvedConfiguration(configuration)
            await MainActor.run { self?.syncProxyServerAddresses(for: resolved) }
            let result = await LatencyTester.test(resolved)
            await MainActor.run { self?.latencyResults[configurationId] = result }
        }
    }

    func testLatencies(for targets: [ProxyConfiguration]? = nil) {
        latencyTask?.cancel()
        let configs = targets ?? configurations
        for config in configs {
            latencyResults[config.id] = .testing
        }
        latencyTask = Task.detached { [weak self] in
            let resolvedConfigurations = configs.map(LatencyTester.resolvedConfiguration)
            await MainActor.run { self?.syncProxyServerAddresses(for: resolvedConfigurations) }
            for await (id, result) in LatencyTester.testAll(resolvedConfigurations) {
                await MainActor.run { [weak self] in
                    self?.latencyResults[id] = result
                }
            }
        }
    }

    // MARK: - Chain Latency Testing

    private var chainLatencyTask: Task<Void, Never>?

    func testChainLatency(for chain: ProxyChain) {
        guard let resolved = resolveChain(chain) else { return }
        chainLatencyResults[chain.id] = .testing
        let chainId = chain.id
        chainLatencyTask?.cancel()
        chainLatencyTask = Task.detached { [weak self] in
            let resolvedForTest = LatencyTester.resolvedConfiguration(resolved)
            await MainActor.run { self?.syncProxyServerAddresses(for: resolvedForTest) }
            let result = await LatencyTester.test(resolvedForTest)
            await MainActor.run { self?.chainLatencyResults[chainId] = result }
        }
    }

    func testAllChainLatencies() {
        chainLatencyTask?.cancel()
        var chainData: [(UUID, ProxyConfiguration)] = []
        for chain in chains {
            if let resolved = resolveChain(chain) {
                chainLatencyResults[chain.id] = .testing
                chainData.append((chain.id, resolved))
            }
        }
        chainLatencyTask = Task.detached { [weak self] in
            let resolvedChains = chainData.map { ($0.0, LatencyTester.resolvedConfiguration($0.1)) }
            await MainActor.run { self?.syncProxyServerAddresses(for: resolvedChains.map(\.1)) }
            let configs = resolvedChains.map { $0.1 }
            let idMap = Dictionary(uniqueKeysWithValues: zip(configs.map(\.id), resolvedChains.map(\.0)))
            for await (configId, result) in LatencyTester.testAll(configs) {
                if let chainId = idMap[configId] {
                    await MainActor.run { [weak self] in
                        self?.chainLatencyResults[chainId] = result
                    }
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
                let stats = ConnectionStatsModel.shared
                if connection.status == .connected {
                    if let session = self.vpnManager?.connection as? NETunnelProviderSession {
                        stats.startPolling(session: session)
                    }
                } else {
                    stats.stopPolling()
                    if connection.status == .disconnected || connection.status == .invalid {
                        stats.reset()
                        if self.pendingReconnect {
                            self.pendingReconnect = false
                            self.connectVPN()
                        }
                    }
                }
            }
    }

    private func setupVPNManager() {
        Task {
            let managers = try? await NETunnelProviderManager.loadAllFromPreferences()
            if let manager = managers?.first {
                self.vpnManager = manager
                self.vpnStatus = manager.connection.status
                if manager.connection.status == .connected,
                   let session = manager.connection as? NETunnelProviderSession {
                    ConnectionStatsModel.shared.startPolling(session: session)
                }
            } else {
                self.vpnManager = NETunnelProviderManager()
            }
            self.isManagerReady = true
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

        // Mark the active proxy domain so ProxyDNSCache returns stale IPs on expiry
        ProxyDNSCache.shared.setActiveProxyDomain(configuration.serverAddress)

        // Sync proxy server addresses so the extension can bypass them at the lwIP level
        syncProxyServerAddresses(for: configuration)

        Task {
            // Routing sync (file I/O + DNS off main actor)
            await syncRoutingConfigurationToNE()

            // Pre-resolve the main proxy address off main actor
            let resolvedIP = await Task.detached {
                VPNViewModel.resolveServerAddress(configuration.serverAddress)
            }.value

            // Configure the VPN (back on main actor)
            let tunnelProtocol = NETunnelProviderProtocol()
            tunnelProtocol.providerBundleIdentifier = "com.argsment.Anywhere.Network-Extension"
            tunnelProtocol.serverAddress = "Anywhere"

            manager.protocolConfiguration = tunnelProtocol
            manager.localizedDescription = "Anywhere"
            manager.isEnabled = true

            let alwaysOn = AWCore.userDefaults.bool(forKey: "alwaysOnEnabled")
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
                        var configurationDict = VPNViewModel.serializeConfiguration(configuration)
                        if let resolvedIP {
                            configurationDict["resolvedIP"] = resolvedIP
                        }

                        // Persist configuration to App Group so the Network Extension
                        // can read it when started from Settings or Always On (On Demand),
                        // where options is nil.
                        if let jsonData = try? JSONSerialization.data(withJSONObject: configurationDict) {
                            AWCore.userDefaults.set(jsonData, forKey: "lastConfigurationData")
                        }

                        try manager.connection.startVPNTunnel(options: ["config": configurationDict as NSObject])
                    } catch {
                        Task { @MainActor in self.startError = error.localizedDescription }
                    }
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

    func reconnectVPN() {
        guard let manager = vpnManager,
              vpnStatus == .connected || vpnStatus == .connecting else { return }
        pendingReconnect = true
        // Disable on-demand first to prevent system auto-restart during reconnection
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
    private func sendConfigurationToTunnel(_ configuration: ProxyConfiguration) {
        guard let session = vpnManager?.connection as? NETunnelProviderSession else { return }

        // Sync proxy addresses so the extension bypasses this config's server at the lwIP level
        syncProxyServerAddresses(for: configuration)

        var configurationDict = Self.serializeConfiguration(configuration)

        // Resolve DNS and send off main actor
        Task.detached {
            VPNViewModel.resolveAddressesInDict(&configurationDict)

            // Keep App Group in sync so On Demand restarts use the latest selection
            if let jsonData = try? JSONSerialization.data(withJSONObject: configurationDict) {
                AWCore.userDefaults.set(jsonData, forKey: "lastConfigurationData")
            }

            guard let data = try? JSONSerialization.data(withJSONObject: configurationDict) else { return }
            try? session.sendProviderMessage(data) { _ in }
        }
    }

    /// Resolves `serverAddress` to IP for a config dict (main proxy only, for logging/initial bypass).
    /// Chain proxy addresses are resolved lazily via ProxyDNSCache at connection time.
    nonisolated private static func resolveAddressesInDict(_ dict: inout [String: Any]) {
        if let addr = dict["serverAddress"] as? String, dict["resolvedIP"] == nil {
            if let resolved = resolveServerAddress(addr) {
                dict["resolvedIP"] = resolved
            }
        }
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
    func syncRoutingConfigurationToNE() async {
        await ruleSetStore.syncToAppGroup(configurations: configurations, serializeConfiguration: VPNViewModel.serializeConfiguration)
        await ruleSetStore.syncBypassCountryRules()
    }

    // MARK: - Proxy Server Address Sync

    /// Syncs proxy server domains for the given configuration (including chain
    /// proxies) plus any already-cached resolved IPs to the extension via
    /// App Group + IPC. Called on VPN connect, configuration switch, and latency test.
    func syncProxyServerAddresses(for configuration: ProxyConfiguration) {
        syncProxyServerAddresses(for: [configuration])
    }

    func syncProxyServerAddresses(for configurations: [ProxyConfiguration]) {
        var domains = Set<String>()
        var addresses = Set<String>()
        for configuration in configurations {
            domains.insert(configuration.serverAddress)
            if let resolvedIP = configuration.resolvedIP {
                addresses.insert(resolvedIP)
            }
            if let chain = configuration.chain {
                for proxy in chain {
                    domains.insert(proxy.serverAddress)
                    if let resolvedIP = proxy.resolvedIP {
                        addresses.insert(resolvedIP)
                    }
                }
            }
        }

        // Collect domains + any explicit or already-cached resolved IPs
        addresses.formUnion(domains)
        for domain in domains {
            if let ips = ProxyDNSCache.shared.cachedIPs(for: domain) {
                addresses.formUnion(ips)
            }
        }

        let addressArray = Array(addresses)

        // Persist to App Group so the extension can read them on start (Settings / Always On)
        if let data = try? JSONSerialization.data(withJSONObject: addressArray) {
            AWCore.userDefaults.set(data, forKey: "proxyServerAddresses")
        }

        // Send to running tunnel via IPC
        guard vpnStatus == .connected,
              let session = vpnManager?.connection as? NETunnelProviderSession else { return }
        let message: [String: Any] = ["type": "proxyAddresses", "addresses": addressArray]
        guard let data = try? JSONSerialization.data(withJSONObject: message) else { return }
        try? session.sendProviderMessage(data) { _ in }
    }

    // MARK: - Configuration Serialization

    nonisolated static func serializeConfiguration(_ configuration: ProxyConfiguration) -> [String: Any] {
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
            "outboundProtocol": configuration.outboundProtocol.rawValue,
        ]

        // Add protocol-specific credential fields
        switch configuration.outbound {
        case .vless: break
        case .shadowsocks(let password, let method):
            configurationDict["ssPassword"] = password
            configurationDict["ssMethod"] = method
        case .socks5(let username, let password):
            if let username { configurationDict["socks5Username"] = username }
            if let password { configurationDict["socks5Password"] = password }
        case .http11(let username, let password):
            configurationDict["http11Username"] = username
            configurationDict["http11Password"] = password
        case .http2(let username, let password):
            configurationDict["http2Username"] = username
            configurationDict["http2Password"] = password
        case .http3(let username, let password):
            configurationDict["http3Username"] = username
            configurationDict["http3Password"] = password
        }

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

        // Add proxy chain if present
        if let chain = configuration.chain, !chain.isEmpty {
            configurationDict["chain"] = chain.map { Self.serializeConfiguration($0) }
        }

        return configurationDict
    }

    // MARK: - Notifications

    private func notifySettingsChanged() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName("com.argsment.Anywhere.settingsChanged" as CFString),
            nil, nil, true
        )
    }
}
