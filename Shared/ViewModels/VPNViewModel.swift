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

private let logger = AnywhereLogger(category: "VPNViewModel")

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
                AWCore.setSelectedChainId(nil)
                AWCore.setSelectedConfigurationId(selectedConfiguration?.id)
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

    private let store = ConfigurationStore.shared
    private let subscriptionStore = SubscriptionStore.shared
    private let chainStore = ChainStore.shared
    private let ruleSetStore = RoutingRuleSetStore.shared
    @Published private(set) var isManagerReady = false
    private var vpnManager: NETunnelProviderManager?
    private var statusObserver: AnyCancellable?
    private var storeCancellable: AnyCancellable?
    private var subscriptionStoreCancellable: AnyCancellable?
    private var chainStoreCancellable: AnyCancellable?
    @Published private(set) var pendingReconnect = false
    /// Read by `selectedConfiguration.didSet` to skip the default behavior that clears
    /// `selectedChainId`. Set only via `withoutSelectionPersistence` so the flag always
    /// resets, even if the assignment inside the block throws.
    private var _suppressSelectionPersistence = false

    /// Assign to `selectedConfiguration` without triggering the chain-clearing branch
    /// of its didSet. Used when restoring a chain selection or re-resolving an already
    /// selected chain, where the chain ID has already been persisted.
    private func withoutSelectionPersistence(_ block: () -> Void) {
        _suppressSelectionPersistence = true
        defer { _suppressSelectionPersistence = false }
        block()
    }

    init() {
        configurations = store.configurations
        subscriptions = subscriptionStore.subscriptions
        chains = chainStore.chains

        // Restore selection from UserDefaults — chain takes priority
        if let savedChainId = AWCore.getSelectedChainId(),
           let chain = chains.first(where: { $0.id == savedChainId }),
           let resolved = resolveChain(chain) {
            selectedChainId = savedChainId
            withoutSelectionPersistence { selectedConfiguration = resolved }
        } else if let savedConfigurationId = AWCore.getSelectedConfigurationId(),
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

                // Reset routing rules that reference deleted configs/chains
                self.clearOrphanedRuleSetAssignments(
                    configIds: Set(newConfigurations.map { $0.id.uuidString }),
                    chainIds: Set(self.chains.map { $0.id.uuidString })
                )

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
                    AWCore.setSelectedChainId(nil)
                    self.selectedConfiguration = self.configurations.first
                }

                // Reset routing rules that reference deleted chains
                self.clearOrphanedRuleSetAssignments(
                    configIds: Set(self.configurations.map { $0.id.uuidString }),
                    chainIds: Set(newChains.map { $0.id.uuidString })
                )
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
        !isManagerReady || !hasConfigurations || vpnStatus.isTransitioning
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
                withoutSelectionPersistence { selectedConfiguration = resolved }
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
        AWCore.setSelectedChainId(chain.id)
        AWCore.setSelectedConfigurationId(nil)
        withoutSelectionPersistence { selectedConfiguration = resolved }
    }

    /// Resolves a chain into a composite ProxyConfiguration.
    ///
    /// The last proxy becomes the main config; preceding proxies fill the `chain` field.
    func resolveChain(_ chain: ProxyChain) -> ProxyConfiguration? {
        chain.resolveComposite(from: configurations)
    }

    /// Re-resolves the currently selected chain after underlying configs change.
    private func reResolveSelectedChain() {
        guard let chainId = selectedChainId,
              let chain = chains.first(where: { $0.id == chainId }) else {
            // Chain itself was deleted — handled by chain store sink
            return
        }
        if let resolved = resolveChain(chain) {
            withoutSelectionPersistence { selectedConfiguration = resolved }
        } else {
            // Chain is broken (proxies deleted), fall back
            selectedChainId = nil
            AWCore.setSelectedChainId(nil)
            selectedConfiguration = configurations.first
        }
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
                outbound: configuration.outbound
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
                outbound: configuration.outbound
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

    func moveSubscriptions(fromOffsets source: IndexSet, toOffset destination: Int) {
        subscriptionStore.move(fromOffsets: source, toOffset: destination)
    }

    func moveStandaloneConfigurations(fromOffsets source: IndexSet, toOffset destination: Int) {
        store.moveStandaloneConfigurations(fromOffsets: source, toOffset: destination)
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
    //
    // Latency tests run inside the network extension via IPC. The main app
    // sends a `testLatency` message containing the configuration to test; the
    // extension dials the proxy directly (independent of the active tunnel)
    // and replies with the round-trip time. The tunnel must be running to
    // serve as the IPC host — if it isn't, we start it first.

    private var latencyTask: Task<Void, Never>?

    /// Cap on simultaneous in-flight test requests. Mirrors the previous
    /// in-process limit; keeps extension proxy connections within what a
    /// typical residential uplink/NAT can sustain.
    private static let maxConcurrentLatencyTests = 4

    func testLatency(for configuration: ProxyConfiguration) {
        latencyTask?.cancel()
        let configurationId = configuration.id
        latencyResults[configurationId] = .testing
        latencyTask = Task { [weak self] in
            guard let self else { return }
            let result = await self.runLatencyTest(for: configuration)
            self.latencyResults[configurationId] = result
        }
    }

    func testLatencies(for targets: [ProxyConfiguration]? = nil) {
        latencyTask?.cancel()
        let configs = targets ?? configurations
        for config in configs {
            latencyResults[config.id] = .testing
        }
        latencyTask = Task { [weak self] in
            guard let self else { return }
            await self.runLatencyTests(configs) { id, result in
                self.latencyResults[id] = result
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
        chainLatencyTask = Task { [weak self] in
            guard let self else { return }
            let result = await self.runLatencyTest(for: resolved)
            self.chainLatencyResults[chainId] = result
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
        let chainIdByConfigId: [UUID: UUID] = Dictionary(uniqueKeysWithValues: chainData.map { ($0.1.id, $0.0) })
        chainLatencyTask = Task { [weak self] in
            guard let self else { return }
            await self.runLatencyTests(chainData.map(\.1)) { configId, result in
                if let chainId = chainIdByConfigId[configId] {
                    self.chainLatencyResults[chainId] = result
                }
            }
        }
    }

    // MARK: - IPC-Backed Latency Tests

    /// Runs a single latency test in the network extension. Starts the tunnel
    /// if it isn't already up so the IPC message has a recipient.
    private func runLatencyTest(for configuration: ProxyConfiguration) async -> LatencyResult {
        guard await ensureTunnelRunningForTesting() else { return .failed }
        return await sendLatencyTestMessage(for: configuration)
    }

    /// Runs latency tests for a batch, capped at ``maxConcurrentLatencyTests``
    /// in-flight requests. Reports each result via `onResult` as it arrives.
    private func runLatencyTests(
        _ configurations: [ProxyConfiguration],
        onResult: @MainActor @escaping (UUID, LatencyResult) -> Void
    ) async {
        guard !configurations.isEmpty else { return }
        guard await ensureTunnelRunningForTesting() else {
            for config in configurations { onResult(config.id, .failed) }
            return
        }
        await withTaskGroup(of: (UUID, LatencyResult).self) { group in
            var iterator = configurations.makeIterator()
            for _ in 0..<min(Self.maxConcurrentLatencyTests, configurations.count) {
                if let config = iterator.next() {
                    group.addTask { [weak self] in
                        let r = await self?.sendLatencyTestMessage(for: config) ?? .failed
                        return (config.id, r)
                    }
                }
            }
            for await pair in group {
                onResult(pair.0, pair.1)
                if let config = iterator.next() {
                    group.addTask { [weak self] in
                        let r = await self?.sendLatencyTestMessage(for: config) ?? .failed
                        return (config.id, r)
                    }
                }
            }
        }
    }

    /// Sends one `testLatency` IPC message and awaits the extension's reply.
    /// Pre-resolves the proxy server address so the extension can dial via IP
    /// without any DNS-over-tunnel path.
    private func sendLatencyTestMessage(for configuration: ProxyConfiguration) async -> LatencyResult {
        guard let session = vpnManager?.connection as? NETunnelProviderSession else { return .failed }

        let resolved = await Self.resolved(configuration)
        guard let messageData = try? JSONEncoder().encode(TunnelMessage.testLatency(resolved)) else { return .failed }

        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(messageData) { responseData in
                    let result = (responseData.flatMap { try? JSONDecoder().decode(LatencyTestResponse.self, from: $0) })?.asLatencyResult ?? .failed
                    continuation.resume(returning: result)
                }
            } catch {
                logger.warning("Failed to send latency test request: \(error.localizedDescription)")
                continuation.resume(returning: .failed)
            }
        }
    }

    /// Returns a copy of `configuration` with `resolvedIP` set when missing.
    /// Runs DNS resolution off the main actor since `getaddrinfo` blocks.
    private static func resolved(_ configuration: ProxyConfiguration) async -> ProxyConfiguration {
        await Task.detached { Self.withResolvedIP(configuration) }.value
    }

    /// Returns `configuration` with `resolvedIP` set, preferring an existing
    /// value, then `fallback`, then a fresh `getaddrinfo` lookup.
    nonisolated static func withResolvedIP(
        _ configuration: ProxyConfiguration,
        fallback: String? = nil
    ) -> ProxyConfiguration {
        if configuration.resolvedIP != nil { return configuration }
        guard let resolved = fallback ?? resolveServerAddress(configuration.serverAddress) else {
            return configuration
        }
        return ProxyConfiguration(
            id: configuration.id,
            name: configuration.name,
            serverAddress: configuration.serverAddress,
            serverPort: configuration.serverPort,
            resolvedIP: resolved,
            subscriptionId: configuration.subscriptionId,
            outbound: configuration.outbound,
            chain: configuration.chain
        )
    }

    /// Per-test timeout for waiting on tunnel startup before the IPC roundtrip.
    private static let tunnelStartupTimeout: Duration = .seconds(15)

    /// Ensures the tunnel is `.connected` so it can receive IPC messages.
    /// Triggers a connect if currently disconnected and waits for the status
    /// transition. Returns false if startup times out or fails.
    private func ensureTunnelRunningForTesting() async -> Bool {
        // Wait for the manager to finish loading on first launch.
        if !isManagerReady {
            for await ready in $isManagerReady.values where ready { break }
        }
        if vpnStatus == .connected { return true }

        // Bootstrap a selection if there is none — otherwise connectVPN() noops.
        if selectedConfiguration == nil {
            selectedConfiguration = configurations.first
            guard selectedConfiguration != nil else { return false }
        }

        if vpnStatus != .connecting && vpnStatus != .reasserting {
            connectVPN()
        }

        return await waitForVPNStatus(.connected, timeout: Self.tunnelStartupTimeout)
    }

    private func waitForVPNStatus(_ target: NEVPNStatus, timeout: Duration) async -> Bool {
        if vpnStatus == target { return true }
        return await withTaskGroup(of: Bool.self) { group in
            group.addTask { @MainActor [weak self] in
                guard let self else { return false }
                // Wait for an active transition before treating .disconnected/.invalid
                // as a failure — `$vpnStatus.values` emits the current value first,
                // which is typically .disconnected when starting from cold.
                var sawTransition = false
                for await status in self.$vpnStatus.values {
                    if status == target { return true }
                    if status == .connecting || status == .reasserting { sawTransition = true }
                    if sawTransition && (status == .invalid || status == .disconnected) { return false }
                }
                return false
            }
            group.addTask {
                try? await Task.sleep(for: timeout)
                return false
            }
            let result = await group.next() ?? false
            group.cancelAll()
            return result
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

    private static let providerBundleIdentifier = "com.argsment.Anywhere.Network-Extension"

    private func setupVPNManager() {
        Task {
            let managers = try? await NETunnelProviderManager.loadAllFromPreferences()
            if let manager = managers?.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.providerBundleIdentifier
            }) ?? managers?.first {
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

            let alwaysOn = AWCore.getAlwaysOnEnabled()
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

                    let resolved = Self.withResolvedIP(configuration, fallback: resolvedIP)

                    // Persist configuration to App Group so the Network Extension
                    // can read it when started from Settings or Always On (On Demand),
                    // where options is nil.
                    if let configData = try? JSONEncoder().encode(resolved) {
                        AWCore.setLastConfigurationData(configData)
                    }

                    do {
                        let messageData = try JSONEncoder().encode(TunnelMessage.setConfiguration(resolved))
                        try manager.connection.startVPNTunnel(options: [TunnelMessage.optionKey: messageData as NSObject])
                    } catch {
                        Task { @MainActor in self.startError = error.localizedDescription }
                    }
                }
            }
        }
    }

    func disconnectVPN() {
        guard let manager = vpnManager else { return }
        // Clear any pending reconnect — an explicit disconnect should not auto-reconnect
        pendingReconnect = false
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

        // Resolve DNS and send off main actor.
        Task.detached {
            let resolved = Self.withResolvedIP(configuration)

            // Keep App Group in sync so On Demand restarts use the latest selection.
            if let configData = try? JSONEncoder().encode(resolved) {
                AWCore.setLastConfigurationData(configData)
            }

            guard let data = try? JSONEncoder().encode(TunnelMessage.setConfiguration(resolved)) else { return }
            do {
                try session.sendProviderMessage(data) { _ in }
            } catch {
                logger.warning("Failed to send configuration to tunnel: \(error.localizedDescription)")
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
        var resolvedAddresses: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(bare, nil, &hints, &resolvedAddresses) == 0, let head = resolvedAddresses else {
            return nil
        }
        defer { freeaddrinfo(head) }

        // Extract the first resolved IP as a string
        var current: UnsafeMutablePointer<addrinfo>? = head
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
        await ruleSetStore.syncToAppGroup(configurations: configurations, chains: chains, serializeConfiguration: VPNViewModel.serializeConfiguration)
    }

    /// Drops rule-set assignments whose target (proxy or chain) no longer exists,
    /// surfaces the affected names for UI, and re-syncs routing.
    private func clearOrphanedRuleSetAssignments(configIds: Set<String>, chainIds: Set<String>) {
        let affected = ruleSetStore.clearOrphanedAssignments(availableIds: configIds.union(chainIds))
        guard !affected.isEmpty else { return }
        orphanedRuleSetNames = affected
        Task { await syncRoutingConfigurationToNE() }
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
        case .hysteria(let password, let uploadMbps, let sni):
            configurationDict["hysteriaPassword"] = password
            configurationDict["hysteriaUploadMbps"] = uploadMbps
            configurationDict["hysteriaSNI"] = sni
        case .trojan(let password, let tls):
            configurationDict["trojanPassword"] = password
            configurationDict["trojanSNI"] = tls.serverName
            if let alpn = tls.alpn, !alpn.isEmpty {
                configurationDict["trojanALPN"] = alpn.joined(separator: ",")
            }
            configurationDict["trojanFingerprint"] = tls.fingerprint.rawValue
        case .shadowsocks(let password, let method):
            configurationDict["ssPassword"] = password
            configurationDict["ssMethod"] = method
        case .socks5(let username, let password):
            if let username { configurationDict["socks5Username"] = username }
            if let password { configurationDict["socks5Password"] = password }
        case .sudoku(let sudoku):
            configurationDict["sudokuKey"] = sudoku.key
            configurationDict["sudokuAEADMethod"] = sudoku.aeadMethod.rawValue
            configurationDict["sudokuPaddingMin"] = sudoku.paddingMin
            configurationDict["sudokuPaddingMax"] = sudoku.paddingMax
            configurationDict["sudokuASCIIMode"] = sudoku.asciiMode.rawValue
            configurationDict["sudokuCustomTables"] = sudoku.customTables
            configurationDict["sudokuEnablePureDownlink"] = sudoku.enablePureDownlink
            configurationDict["sudokuHTTPMaskDisable"] = sudoku.httpMask.disable
            configurationDict["sudokuHTTPMaskMode"] = sudoku.httpMask.mode.rawValue
            configurationDict["sudokuHTTPMaskTLS"] = sudoku.httpMask.tls
            configurationDict["sudokuHTTPMaskHost"] = sudoku.httpMask.host
            configurationDict["sudokuHTTPMaskPathRoot"] = sudoku.httpMask.pathRoot
            configurationDict["sudokuHTTPMaskMultiplex"] = sudoku.httpMask.multiplex.rawValue
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
        
        if configuration.outboundProtocol == .vless {
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

            if let hu = configuration.httpUpgrade {
                configurationDict["huHost"] = hu.host
                configurationDict["huPath"] = hu.path
                if !hu.headers.isEmpty {
                    configurationDict["huHeaders"] = hu.headers.map { "\($0.key):\($0.value)" }.joined(separator: ",")
                }
            }
            
            if let grpc = configuration.grpc {
                configurationDict["grpcServiceName"] = grpc.serviceName
                configurationDict["grpcAuthority"] = grpc.authority
                configurationDict["grpcMultiMode"] = grpc.multiMode
                configurationDict["grpcUserAgent"] = grpc.userAgent
                configurationDict["grpcInitialWindowsSize"] = grpc.initialWindowsSize
                configurationDict["grpcIdleTimeout"] = grpc.idleTimeout
                configurationDict["grpcHealthCheckTimeout"] = grpc.healthCheckTimeout
                configurationDict["grpcPermitWithoutStream"] = grpc.permitWithoutStream
            }

            if let xhttp = configuration.xhttp {
                configurationDict["xhttpHost"] = xhttp.host
                configurationDict["xhttpPath"] = xhttp.path
                configurationDict["xhttpMode"] = xhttp.mode.rawValue
                if !xhttp.headers.isEmpty {
                    configurationDict["xhttpHeaders"] = xhttp.headers.map { "\($0.key):\($0.value)" }.joined(separator: ",")
                }
                configurationDict["xhttpNoGRPCHeader"] = xhttp.noGRPCHeader
            }
        }

        // Add proxy chain if present
        if let chain = configuration.chain, !chain.isEmpty {
            configurationDict["chain"] = chain.map { Self.serializeConfiguration($0) }
        }

        return configurationDict
    }
}

extension NEVPNStatus {
    /// True while the VPN is moving between `.connected` and `.disconnected` —
    /// `.connecting`, `.disconnecting`, or `.reasserting`. Callers use this to
    /// gate UI affordances (disable the power button, show the spinner) during
    /// states the user shouldn't be allowed to re-enter.
    var isTransitioning: Bool {
        self == .connecting || self == .disconnecting || self == .reasserting
    }
}
