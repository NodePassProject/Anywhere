//
//  VPNViewModel.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import NetworkExtension
import Combine
import SwiftUI
import Observation

private let logger = AnywhereLogger(category: "VPNViewModel")

@MainActor
@Observable
class VPNViewModel {
    static let shared = VPNViewModel()

    var vpnStatus: NEVPNStatus = .disconnected
    var selectedConfiguration: ProxyConfiguration? {
        didSet {
            if !_suppressSelectionPersistence {
                // Direct proxy selection — clear any chain selection
                selectedChainId = nil
                AWCore.setSelectedChainId(nil)
                AWCore.setSelectedConfigurationId(selectedConfiguration?.id)
                // Tell NE to re-filter routing rules against the new default.
                AWCore.notifyRoutingChanged()
            }
            if vpnStatus == .connected, let selectedConfiguration {
                sendConfigurationToTunnel(selectedConfiguration)
            }
        }
    }
    /// Non-nil when a chain is the active selection.
    private(set) var selectedChainId: UUID?
    var latencyResults: [UUID: LatencyResult] = [:]
    var chainLatencyResults: [UUID: LatencyResult] = [:]
    var startError: String?

    private(set) var isManagerReady = false
    @ObservationIgnored private var vpnManager: NETunnelProviderManager?
    @ObservationIgnored private var statusObserver: AnyCancellable?
    private(set) var pendingReconnect = false
    /// Set only via `withoutSelectionPersistence` so the flag always resets.
    @ObservationIgnored private var _suppressSelectionPersistence = false

    /// Assigns to `selectedConfiguration` without triggering the chain-clearing branch of its didSet.
    private func withoutSelectionPersistence(_ block: () -> Void) {
        _suppressSelectionPersistence = true
        defer { _suppressSelectionPersistence = false }
        block()
    }

    init() {
        setupStatusObserver()
        setupVPNManager()
    }

    // MARK: - Selection

    /// Restores the persisted selection (chain takes priority) against the current data.
    private func restoreSelection(configurations: [ProxyConfiguration], chains: [ProxyChain]) {
        guard selectedConfiguration == nil, selectedChainId == nil else { return }
        if let savedChainId = AWCore.getSelectedChainId(),
           let chain = chains.first(where: { $0.id == savedChainId }),
           let resolved = chain.resolveComposite(from: configurations) {
            selectedChainId = savedChainId
            withoutSelectionPersistence { selectedConfiguration = resolved }
        } else if let savedConfigurationId = AWCore.getSelectedConfigurationId(),
                  let configuration = configurations.first(where: { $0.id == savedConfigurationId }) {
            selectedConfiguration = configuration
        } else {
            selectedConfiguration = configurations.first
        }
    }

    /// Re-validates the active selection against current data: restores the persisted
    /// selection at launch, re-resolves a selected chain, or refreshes/falls back the selected proxy.
    func revalidateSelection(configurations: [ProxyConfiguration], chains: [ProxyChain]) {
        if selectedConfiguration == nil, selectedChainId == nil {
            restoreSelection(configurations: configurations, chains: chains)
            return
        }
        if let chainId = selectedChainId {
            if let chain = chains.first(where: { $0.id == chainId }),
               let resolved = chain.resolveComposite(from: configurations) {
                withoutSelectionPersistence { selectedConfiguration = resolved }
            } else {
                // Chain (or its proxies) gone — fall back to the first proxy.
                selectedChainId = nil
                AWCore.setSelectedChainId(nil)
                selectedConfiguration = configurations.first
            }
        } else {
            if let selected = selectedConfiguration {
                if let refreshed = configurations.first(where: { $0.id == selected.id }) {
                    if refreshed != selected { selectedConfiguration = refreshed }
                } else {
                    selectedConfiguration = configurations.first
                }
            }
            if selectedConfiguration == nil {
                selectedConfiguration = configurations.first
            }
        }
    }

    func selectIfNone(_ configuration: ProxyConfiguration) {
        if selectedConfiguration == nil { selectedConfiguration = configuration }
    }

    // MARK: - Computed Properties

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

    func isButtonDisabled(hasConfigurations: Bool) -> Bool {
        !isManagerReady || !hasConfigurations || vpnStatus.isTransitioning
    }

    // MARK: - Chain Selection

    func selectChain(_ chain: ProxyChain, configurations: [ProxyConfiguration]) {
        guard let resolved = chain.resolveComposite(from: configurations) else { return }
        selectedChainId = chain.id
        AWCore.setSelectedChainId(chain.id)
        AWCore.setSelectedConfigurationId(nil)
        withoutSelectionPersistence { selectedConfiguration = resolved }
        // Tell NE to re-filter routing rules against the new default.
        AWCore.notifyRoutingChanged()
    }

    // MARK: - Latency Testing

    @ObservationIgnored private var latencyTask: Task<Void, Never>?

    private static let maxConcurrentLatencyTests = 4

    func testLatency(for configuration: ProxyConfiguration) {
        latencyTask?.cancel()
        let configurationId = configuration.id
        latencyResults[configurationId] = .testing
        let useIPC = vpnStatus == .connected
        latencyTask = Task { [weak self] in
            let result = await Self.runSingleLatencyTest(for: configuration, viaIPC: useIPC, session: useIPC ? self?.providerSession : nil)
            await MainActor.run { self?.latencyResults[configurationId] = result }
        }
    }

    func testLatencies(for targets: [ProxyConfiguration]) {
        latencyTask?.cancel()
        for config in targets {
            latencyResults[config.id] = .testing
        }
        let useIPC = vpnStatus == .connected
        let session = useIPC ? providerSession : nil
        latencyTask = Task { [weak self] in
            await Self.runLatencyTests(targets, viaIPC: useIPC, session: session) { id, result in
                await MainActor.run { self?.latencyResults[id] = result }
            }
        }
    }

    // MARK: - Chain Latency Testing

    @ObservationIgnored private var chainLatencyTask: Task<Void, Never>?

    func testChainLatency(for chain: ProxyChain, configurations: [ProxyConfiguration]) {
        guard let resolved = chain.resolveComposite(from: configurations) else { return }
        chainLatencyResults[chain.id] = .testing
        let chainId = chain.id
        let useIPC = vpnStatus == .connected
        let session = useIPC ? providerSession : nil
        chainLatencyTask?.cancel()
        chainLatencyTask = Task { [weak self] in
            let result = await Self.runSingleLatencyTest(for: resolved, viaIPC: useIPC, session: session)
            await MainActor.run { self?.chainLatencyResults[chainId] = result }
        }
    }

    func testAllChainLatencies(chains: [ProxyChain], configurations: [ProxyConfiguration]) {
        chainLatencyTask?.cancel()
        var chainData: [(UUID, ProxyConfiguration)] = []
        for chain in chains {
            if let resolved = chain.resolveComposite(from: configurations) {
                chainLatencyResults[chain.id] = .testing
                chainData.append((chain.id, resolved))
            }
        }
        let chainIdByConfigId: [UUID: UUID] = Dictionary(uniqueKeysWithValues: chainData.map { ($0.1.id, $0.0) })
        let useIPC = vpnStatus == .connected
        let session = useIPC ? providerSession : nil
        chainLatencyTask = Task { [weak self] in
            await Self.runLatencyTests(chainData.map(\.1), viaIPC: useIPC, session: session) { configId, result in
                if let chainId = chainIdByConfigId[configId] {
                    await MainActor.run { self?.chainLatencyResults[chainId] = result }
                }
            }
        }
    }

    // MARK: - Latency Test Execution

    private var providerSession: NETunnelProviderSession? {
        vpnManager?.connection as? NETunnelProviderSession
    }

    nonisolated private static func runSingleLatencyTest(
        for configuration: ProxyConfiguration,
        viaIPC: Bool,
        session: NETunnelProviderSession?
    ) async -> LatencyResult {
        if viaIPC, let session {
            return await sendLatencyTestMessage(for: configuration, session: session)
        }
        return await LatencyTester.test(configuration)
    }

    /// Runs a batch of tests with at most `maxConcurrentLatencyTests` in flight, reporting each result as it arrives.
    nonisolated private static func runLatencyTests(
        _ configurations: [ProxyConfiguration],
        viaIPC: Bool,
        session: NETunnelProviderSession?,
        onResult: @Sendable @escaping (UUID, LatencyResult) async -> Void
    ) async {
        guard !configurations.isEmpty else { return }
        await withTaskGroup(of: (UUID, LatencyResult).self) { group in
            var iterator = configurations.makeIterator()
            for _ in 0..<min(Self.maxConcurrentLatencyTests, configurations.count) {
                if let config = iterator.next() {
                    group.addTask {
                        let r = await runSingleLatencyTest(for: config, viaIPC: viaIPC, session: session)
                        return (config.id, r)
                    }
                }
            }
            for await pair in group {
                await onResult(pair.0, pair.1)
                if let config = iterator.next() {
                    group.addTask {
                        let r = await runSingleLatencyTest(for: config, viaIPC: viaIPC, session: session)
                        return (config.id, r)
                    }
                }
            }
        }
    }

    /// Sends one `testLatency` IPC message and awaits the extension's reply. The extension
    /// resolves the address itself — main-app DNS while the tunnel is up yields lwIP fake IPs.
    nonisolated private static func sendLatencyTestMessage(
        for configuration: ProxyConfiguration,
        session: NETunnelProviderSession
    ) async -> LatencyResult {
        guard let messageData = try? JSONEncoder().encode(TunnelMessage.testLatency(configuration)) else { return .failed }

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

    /// Returns `configuration` with `resolvedIP` set, preferring an existing value, then `fallback`, then a DNS lookup.
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

    // MARK: - Setup

    private func setupStatusObserver() {
        statusObserver = NotificationCenter.default
            .publisher(for: .NEVPNStatusDidChange)
            .compactMap { $0.object as? NEVPNConnection }
            .receive(on: DispatchQueue.main)
            .sink { [weak self] connection in
                guard let self else { return }
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
            // Pre-resolve the main proxy address off main actor.
            let resolvedIP = await Task.detached {
                VPNViewModel.resolveServerAddress(configuration.serverAddress)
            }.value

            let tunnelProtocol = NETunnelProviderProtocol()
            tunnelProtocol.providerBundleIdentifier = "com.argsment.Anywhere.Network-Extension"
            tunnelProtocol.serverAddress = "Anywhere"
            #if !os(tvOS)
            tunnelProtocol.includeAllNetworks = AWCore.getTunnelIncludeAllNetworks()
            tunnelProtocol.excludeLocalNetworks = !AWCore.getTunnelIncludeLocalNetworks()
            tunnelProtocol.excludeAPNs = !AWCore.getTunnelIncludeAPNs()
            tunnelProtocol.excludeCellularServices = !AWCore.getTunnelIncludeCellularServices()
            #endif

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

                    // Persist to App Group so the NE can read it when started from Settings or On Demand, where options is nil.
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

    /// Resolves a server address to an IP string (IP literals pass through) via the
    /// shared `DNSResolver`, so proxy lookups share the transport layers' cache.
    nonisolated static func resolveServerAddress(_ address: String) -> String? {
        DNSResolver.shared.resolveHost(address)
    }

}

extension NEVPNStatus {
    var isTransitioning: Bool {
        self == .connecting || self == .disconnecting || self == .reasserting
    }
}
