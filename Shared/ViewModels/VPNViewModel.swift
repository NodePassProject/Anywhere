//
//  VPNViewModel.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import NetworkExtension
import SwiftUI
import Observation

nonisolated private let logger = AnywhereLogger(category: "VPNViewModel")

@MainActor
@Observable
class VPNViewModel {
    static let shared = VPNViewModel()

    var vpnStatus: NEVPNStatus = .disconnected
    var selectedConfiguration: ProxyConfiguration? {
        didSet {
            if !_suppressSelectionPersistence {
                selectedChainId = nil
                AWCore.setSelectedChainId(nil)
                AWCore.setSelectedConfigurationId(selectedConfiguration?.id)
                RoutingRuleSetStore.shared.scheduleSyncToAppGroup()
            }
            if vpnStatus == .connected, let selectedConfiguration {
                sendConfigurationToTunnel(selectedConfiguration)
            }
        }
    }
    private(set) var selectedChainId: UUID?
    var latencyResults: [UUID: LatencyResult] = [:]
    var chainLatencyResults: [UUID: LatencyResult] = [:]
    var startError: String?

    private(set) var isManagerReady = false
    @ObservationIgnored private var vpnManager: NETunnelProviderManager?
    @ObservationIgnored private var statusObserver: Task<Void, Never>?
    private(set) var pendingReconnect = false
    @ObservationIgnored private var reassertingDebounceTask: Task<Void, Never>?
    private static let reassertingDebounceInterval: Duration = .seconds(5)
    @ObservationIgnored private var _suppressSelectionPersistence = false
    
    private func withoutSelectionPersistence(_ block: () -> Void) {
        _suppressSelectionPersistence = true
        defer { _suppressSelectionPersistence = false }
        block()
    }

    init() {
        restoreLatencyResults()
        setupStatusObserver()
        setupVPNManager()
    }

    // MARK: - Selection

    private func restoreSelection(configurations: [ProxyConfiguration], chains: [ProxyChain]) {
        guard selectedConfiguration == nil, selectedChainId == nil else { return }
        if let savedChainId = AWCore.getSelectedChainId(),
           let chain = chains.first(where: { $0.id == savedChainId }),
           let resolved = chain.resolveComposite(from: configurations) {
            selectedChainId = savedChainId
            withoutSelectionPersistence { selectedConfiguration = resolved }
        } else if let savedConfigurationId = AWCore.getSelectedConfigurationId(),
                  let configuration = configurations.first(where: { $0.id == savedConfigurationId }) {
            withoutSelectionPersistence { selectedConfiguration = configuration }
        } else {
            selectedConfiguration = configurations.first
        }
    }

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
    
    var status: VPNStatus {
        VPNStatus(vpnStatus)
    }

    var statusText: String {
        status.localizedText
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
        RoutingRuleSetStore.shared.scheduleSyncToAppGroup()
        withoutSelectionPersistence { selectedConfiguration = resolved }
    }

    // MARK: - Latency Testing

    @ObservationIgnored private var batchLatencyTask: Task<Void, Never>?
    @ObservationIgnored private var batchLatencyTargetIds: Set<UUID> = []
    @ObservationIgnored private var singleLatencyTasks: [UUID: Task<Void, Never>] = [:]

    nonisolated private static let maxConcurrentLatencyTests = 8

    func testLatency(for configuration: ProxyConfiguration) {
        let configurationId = configuration.id
        singleLatencyTasks[configurationId]?.cancel()
        latencyResults[configurationId] = .testing
        let useIPC = vpnStatus == .connected
        singleLatencyTasks[configurationId] = Task { [weak self] in
            let result = await Self.runSingleLatencyTest(for: configuration, viaIPC: useIPC, session: useIPC ? self?.providerSession : nil)
            await MainActor.run {
                guard !Task.isCancelled else { return }
                self?.singleLatencyTasks[configurationId] = nil
                self?.recordLatencyResult(result, for: configurationId)
            }
        }
    }

    func testLatencies(for targets: [ProxyConfiguration]) {
        batchLatencyTask?.cancel()
        let targetIds = Set(targets.map(\.id))
        restoreDisplacedResults(in: \.latencyResults, stored: storedLatencyResults, previousTargets: batchLatencyTargetIds, newTargets: targetIds)
        batchLatencyTargetIds = targetIds
        for config in targets {
            latencyResults[config.id] = .testing
        }
        let useIPC = vpnStatus == .connected
        let session = useIPC ? providerSession : nil
        batchLatencyTask = Task { [weak self] in
            await Self.runLatencyTests(targets, viaIPC: useIPC, session: session, isStillWanted: { id in
                ConfigurationStore.shared.configurations.contains { $0.id == id }
            }) { id, result in
                await MainActor.run {
                    guard !Task.isCancelled else { return }
                    self?.recordLatencyResult(result, for: id)
                }
            }
        }
    }
    
    private func restoreDisplacedResults(
        in results: ReferenceWritableKeyPath<VPNViewModel, [UUID: LatencyResult]>,
        stored: [UUID: LatencyResult],
        previousTargets: Set<UUID>,
        newTargets: Set<UUID>
    ) {
        for staleId in previousTargets where !newTargets.contains(staleId) {
            if self[keyPath: results][staleId] == .testing {
                self[keyPath: results][staleId] = stored[staleId]
            }
        }
    }

    // MARK: - Chain Latency Testing

    @ObservationIgnored private var batchChainLatencyTask: Task<Void, Never>?
    @ObservationIgnored private var batchChainLatencyTargetIds: Set<UUID> = []
    @ObservationIgnored private var singleChainLatencyTasks: [UUID: Task<Void, Never>] = [:]

    func testChainLatency(for chain: ProxyChain, configurations: [ProxyConfiguration]) {
        guard let resolved = chain.resolveComposite(from: configurations) else { return }
        let chainId = chain.id
        singleChainLatencyTasks[chainId]?.cancel()
        chainLatencyResults[chainId] = .testing
        let useIPC = vpnStatus == .connected
        let session = useIPC ? providerSession : nil
        singleChainLatencyTasks[chainId] = Task { [weak self] in
            let result = await Self.runSingleLatencyTest(for: resolved, viaIPC: useIPC, session: session)
            await MainActor.run {
                guard !Task.isCancelled else { return }
                self?.singleChainLatencyTasks[chainId] = nil
                self?.recordChainLatencyResult(result, for: chainId)
            }
        }
    }

    func testAllChainLatencies(chains: [ProxyChain], configurations: [ProxyConfiguration]) {
        batchChainLatencyTask?.cancel()
        var chainData: [(UUID, ProxyConfiguration)] = []
        for chain in chains {
            if let resolved = chain.resolveComposite(from: configurations) {
                chainData.append((chain.id, resolved))
            }
        }
        let targetIds = Set(chainData.map(\.0))
        restoreDisplacedResults(in: \.chainLatencyResults, stored: storedChainLatencyResults, previousTargets: batchChainLatencyTargetIds, newTargets: targetIds)
        batchChainLatencyTargetIds = targetIds
        for (chainId, _) in chainData {
            chainLatencyResults[chainId] = .testing
        }
        let chainIdByConfigId: [UUID: UUID] = Dictionary(uniqueKeysWithValues: chainData.map { ($0.1.id, $0.0) })
        let useIPC = vpnStatus == .connected
        let session = useIPC ? providerSession : nil
        batchChainLatencyTask = Task { [weak self] in
            await Self.runLatencyTests(chainData.map(\.1), viaIPC: useIPC, session: session, isStillWanted: { compositeId in
                guard let chainId = chainIdByConfigId[compositeId],
                      let chain = ChainStore.shared.chains.first(where: { $0.id == chainId }) else { return false }
                return chain.resolveComposite(from: ConfigurationStore.shared.configurations) != nil
            }) { configId, result in
                if let chainId = chainIdByConfigId[configId] {
                    await MainActor.run {
                        guard !Task.isCancelled else { return }
                        self?.recordChainLatencyResult(result, for: chainId)
                    }
                }
            }
        }
    }

    // MARK: - Latency Persistence
    
    @ObservationIgnored private var storedLatencyResults: [UUID: LatencyResult] = [:]
    @ObservationIgnored private var storedChainLatencyResults: [UUID: LatencyResult] = [:]

    private func restoreLatencyResults() {
        storedLatencyResults = Self.decodeLatencyResults(AWCore.getLatencyResultsData())
        storedChainLatencyResults = Self.decodeLatencyResults(AWCore.getChainLatencyResultsData())
        latencyResults = storedLatencyResults
        chainLatencyResults = storedChainLatencyResults
    }

    private func recordLatencyResult(_ result: LatencyResult, for configurationId: UUID) {
        guard ConfigurationStore.shared.configurations.contains(where: { $0.id == configurationId }) else { return }
        latencyResults[configurationId] = result
        storedLatencyResults[configurationId] = result
        if let data = Self.encodeLatencyResults(storedLatencyResults) {
            AWCore.setLatencyResultsData(data)
        }
    }

    private func recordChainLatencyResult(_ result: LatencyResult, for chainId: UUID) {
        guard ChainStore.shared.chains.contains(where: { $0.id == chainId }) else { return }
        chainLatencyResults[chainId] = result
        storedChainLatencyResults[chainId] = result
        if let data = Self.encodeLatencyResults(storedChainLatencyResults) {
            AWCore.setChainLatencyResultsData(data)
        }
    }
    
    func pruneLatencyState(liveConfigurationIds: Set<UUID>) {
        for (id, task) in singleLatencyTasks where !liveConfigurationIds.contains(id) {
            task.cancel()
            singleLatencyTasks[id] = nil
        }
        let staleLive = latencyResults.keys.filter { !liveConfigurationIds.contains($0) }
        for id in staleLive { latencyResults[id] = nil }
        let staleStored = storedLatencyResults.keys.filter { !liveConfigurationIds.contains($0) }
        if !staleStored.isEmpty {
            for id in staleStored { storedLatencyResults[id] = nil }
            if let data = Self.encodeLatencyResults(storedLatencyResults) {
                AWCore.setLatencyResultsData(data)
            }
        }
    }
    
    func pruneChainLatencyState(liveChainIds: Set<UUID>) {
        for (id, task) in singleChainLatencyTasks where !liveChainIds.contains(id) {
            task.cancel()
            singleChainLatencyTasks[id] = nil
        }
        let staleLive = chainLatencyResults.keys.filter { !liveChainIds.contains($0) }
        for id in staleLive { chainLatencyResults[id] = nil }
        let staleStored = storedChainLatencyResults.keys.filter { !liveChainIds.contains($0) }
        if !staleStored.isEmpty {
            for id in staleStored { storedChainLatencyResults[id] = nil }
            if let data = Self.encodeLatencyResults(storedChainLatencyResults) {
                AWCore.setChainLatencyResultsData(data)
            }
        }
    }
    
    private static func encodeLatencyResults(_ results: [UUID: LatencyResult]) -> Data? {
        try? JSONEncoder().encode(results.mapValues { LatencyTestResponse($0) })
    }

    private static func decodeLatencyResults(_ data: Data?) -> [UUID: LatencyResult] {
        guard let data,
              let responses = try? JSONDecoder().decode([UUID: LatencyTestResponse].self, from: data) else {
            return [:]
        }
        return responses.mapValues { $0.asLatencyResult }
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
    
    nonisolated private static func runLatencyTests(
        _ configurations: [ProxyConfiguration],
        viaIPC: Bool,
        session: NETunnelProviderSession?,
        isStillWanted: (@MainActor @Sendable (UUID) -> Bool)? = nil,
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
                while let config = iterator.next() {
                    if let isStillWanted, await !isStillWanted(config.id) { continue }
                    group.addTask {
                        let r = await runSingleLatencyTest(for: config, viaIPC: viaIPC, session: session)
                        return (config.id, r)
                    }
                    break
                }
            }
        }
    }
    
    nonisolated private static func sendLatencyTestMessage(
        for configuration: ProxyConfiguration,
        session: NETunnelProviderSession
    ) async -> LatencyResult {
        guard let messageData = try? JSONEncoder().encode(TunnelMessage.testLatency(configuration)) else { return .failed }

        let responseData = await ProviderMessageConcurrencyBridge.send(messageData, over: session)
        return (responseData.flatMap { try? JSONDecoder().decode(LatencyTestResponse.self, from: $0) })?.asLatencyResult ?? .failed
    }
    
    nonisolated static func withResolvedIP(
        _ configuration: ProxyConfiguration,
        fallback: String? = nil
    ) async -> ProxyConfiguration {
        if configuration.resolvedIP != nil { return configuration }
        let resolvedIP: String?
        if let fallback {
            resolvedIP = fallback
        } else {
            resolvedIP = await resolveServerAddress(configuration.serverAddress)
        }
        guard let resolved = resolvedIP else {
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
        statusObserver = Task { [weak self] in
            for await note in NotificationCenter.default.notifications(named: .NEVPNStatusDidChange) {
                guard !Task.isCancelled, let self else { return }
                guard let connection = note.object as? NEVPNConnection,
                      connection === self.vpnManager?.connection else { continue }
                self.handleStatusChange(connection.status, on: connection)
            }
        }
    }
    
    private func handleStatusChange(_ status: NEVPNStatus, on connection: NEVPNConnection) {
        reassertingDebounceTask?.cancel()
        reassertingDebounceTask = nil

        if status == .reasserting, vpnStatus == .connected {
            reassertingDebounceTask = Task { [weak self] in
                try? await Task.sleep(for: Self.reassertingDebounceInterval)
                guard !Task.isCancelled, let self else { return }
                // Re-check the live status: apply only if it never recovered.
                guard connection.status == .reasserting else { return }
                self.applyStatus(.reasserting, on: connection)
            }
            return
        }

        applyStatus(status, on: connection)
    }
    
    private func applyStatus(_ status: NEVPNStatus, on connection: NEVPNConnection) {
        vpnStatus = status
        let stats = ConnectionStatsModel.shared
        if status == .connected {
            if let session = connection as? NETunnelProviderSession {
                stats.startPolling(session: session)
            }
        } else {
            stats.stopPolling()
            if status == .disconnected || status == .invalid {
                stats.reset()
                if pendingReconnect {
                    pendingReconnect = false
                    connectVPN()
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

        Task { [self] in
            let resolvedIP = await VPNViewModel.resolveServerAddress(configuration.serverAddress)

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

            do {
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()

                let resolved = await Self.withResolvedIP(configuration, fallback: resolvedIP)
                
                if let configData = try? JSONEncoder().encode(resolved) {
                    AWCore.setLastConfigurationData(configData)
                }

                let messageData = try JSONEncoder().encode(TunnelMessage.setConfiguration(resolved))
                try manager.connection.startVPNTunnel(options: [TunnelMessage.optionKey: messageData as NSObject])
            } catch {
                self.startError = error.localizedDescription
            }
        }
    }

    func disconnectVPN() {
        guard let manager = vpnManager else { return }
        pendingReconnect = false
        if manager.isOnDemandEnabled {
            manager.isOnDemandEnabled = false
            Task {
                try? await manager.saveToPreferences()
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
        if manager.isOnDemandEnabled {
            manager.isOnDemandEnabled = false
            Task {
                try? await manager.saveToPreferences()
                manager.connection.stopVPNTunnel()
            }
        } else {
            manager.connection.stopVPNTunnel()
        }
    }

    // MARK: - Configuration Switching

    private func sendConfigurationToTunnel(_ configuration: ProxyConfiguration) {
        guard let session = vpnManager?.connection as? NETunnelProviderSession else { return }

        Task.detached {
            let resolved = await Self.withResolvedIP(configuration)

            // Keep App Group in sync so On Demand restarts use the latest selection.
            if let configData = try? JSONEncoder().encode(resolved) {
                AWCore.setLastConfigurationData(configData)
            }

            guard let data = try? JSONEncoder().encode(TunnelMessage.setConfiguration(resolved)) else { return }
            _ = await ProviderMessageConcurrencyBridge.send(data, over: session)
        }
    }

    // MARK: - DNS Resolution
    
    nonisolated static func resolveServerAddress(_ address: String) async -> String? {
        await DNSResolver.shared.resolveHost(address)
    }

}

extension NEVPNStatus {
    var isTransitioning: Bool {
        self == .connecting || self == .disconnecting || self == .reasserting
    }
}

extension VPNStatus {
    init(_ status: NEVPNStatus) {
        switch status {
        case .invalid: self = .invalid
        case .disconnected: self = .disconnected
        case .connecting: self = .connecting
        case .connected: self = .connected
        case .reasserting: self = .reasserting
        case .disconnecting: self = .disconnecting
        @unknown default: self = .invalid
        }
    }
}
