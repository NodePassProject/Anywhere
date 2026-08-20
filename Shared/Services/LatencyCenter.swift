//
//  LatencyCenter.swift
//  Anywhere
//
//  Created by NodePassProject on 8/3/26.
//

import Foundation
import NetworkExtension
import Observation

@MainActor
protocol LatencyTransport: AnyObject, Sendable {
    var isTunnelActive: Bool { get }
    func sendRaw(_ data: Data) async -> Data?
}

@MainActor
@Observable
final class LatencyCenter {
    var latencyResults: [UUID: LatencyResult] = [:]
    var chainLatencyResults: [UUID: LatencyResult] = [:]

    nonisolated private static let maxConcurrentLatencyTests = 8

    init() {
        restoreResults()
    }

    // MARK: - Configuration Tests

    @ObservationIgnored private var batchLatencyTask: Task<Void, Never>?
    @ObservationIgnored private var batchLatencyTargetIds: Set<UUID> = []
    @ObservationIgnored private var singleLatencyTasks: [UUID: Task<Void, Never>] = [:]

    func testLatency(
        for configuration: ProxyConfiguration,
        transport: LatencyTransport?,
        isLive: @escaping @MainActor @Sendable (UUID) -> Bool = { _ in true }
    ) {
        let configurationId = configuration.id
        singleLatencyTasks[configurationId]?.cancel()
        latencyResults[configurationId] = .testing
        let send = Self.tunnelSend(transport)
        singleLatencyTasks[configurationId] = Task { [weak self] in
            let result = await Self.runSingleLatencyTest(for: configuration, send: send)
            await MainActor.run {
                guard !Task.isCancelled else { return }
                self?.singleLatencyTasks[configurationId] = nil
                self?.recordLatencyResult(result, for: configurationId, isLive: isLive)
            }
        }
    }

    func testLatencies(
        for targets: [ProxyConfiguration],
        transport: LatencyTransport?,
        isLive: @escaping @MainActor @Sendable (UUID) -> Bool = { _ in true }
    ) {
        batchLatencyTask?.cancel()
        let targetIds = Set(targets.map(\.id))
        restoreDisplacedResults(in: \.latencyResults, stored: storedLatencyResults, previousTargets: batchLatencyTargetIds, newTargets: targetIds)
        batchLatencyTargetIds = targetIds
        for config in targets {
            latencyResults[config.id] = .testing
        }
        let send = Self.tunnelSend(transport)
        batchLatencyTask = Task { [weak self] in
            await Self.runLatencyTests(targets, send: send, isStillWanted: isLive) { id, result in
                await MainActor.run {
                    guard !Task.isCancelled else { return }
                    self?.recordLatencyResult(result, for: id, isLive: isLive)
                }
            }
        }
    }

    private func restoreDisplacedResults(
        in results: ReferenceWritableKeyPath<LatencyCenter, [UUID: LatencyResult]>,
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

    // MARK: - Chain Tests

    @ObservationIgnored private var batchChainLatencyTask: Task<Void, Never>?
    @ObservationIgnored private var batchChainLatencyTargetIds: Set<UUID> = []
    @ObservationIgnored private var singleChainLatencyTasks: [UUID: Task<Void, Never>] = [:]

    func testChainLatency(
        for chain: ProxyChain,
        configurations: [ProxyConfiguration],
        transport: LatencyTransport?,
        isLiveChain: @escaping @MainActor @Sendable (UUID) -> Bool = { _ in true }
    ) {
        guard let resolved = chain.resolveComposite(from: configurations) else { return }
        let chainId = chain.id
        singleChainLatencyTasks[chainId]?.cancel()
        chainLatencyResults[chainId] = .testing
        let send = Self.tunnelSend(transport)
        singleChainLatencyTasks[chainId] = Task { [weak self] in
            let result = await Self.runSingleLatencyTest(for: resolved, send: send)
            await MainActor.run {
                guard !Task.isCancelled else { return }
                self?.singleChainLatencyTasks[chainId] = nil
                self?.recordChainLatencyResult(result, for: chainId, isLive: isLiveChain)
            }
        }
    }

    func testAllChainLatencies(
        chains: [ProxyChain],
        configurations: [ProxyConfiguration],
        transport: LatencyTransport?,
        isLiveChain: @escaping @MainActor @Sendable (UUID) -> Bool = { _ in true },
        isResolvableChain: @escaping @MainActor @Sendable (UUID) -> Bool = { _ in true }
    ) {
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
        let send = Self.tunnelSend(transport)
        batchChainLatencyTask = Task { [weak self] in
            await Self.runLatencyTests(chainData.map(\.1), send: send, isStillWanted: { compositeId in
                guard let chainId = chainIdByConfigId[compositeId] else { return false }
                return isResolvableChain(chainId)
            }) { configId, result in
                if let chainId = chainIdByConfigId[configId] {
                    await MainActor.run {
                        guard !Task.isCancelled else { return }
                        self?.recordChainLatencyResult(result, for: chainId, isLive: isLiveChain)
                    }
                }
            }
        }
    }

    // MARK: - Persistence

    @ObservationIgnored private var storedLatencyResults: [UUID: LatencyResult] = [:]
    @ObservationIgnored private var storedChainLatencyResults: [UUID: LatencyResult] = [:]

    private func restoreResults() {
        storedLatencyResults = Self.decodeLatencyResults(AWCore.getLatencyResultsData())
        storedChainLatencyResults = Self.decodeLatencyResults(AWCore.getChainLatencyResultsData())
        latencyResults = storedLatencyResults
        chainLatencyResults = storedChainLatencyResults
    }

    private func recordLatencyResult(
        _ result: LatencyResult,
        for configurationId: UUID,
        isLive: @MainActor (UUID) -> Bool
    ) {
        guard isLive(configurationId) else { return }
        latencyResults[configurationId] = result
        storedLatencyResults[configurationId] = result
        if let data = Self.encodeLatencyResults(storedLatencyResults) {
            AWCore.setLatencyResultsData(data)
        }
    }

    private func recordChainLatencyResult(
        _ result: LatencyResult,
        for chainId: UUID,
        isLive: @MainActor (UUID) -> Bool
    ) {
        guard isLive(chainId) else { return }
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

    // MARK: - Execution

    private static func tunnelSend(_ transport: LatencyTransport?) -> (@Sendable (Data) async -> Data?)? {
        guard let transport, transport.isTunnelActive else { return nil }
        return { [weak transport] data in await transport?.sendRaw(data) }
    }

    nonisolated private static func runSingleLatencyTest(
        for configuration: ProxyConfiguration,
        send: (@Sendable (Data) async -> Data?)?
    ) async -> LatencyResult {
        if let send {
            return await sendLatencyTestMessage(for: configuration, send: send)
        }
        return await LatencyTester.test(configuration)
    }

    nonisolated private static func runLatencyTests(
        _ configurations: [ProxyConfiguration],
        send: (@Sendable (Data) async -> Data?)?,
        isStillWanted: (@MainActor @Sendable (UUID) -> Bool)? = nil,
        onResult: @Sendable @escaping (UUID, LatencyResult) async -> Void
    ) async {
        guard !configurations.isEmpty else { return }
        await withTaskGroup(of: (UUID, LatencyResult).self) { group in
            var iterator = configurations.makeIterator()
            for _ in 0..<min(Self.maxConcurrentLatencyTests, configurations.count) {
                if let config = iterator.next() {
                    group.addTask {
                        let r = await runSingleLatencyTest(for: config, send: send)
                        return (config.id, r)
                    }
                }
            }
            for await pair in group {
                await onResult(pair.0, pair.1)
                while let config = iterator.next() {
                    if let isStillWanted, await !isStillWanted(config.id) { continue }
                    group.addTask {
                        let r = await runSingleLatencyTest(for: config, send: send)
                        return (config.id, r)
                    }
                    break
                }
            }
        }
    }

    nonisolated private static func sendLatencyTestMessage(
        for configuration: ProxyConfiguration,
        send: @Sendable (Data) async -> Data?
    ) async -> LatencyResult {
        guard let messageData = try? JSONEncoder().encode(TunnelMessage.testLatency(configuration)) else { return .failed }

        let responseData = await send(messageData)
        return (responseData.flatMap { try? JSONDecoder().decode(LatencyTestResponse.self, from: $0) })?.asLatencyResult ?? .failed
    }
}
