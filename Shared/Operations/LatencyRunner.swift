//
//  LatencyRunner.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
struct LatencyRunner {
    let latency: LatencyCenter
    let tunnel: TunnelController
    let configurationStore: ConfigurationStore
    let chainStore: ChainStore

    func test(_ configuration: ProxyConfiguration) {
        latency.testLatency(for: configuration, transport: tunnel, isLive: liveConfiguration)
    }

    func testAll(_ targets: [ProxyConfiguration]) {
        latency.testLatencies(for: targets, transport: tunnel, isLive: liveConfiguration)
    }

    func testChain(_ chain: ProxyChain) {
        latency.testChainLatency(
            for: chain,
            configurations: configurationStore.configurations,
            transport: tunnel,
            isLiveChain: liveChain
        )
    }

    func testChains(_ chains: [ProxyChain]) {
        latency.testAllChainLatencies(
            chains: chains,
            configurations: configurationStore.configurations,
            transport: tunnel,
            isLiveChain: liveChain,
            isResolvableChain: resolvableChain
        )
    }

    // MARK: - Liveness

    private var liveConfiguration: @MainActor @Sendable (UUID) -> Bool {
        { [weak configurationStore] id in
            configurationStore?.configurations.contains { $0.id == id } ?? false
        }
    }

    private var liveChain: @MainActor @Sendable (UUID) -> Bool {
        { [weak chainStore] id in
            chainStore?.chains.contains { $0.id == id } ?? false
        }
    }

    private var resolvableChain: @MainActor @Sendable (UUID) -> Bool {
        { [weak chainStore, weak configurationStore] id in
            guard let chain = chainStore?.chains.first(where: { $0.id == id }),
                  let configurations = configurationStore?.configurations else { return false }
            return chain.resolveComposite(from: configurations) != nil
        }
    }
}
