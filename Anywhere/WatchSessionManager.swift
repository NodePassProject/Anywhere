//
//  WatchSessionManager.swift
//  Anywhere
//
//  Created by NodePassProject on 7/4/26.
//

import Foundation
import NetworkExtension
import WatchConnectivity

nonisolated private let logger = AnywhereLogger(category: "WatchSessionManager")

@MainActor
final class WatchSessionManager: NSObject {
    private let tunnel: TunnelController
    private let selection: ProxySelection
    private let configurationStore: ConfigurationStore
    private let chainStore: ChainStore
    private let subscriptionStore: SubscriptionStore

    private var session: WCSession?
    
    private var lastPushedSnapshotData: Data?

    init(
        tunnel: TunnelController,
        selection: ProxySelection,
        configurationStore: ConfigurationStore,
        chainStore: ChainStore,
        subscriptionStore: SubscriptionStore
    ) {
        self.tunnel = tunnel
        self.selection = selection
        self.configurationStore = configurationStore
        self.chainStore = chainStore
        self.subscriptionStore = subscriptionStore
        super.init()
    }
    
    func start() {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        self.session = session
        session.delegate = self
        session.activate()
        observeAndPush()
    }

    // MARK: - State Mirroring
    
    private func observeAndPush() {
        withObservationTracking {
            _ = buildSnapshot()
        } onChange: { [weak self] in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.pushSnapshot()
                self.observeAndPush()
            }
        }
    }

    private func buildSnapshot() -> WatchBridge.Snapshot {
        var sections: [WatchBridge.Section] = []
        let standalone = configurationStore.standalonePickerItems
        if !standalone.isEmpty {
            sections.append(WatchBridge.Section(
                id: WatchBridge.standaloneSectionId,
                header: nil,
                items: standalone.map { WatchBridge.Item(id: $0.id, name: $0.name) }
            ))
        }
        let chains = chainStore.pickerItems
        if !chains.isEmpty {
            sections.append(WatchBridge.Section(
                id: WatchBridge.chainsSectionId,
                header: String(localized: "Chains"),
                items: chains.map { WatchBridge.Item(id: $0.id, name: $0.name) }
            ))
        }
        for section in subscriptionStore.pickerSections {
            sections.append(WatchBridge.Section(
                id: section.id,
                header: section.header,
                items: section.items.map { WatchBridge.Item(id: $0.id, name: $0.name) }
            ))
        }

        return WatchBridge.Snapshot(
            status: tunnel.status,
            selectedId: selection.selectedChainId ?? selection.selectedConfiguration?.id,
            selectedName: selection.selectedConfiguration?.name,
            sections: sections
        )
    }

    private func pushSnapshot() {
        guard let session,
              session.activationState == .activated,
              session.isPaired,
              session.isWatchAppInstalled else { return }
        guard let data = Self.encodeSnapshot(buildSnapshot()), data != lastPushedSnapshotData else { return }
        do {
            try session.updateApplicationContext([
                WatchBridge.snapshotKey: data,
                WatchBridge.snapshotDateKey: Date.now,
            ])
            lastPushedSnapshotData = data
        } catch {
            logger.warning("Failed to push watch context: \(error.localizedDescription)")
        }
    }
    
    nonisolated private static func encodeSnapshot(_ snapshot: WatchBridge.Snapshot) -> Data? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return try? encoder.encode(snapshot)
    }

    // MARK: - Requests

    private func handle(_ request: WatchBridge.Request) async -> [String: Any] {
        switch request {
        case .state:
            await waitUntilReady()
        case .toggleVPN:
            await waitUntilReady()
            tunnel.toggle()
        case .select(let id):
            await waitUntilReady()
            select(id: id)
        }
        return buildSnapshot().payload ?? [:]
    }
    
    private func select(id: UUID) {
        let configurations = configurationStore.configurations
        if let chain = chainStore.chains.first(where: { $0.id == id }) {
            selection.selectChain(chain, configurations: configurations)
        } else if let configuration = configurations.first(where: { $0.id == id }) {
            selection.selectedConfiguration = configuration
        }
    }
    
    private func waitUntilReady(timeout: Duration = .seconds(5)) async {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        while clock.now < deadline {
            if tunnel.isManagerReady, configurationStore.isLoaded { return }
            try? await Task.sleep(for: .milliseconds(50))
        }
        logger.warning("Timed out waiting for stores before serving watch request")
    }
}

// MARK: - WCSessionDelegate

extension WatchSessionManager: WCSessionDelegate {
    nonisolated func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: (any Error)?) {
        if let error {
            logger.warning("Watch session activation failed: \(error.localizedDescription)")
            return
        }
        Task { @MainActor in self.pushSnapshot() }
    }

    nonisolated func sessionDidBecomeInactive(_ session: WCSession) {}

    nonisolated func sessionDidDeactivate(_ session: WCSession) {
        // Re-activate so a newly paired watch keeps working.
        session.activate()
    }

    nonisolated func sessionWatchStateDidChange(_ session: WCSession) {
        Task { @MainActor in self.pushSnapshot() }
    }

    nonisolated func session(_ session: WCSession, didReceiveMessage message: [String: Any], replyHandler: @escaping ([String: Any]) -> Void) {
        guard let request = WatchBridge.Request(payload: message) else {
            replyHandler([:])
            return
        }
        let reply = WatchConnectivityConcurrencyBridge.ReplyHandler(replyHandler)
        Task { @MainActor in
            reply(await self.handle(request))
        }
    }

    nonisolated func session(_ session: WCSession, didReceiveMessage message: [String: Any]) {
        guard let request = WatchBridge.Request(payload: message) else { return }
        Task { @MainActor in
            _ = await self.handle(request)
        }
    }
}
