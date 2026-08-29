//
//  WatchSessionManager.swift
//  Anywhere
//
//  Created by NodePassProject on 7/4/26.
//

import Foundation
import WatchConnectivity

nonisolated private let logger = AnywhereLogger(category: "WatchSessionManager")

@MainActor
final class WatchSessionManager: NSObject {
    private let tunnel: TunnelController
    private let selection: ProxySelection
    private let configurationStore: ConfigurationStore
    private let chainStore: ChainStore
    private let groupStore: GroupStore
    private let subscriptionStore: SubscriptionStore
    private let operations: Operations

    private var session: WCSession?
    
    private var mirrored: WatchBridge.Snapshot?
    
    private var readyWaiters: [UUID: CheckedContinuation<Void, Never>] = [:]

    init(
        tunnel: TunnelController,
        selection: ProxySelection,
        configurationStore: ConfigurationStore,
        chainStore: ChainStore,
        groupStore: GroupStore,
        subscriptionStore: SubscriptionStore,
        operations: Operations
    ) {
        self.tunnel = tunnel
        self.selection = selection
        self.configurationStore = configurationStore
        self.chainStore = chainStore
        self.groupStore = groupStore
        self.subscriptionStore = subscriptionStore
        self.operations = operations
        super.init()
    }

    func start() {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        self.session = session
        session.delegate = self
        session.activate()
        observeMirroredState()
        observeReadiness()
    }

    // MARK: - Snapshot
    
    private var currentSnapshot: WatchBridge.Snapshot {
        WatchSnapshotBuilder(
            status: tunnel.status,
            selectedId: selection.selectedChainId ?? selection.selectedConfiguration?.id,
            selectedName: selection.selectedConfiguration?.name,
            configurations: configurationStore.configurations,
            chains: chainStore.chains,
            groups: groupStore.groups,
            subscriptions: subscriptionStore.subscriptions
        ).snapshot
    }

    // MARK: - Mirroring

    private func observeMirroredState() {
        withObservationTracking {
            _ = tunnel.status
            _ = selection.selectedConfiguration
            _ = selection.selectedChainId
            _ = configurationStore.configurations
            _ = chainStore.chains
            _ = groupStore.groups
            _ = subscriptionStore.subscriptions
        } onChange: { [weak self] in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.observeMirroredState()
                self.mirror()
            }
        }
    }
    
    private func mirror() {
        guard let session,
              session.activationState == .activated,
              session.isPaired,
              session.isWatchAppInstalled else { return }
        let snapshot = currentSnapshot
        guard snapshot != mirrored, let payload = snapshot.payload else { return }
        do {
            try session.updateApplicationContext(payload)
            mirrored = snapshot
        } catch {
            logger.warning("Failed to push watch context: \(error.localizedDescription)")
        }
    }

    // MARK: - Requests
    
    private func serve(_ request: WatchBridge.Request) async -> [String: Any] {
        await waitUntilReady()
        switch request {
        case .state:
            break
        case .toggleVPN:
            operations.tunnel.toggle()
        case .select(let id):
            select(id: id)
        }
        return currentSnapshot.payload ?? [:]
    }
    
    private func select(id: UUID) {
        let configurations = configurationStore.configurations
        if let chain = chainStore.chains.first(where: { $0.id == id }) {
            operations.selection.selectChain(chain, configurations: configurations)
        } else if let configuration = configurations.first(where: { $0.id == id }) {
            operations.selection.select(configuration)
        }
    }

    // MARK: - Readiness
    
    private var isReady: Bool { tunnel.isManagerReady && configurationStore.isLoaded }

    private func observeReadiness() {
        guard !isReady else {
            let waiters = Array(readyWaiters.values)
            readyWaiters.removeAll()
            for continuation in waiters { continuation.resume() }
            return
        }
        withObservationTracking {
            _ = tunnel.isManagerReady
            _ = configurationStore.isLoaded
        } onChange: { [weak self] in
            Task { @MainActor [weak self] in self?.observeReadiness() }
        }
    }
    
    private func waitUntilReady(timeout: Duration = .seconds(5)) async {
        guard !isReady else { return }
        let id = UUID()
        let expiry = Task { @MainActor [weak self] in
            try? await Task.sleep(for: timeout)
            guard !Task.isCancelled, let self else { return }
            logger.warning("Timed out waiting for stores before serving watch request")
            self.readyWaiters.removeValue(forKey: id)?.resume()
        }
        defer { expiry.cancel() }
        await withCheckedContinuation { continuation in
            readyWaiters[id] = continuation
        }
    }
}

// MARK: - WCSessionDelegate

extension WatchSessionManager: WCSessionDelegate {
    nonisolated func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: (any Error)?) {
        if let error {
            logger.warning("Watch session activation failed: \(error.localizedDescription)")
            return
        }
        Task { @MainActor in
            self.mirrored = nil
            self.mirror()
        }
    }

    nonisolated func sessionDidBecomeInactive(_ session: WCSession) {}

    nonisolated func sessionDidDeactivate(_ session: WCSession) {
        session.activate()
    }

    nonisolated func sessionWatchStateDidChange(_ session: WCSession) {
        Task { @MainActor in
            self.mirrored = nil
            self.mirror()
        }
    }

    nonisolated func session(_ session: WCSession, didReceiveMessage message: [String: Any], replyHandler: @escaping ([String: Any]) -> Void) {
        guard let request = WatchBridge.Request(payload: message) else {
            replyHandler([:])
            return
        }
        let reply = WatchConnectivityConcurrencyBridge.ReplyHandler(replyHandler)
        Task { @MainActor in
            reply(await self.serve(request))
        }
    }

    nonisolated func session(_ session: WCSession, didReceiveMessage message: [String: Any]) {
        guard let request = WatchBridge.Request(payload: message) else { return }
        Task { @MainActor in
            _ = await self.serve(request)
        }
    }
}
