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

/// iPhone side of the watch bridge: answers watch requests (state, toggle,
/// select) and mirrors VPN status and the proxy list to the watch through
/// the application context whenever they change.
@MainActor
final class WatchSessionManager: NSObject {
    static let shared = WatchSessionManager()

    private var session: WCSession?
    /// Last pushed snapshot encoding, to skip redundant context updates.
    private var lastPushedSnapshotData: Data?

    private override init() {
        super.init()
    }

    /// Activates the session and starts mirroring state changes to the watch.
    /// No-op where WatchConnectivity is unsupported (e.g. iPad).
    func start() {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        self.session = session
        session.delegate = self
        session.activate()
        observeAndPush()
    }

    // MARK: - State Mirroring

    /// Pushes on every change of anything `buildSnapshot()` reads, re-arming
    /// Observation tracking each round.
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
        let viewModel = VPNViewModel.shared

        var sections: [WatchBridge.Section] = []
        let standalone = ConfigurationStore.shared.standalonePickerItems
        if !standalone.isEmpty {
            sections.append(WatchBridge.Section(
                id: WatchBridge.standaloneSectionId,
                header: nil,
                items: standalone.map { WatchBridge.Item(id: $0.id, name: $0.name) }
            ))
        }
        let chains = ChainStore.shared.pickerItems
        if !chains.isEmpty {
            sections.append(WatchBridge.Section(
                id: WatchBridge.chainsSectionId,
                header: String(localized: "Chains"),
                items: chains.map { WatchBridge.Item(id: $0.id, name: $0.name) }
            ))
        }
        for section in SubscriptionStore.shared.pickerSections {
            sections.append(WatchBridge.Section(
                id: section.id,
                header: section.header,
                items: section.items.map { WatchBridge.Item(id: $0.id, name: $0.name) }
            ))
        }

        return WatchBridge.Snapshot(
            status: viewModel.status,
            selectedId: viewModel.selectedChainId ?? viewModel.selectedConfiguration?.id,
            selectedName: viewModel.selectedConfiguration?.name,
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

    /// Sorted keys so identical snapshots encode identically for deduping.
    nonisolated private static func encodeSnapshot(_ snapshot: WatchBridge.Snapshot) -> Data? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return try? encoder.encode(snapshot)
    }

    // MARK: - Requests

    private func handle(_ request: WatchBridge.Request) async -> [String: Any] {
        switch request {
        case .state:
            // A state request right after a background launch should report
            // the real tunnel status, not the not-yet-loaded default.
            await waitUntilReady()
        case .toggleVPN:
            await waitUntilReady()
            VPNViewModel.shared.toggleVPN()
        case .select(let id):
            await waitUntilReady()
            select(id: id)
        }
        return buildSnapshot().payload ?? [:]
    }

    /// Same resolution as the home screen picker: chains win over configurations.
    private func select(id: UUID) {
        let configurations = ConfigurationStore.shared.configurations
        if let chain = ChainStore.shared.chains.first(where: { $0.id == id }) {
            VPNViewModel.shared.selectChain(chain, configurations: configurations)
        } else if let configuration = configurations.first(where: { $0.id == id }) {
            VPNViewModel.shared.selectedConfiguration = configuration
        }
    }

    /// Waits (bounded) for the VPN manager and configuration store to finish
    /// their initial load, so requests arriving right after the system wakes
    /// the app in the background act on real data.
    private func waitUntilReady(timeout: Duration = .seconds(5)) async {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        while clock.now < deadline {
            if VPNViewModel.shared.isManagerReady, ConfigurationStore.shared.isLoaded { return }
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
        Task { @MainActor in
            replyHandler(await self.handle(request))
        }
    }

    nonisolated func session(_ session: WCSession, didReceiveMessage message: [String: Any]) {
        guard let request = WatchBridge.Request(payload: message) else { return }
        Task { @MainActor in
            _ = await self.handle(request)
        }
    }
}
