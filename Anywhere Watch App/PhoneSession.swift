//
//  PhoneSession.swift
//  Anywhere
//
//  Created by NodePassProject on 7/4/26.
//

import Foundation
import Observation
import WatchConnectivity

nonisolated private let logger = AnywhereLogger(category: "PhoneSession")

@MainActor
@Observable
final class PhoneSession: NSObject {
    private(set) var snapshot: WatchBridge.Snapshot?
    private(set) var snapshotDate: Date?
    
    private(set) var isActivated = false
    private(set) var lastError: String?
    
    private var pendingStatus: VPNStatus?
    @ObservationIgnored private var pendingExpiryTask: Task<Void, Never>?
    @ObservationIgnored private var refreshTask: Task<Void, Never>?
    @ObservationIgnored private var unreachableGraceTask: Task<Void, Never>?

    override init() {
        super.init()
    }

    func start() {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        session.delegate = self
        session.activate()
    }

    // MARK: - Derived State

    var status: VPNStatus {
        pendingStatus ?? snapshot?.status ?? .disconnected
    }

    var isConnected: Bool { status == .connected }

    var isTransitioning: Bool { status.isTransitioning }

    // MARK: - Commands
    
    func refresh() {
        guard isActivated else { return }
        guard WCSession.default.isReachable else {
            scheduleUnreachableGrace()
            return
        }
        send(.state)
    }
    
    private func scheduleUnreachableGrace() {
        guard unreachableGraceTask == nil else { return }
        unreachableGraceTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(2.5))
            guard !Task.isCancelled, let self else { return }
            self.unreachableGraceTask = nil
            if !WCSession.default.isReachable {
                self.lastError = "iPhone not reachable"
            }
        }
    }

    private func cancelUnreachableGrace() {
        unreachableGraceTask?.cancel()
        unreachableGraceTask = nil
    }

    func toggleVPN() {
        guard let snapshot, snapshot.hasConfigurations, !isTransitioning else { return }
        setPending(snapshot.status == .connected ? .disconnecting : .connecting)
        send(.toggleVPN)
    }

    func select(_ id: UUID) {
        if var snapshot, snapshot.selectedId != id {
            snapshot.selectedId = id
            snapshot.selectedName = snapshot.sections.flatMap(\.items).first { $0.id == id }?.name
            self.snapshot = snapshot
        }
        send(.select(id: id))
    }

    private func send(_ request: WatchBridge.Request) {
        guard let payload = request.payload else { return }
        WCSession.default.sendMessage(payload) { @Sendable [weak self] reply in
            let snapshot = WatchBridge.Snapshot(payload: reply)
            let date = reply[WatchBridge.snapshotDateKey] as? Date ?? .now
            Task { @MainActor in
                guard let self else { return }
                self.lastError = nil
                if let snapshot {
                    self.apply(snapshot, taken: date)
                }
            }
        } errorHandler: { @Sendable [weak self] error in
            logger.warning("Watch request failed: \(error.localizedDescription)")
            Task { @MainActor in
                guard let self else { return }
                self.clearPending()
                self.lastError = error.localizedDescription
            }
        }
    }

    // MARK: - Snapshot Intake

    private func apply(_ snapshot: WatchBridge.Snapshot, taken date: Date) {
        cancelUnreachableGrace()
        snapshotDate = date
        self.snapshot = snapshot
        
        if let pending = pendingStatus {
            switch pending {
            case .connecting:
                if [.connecting, .reasserting, .connected].contains(snapshot.status) { clearPending() }
            case .disconnecting:
                if [.disconnecting, .disconnected, .invalid].contains(snapshot.status) { clearPending() }
            default:
                clearPending()
            }
        }

        scheduleRefreshIfTransitioning()
    }
    
    private func scheduleRefreshIfTransitioning() {
        refreshTask?.cancel()
        guard isTransitioning else { return }
        refreshTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(1.5))
            guard !Task.isCancelled else { return }
            self?.refresh()
        }
    }

    // MARK: - Pending Status

    private func setPending(_ status: VPNStatus) {
        pendingStatus = status
        pendingExpiryTask?.cancel()
        // Failsafe: never show a phantom transition forever.
        pendingExpiryTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(10))
            guard !Task.isCancelled else { return }
            self?.pendingStatus = nil
        }
        scheduleRefreshIfTransitioning()
    }

    private func clearPending() {
        pendingExpiryTask?.cancel()
        pendingExpiryTask = nil
        pendingStatus = nil
    }
}

// MARK: - WCSessionDelegate

extension PhoneSession: WCSessionDelegate {
    nonisolated func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: (any Error)?) {
        if let error {
            logger.warning("Session activation failed: \(error.localizedDescription)")
        }
        let cachedContext = session.receivedApplicationContext
        let cached = WatchBridge.Snapshot(payload: cachedContext)
        let cachedDate = cachedContext[WatchBridge.snapshotDateKey] as? Date ?? .now
        Task { @MainActor in
            self.isActivated = activationState == .activated
            if self.snapshot == nil, let cached {
                self.apply(cached, taken: cachedDate)
            }
            self.refresh()
        }
    }

    nonisolated func session(_ session: WCSession, didReceiveApplicationContext applicationContext: [String: Any]) {
        let snapshot = WatchBridge.Snapshot(payload: applicationContext)
        let date = applicationContext[WatchBridge.snapshotDateKey] as? Date ?? .now
        Task { @MainActor in
            self.lastError = nil
            if let snapshot {
                self.apply(snapshot, taken: date)
            }
        }
    }

    nonisolated func sessionReachabilityDidChange(_ session: WCSession) {
        guard session.isReachable else { return }
        Task { @MainActor in
            self.cancelUnreachableGrace()
            self.refresh()
        }
    }
}
