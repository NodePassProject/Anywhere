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

/// Watch side of the bridge: holds the latest snapshot received from the
/// iPhone and sends state/toggle/select requests. `sendMessage` wakes the
/// iOS app in the background, so commands work even when it is not running.
@MainActor
@Observable
final class PhoneSession: NSObject {
    static let shared = PhoneSession()

    private(set) var snapshot: WatchBridge.Snapshot?
    /// When the iPhone took `snapshot` — survives cold starts because the
    /// stamp travels with the payload, not the delivery.
    private(set) var snapshotDate: Date?
    private(set) var isActivated = false
    /// Set when the last command failed (e.g. iPhone out of range); cleared
    /// by the next successful exchange.
    private(set) var lastError: String?

    /// Optimistic status shown between sending a toggle and the iPhone
    /// reporting a matching transition, so the button reacts instantly.
    private var pendingStatus: VPNStatus?
    @ObservationIgnored private var pendingExpiryTask: Task<Void, Never>?
    @ObservationIgnored private var refreshTask: Task<Void, Never>?
    /// Pending deadline after a refresh found the session unreachable; if
    /// reachability does not arrive before it fires, staleness is surfaced.
    @ObservationIgnored private var unreachableGraceTask: Task<Void, Never>?

    private override init() {
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

    /// Asks the iPhone for a fresh snapshot.
    func refresh() {
        guard isActivated else { return }
        // Right after foregrounding, reachability lands a beat after
        // activation — sending now is a guaranteed failure and would flash
        // the staleness indicator. Let sessionReachabilityDidChange deliver
        // the refresh, and only surface staleness if it never comes.
        guard WCSession.default.isReachable else {
            scheduleUnreachableGrace()
            return
        }
        send(.state)
    }

    /// Marks the data stale unless reachability arrives within the grace window.
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
        // Update locally so the picker reflects the tap immediately; the
        // reply overwrites with the authoritative state.
        if var snapshot, snapshot.selectedId != id {
            snapshot.selectedId = id
            snapshot.selectedName = snapshot.sections.flatMap(\.items).first { $0.id == id }?.name
            self.snapshot = snapshot
        }
        send(.select(id: id))
    }

    private func send(_ request: WatchBridge.Request) {
        guard let payload = request.payload else { return }
        WCSession.default.sendMessage(payload) { [weak self] reply in
            Task { @MainActor in
                guard let self else { return }
                self.lastError = nil
                self.apply(payload: reply)
            }
        } errorHandler: { [weak self] error in
            logger.warning("Watch request failed: \(error.localizedDescription)")
            Task { @MainActor in
                guard let self else { return }
                self.clearPending()
                self.lastError = error.localizedDescription
            }
        }
    }

    // MARK: - Snapshot Intake

    /// Decodes and applies a snapshot payload, recording when the iPhone took it.
    private func apply(payload: [String: Any]) {
        guard let snapshot = WatchBridge.Snapshot(payload: payload) else { return }
        cancelUnreachableGrace()
        snapshotDate = payload[WatchBridge.snapshotDateKey] as? Date ?? .now
        apply(snapshot)
    }

    private func apply(_ snapshot: WatchBridge.Snapshot) {
        self.snapshot = snapshot

        // Drop the optimistic status once the iPhone reports the transition
        // (or its end state) for the pending direction.
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

    /// The iPhone may be suspended before it can push the final status of a
    /// transition, so poll while one is in flight.
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
        Task { @MainActor in
            self.isActivated = activationState == .activated
            // Seed from the last pushed context so the UI has data instantly
            // on cold start, then ask for fresh state.
            if self.snapshot == nil {
                self.apply(payload: cachedContext)
            }
            self.refresh()
        }
    }

    nonisolated func session(_ session: WCSession, didReceiveApplicationContext applicationContext: [String: Any]) {
        Task { @MainActor in
            self.lastError = nil
            self.apply(payload: applicationContext)
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
