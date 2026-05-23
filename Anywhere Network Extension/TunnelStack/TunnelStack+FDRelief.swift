//
//  TunnelStack+FDRelief.swift
//  Anywhere
//
//  Created by NodePassProject on 5/15/26.
//

import Foundation

private let logger = AnywhereLogger(category: "TunnelStack")

extension TunnelStack {

    // MARK: - FD-Pressure Relief
    //
    // When `socket(2)` returns `EMFILE`, ``FDPressureRelief`` calls back into
    // here so we can close idle direct-bypass UDP flows and let the caller
    // retry. The policy biases by priority tier (see ``FDReliefPriority``): a
    // `.userVisible` requester (TCP, or QUIC carrying proxied traffic) fails
    // in a way the user sees, so it gets a lower idle threshold and a higher
    // eviction budget than a `.bestEffort` requester. Best-effort (direct UDP)
    // eviction stays conservative because evicting an almost-active UDP flow
    // just shifts the retry storm — UDP is lossy by design, so failing the new
    // flow is acceptable when no truly-idle victim exists.
    //
    // Only flows with `holdsDirectFD == true` are eligible. Proxied flows
    // either share mux/SS sockets (closing them doesn't free a per-flow
    // FD) or hold TCP FDs we want to preserve under the user-visible-first
    // policy.

    /// Minimum idle seconds before a flow becomes eligible for eviction, per
    /// priority tier. User-visible is aggressive; best-effort is conservative.
    private static let minIdleForUserVisibleRelief: CFAbsoluteTime = 1.0
    private static let minIdleForBestEffortRelief: CFAbsoluteTime = 30.0

    /// Maximum flows evicted per relief call, per priority tier.
    private static let maxEvictionsForUserVisibleRelief = 4
    private static let maxEvictionsForBestEffortRelief = 1

    /// Installs the process-wide FD-pressure handler. Called from ``start``
    /// and ``restartStackNow``; matched by ``clearFDPressureReliefHandler``
    /// in ``stop``.
    ///
    /// The handler is invoked from socket-creation queues (RawUDPSocket /
    /// RawTCPSocket / QUICSocket I/O queues) and synchronously crosses
    /// into `lwipQueue`. lwIP never sync-waits on those queues, so the hop
    /// is deadlock-safe.
    func installFDPressureReliefHandler() {
        FDPressureRelief.handler = { [weak self] priority in
            guard let self else { return false }
            return self.lwipQueue.sync {
                self.evictDirectUDPFlowsForFDPressure(priority: priority)
            }
        }
    }

    /// Removes the process-wide FD-pressure handler.
    func clearFDPressureReliefHandler() {
        FDPressureRelief.handler = nil
    }

    /// Closes idle direct-bypass UDP flows by LRU to free FDs for the
    /// requester. Must be called on `lwipQueue`. Returns `true` if any flow
    /// was evicted.
    fileprivate func evictDirectUDPFlowsForFDPressure(priority: FDReliefPriority) -> Bool {
        let now = CFAbsoluteTimeGetCurrent()
        let minIdle: CFAbsoluteTime
        let maxEvictions: Int
        switch priority {
        case .userVisible:
            minIdle = Self.minIdleForUserVisibleRelief
            maxEvictions = Self.maxEvictionsForUserVisibleRelief
        case .bestEffort:
            minIdle = Self.minIdleForBestEffortRelief
            maxEvictions = Self.maxEvictionsForBestEffortRelief
        }

        let candidates = udpFlows.values
            .filter { $0.holdsDirectFD && now - $0.lastActivity >= minIdle }
            .sorted { $0.lastActivity < $1.lastActivity }

        var evicted = 0
        for flow in candidates.prefix(maxEvictions) {
            flow.closeSync()
            udpFlows.removeValue(forKey: flow.flowKey)
            evicted += 1
        }
        if evicted > 0 {
            let tag = (priority == .userVisible) ? "user-visible" : "best-effort"
            logger.warning("[UDP] FD pressure: evicted \(evicted) idle direct flow(s) for \(tag) request")
        }
        return evicted > 0
    }
}
