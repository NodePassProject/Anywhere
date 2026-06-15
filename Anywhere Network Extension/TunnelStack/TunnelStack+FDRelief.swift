//
//  TunnelStack+FDRelief.swift
//  Anywhere
//
//  Created by NodePassProject on 5/15/26.
//

import Foundation

private let logger = AnywhereLogger(category: "TunnelStack+FDRelief")

extension TunnelStack {

    // MARK: - FD-Pressure Relief
    //
    // When `socket(2)` returns `EMFILE`, ``FDPressureRelief`` calls back here
    // to close idle direct-bypass UDP flows so the caller can retry. A
    // `.userVisible` requester fails in a way the user sees, so it gets a lower
    // idle threshold and a higher eviction budget than `.bestEffort`. Only
    // flows with `holdsDirectFD == true` are eligible — proxied flows share
    // mux/SS sockets or hold TCP FDs we want to preserve.

    /// Minimum idle seconds before a flow becomes eviction-eligible, per tier.
    private static let minIdleForUserVisibleRelief: CFAbsoluteTime = 1.0
    private static let minIdleForBestEffortRelief: CFAbsoluteTime = 30.0

    /// Maximum flows evicted per relief call, per priority tier.
    private static let maxEvictionsForUserVisibleRelief = 4
    private static let maxEvictionsForBestEffortRelief = 1

    /// Installs the process-wide FD-pressure handler. Invoked from socket I/O
    /// queues and sync-hops onto `udpQueue`. Deadlock-safe: the only udpQueue
    /// sync-wait onto a socket queue is the victim's `closeSync`, and the
    /// victim is a distinct idle flow — never the mid-connect requester.
    func installFDPressureReliefHandler() {
        FDPressureRelief.handler = { [weak self] priority in
            guard let self else { return false }
            return self.udpQueue.sync {
                self.evictDirectUDPFlowsForFDPressure(priority: priority)
            }
        }
    }

    func clearFDPressureReliefHandler() {
        FDPressureRelief.handler = nil
    }

    /// Closes idle direct-bypass UDP flows by LRU. Must be called on
    /// `udpQueue`. Returns `true` if any flow was evicted.
    fileprivate func evictDirectUDPFlowsForFDPressure(priority: FDReliefPriority) -> Bool {
        let now = MonotonicClock.now
        let minIdle: TimeInterval
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
            removeUDPFlow(flow)
            evicted += 1
        }
        if evicted > 0 {
            let tag = (priority == .userVisible) ? "user-visible" : "best-effort"
            logger.warning("[UDP] FD pressure: evicted \(evicted) idle direct flow(s) for \(tag) request")
        }
        return evicted > 0
    }
}
