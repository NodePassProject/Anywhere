//
//  LWIPStack+FDRelief.swift
//  Anywhere
//
//  Created by NodePassProject on 5/15/26.
//

import Foundation

private let logger = AnywhereLogger(category: "LWIPStack")

extension LWIPStack {

    // MARK: - FD-Pressure Relief
    //
    // When `socket(2)` returns `EMFILE`, ``FDPressureRelief`` calls back into
    // here so we can close idle direct-bypass UDP flows and let the caller
    // retry. The policy is TCP-first: TCP failures are user-visible
    // (apps treat them as connection refused), so a TCP requester gets a
    // lower idle threshold and a higher eviction budget than a UDP
    // requester. UDP eviction stays conservative because evicting an
    // almost-active UDP flow just shifts the retry storm — UDP is lossy
    // by design, so failing the new flow is acceptable when no truly-idle
    // victim exists.
    //
    // Only flows with `holdsDirectFD == true` are eligible. Proxied flows
    // either share mux/SS sockets (closing them doesn't free a per-flow
    // FD) or hold TCP FDs we want to preserve under the TCP-first policy.

    /// Minimum idle seconds before a flow becomes eligible for eviction,
    /// per caller class. TCP is aggressive; UDP is conservative.
    private static let minIdleForTCPRelief: CFAbsoluteTime = 1.0
    private static let minIdleForUDPRelief: CFAbsoluteTime = 30.0

    /// Maximum flows evicted per relief call, per caller class.
    private static let maxEvictionsForTCPRelief = 4
    private static let maxEvictionsForUDPRelief = 1

    /// Installs the process-wide FD-pressure handler. Called from ``start``
    /// and ``restartStackNow``; matched by ``clearFDPressureReliefHandler``
    /// in ``stop``.
    ///
    /// The handler is invoked from socket-creation queues (RawUDPSocket /
    /// RawTCPSocket / QUICConnection I/O queues) and synchronously crosses
    /// into `lwipQueue`. lwIP never sync-waits on those queues, so the hop
    /// is deadlock-safe.
    func installFDPressureReliefHandler() {
        FDPressureRelief.handler = { [weak self] caller in
            guard let self else { return false }
            return self.lwipQueue.sync {
                self.evictDirectUDPFlowsForFDPressure(caller: caller)
            }
        }
    }

    /// Removes the process-wide FD-pressure handler.
    func clearFDPressureReliefHandler() {
        FDPressureRelief.handler = nil
    }

    /// Closes idle direct-bypass UDP flows by LRU to free FDs for the
    /// caller. Must be called on `lwipQueue`. Returns `true` if any flow
    /// was evicted.
    fileprivate func evictDirectUDPFlowsForFDPressure(caller: FDReliefCaller) -> Bool {
        let now = CFAbsoluteTimeGetCurrent()
        let minIdle: CFAbsoluteTime
        let maxEvictions: Int
        switch caller {
        case .tcp:
            minIdle = Self.minIdleForTCPRelief
            maxEvictions = Self.maxEvictionsForTCPRelief
        case .udp:
            minIdle = Self.minIdleForUDPRelief
            maxEvictions = Self.maxEvictionsForUDPRelief
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
            let tag = (caller == .tcp) ? "TCP" : "UDP"
            logger.warning("[UDP] FD pressure: evicted \(evicted) idle direct flow(s) for \(tag) request")
        }
        return evicted > 0
    }
}
