//
//  TunnelLimits.swift
//  Anywhere
//
//  Created by NodePassProject on 7/5/26.
//

import Foundation

nonisolated enum TunnelLimits {
    /// Hard ceiling on concurrent TCP connections.
    static let tcpMaxConnections = 512
    /// Hard ceiling on concurrent UDP flows.
    static let udpMaxFlows = 256

    // MARK: - Kernel Flow Budget
    //
    // The kernel refuses new sockets for the process past an undocumented
    // per-process ceiling (observed ≈500 live flows: connect fails with
    // ENOMEM). The budget admits work well below that, leaving headroom for
    // DNS and for closed sockets still draining in the kernel, which no
    // user-space gauge can see.

    /// Admission load (``FlowGauge/admissionLoad``) above which new
    /// domain-routed TCP SYNs are dropped.
    static let flowBudget = 384
    /// New UDP flows (except DNS) are admitted only below this; lower than
    /// ``flowBudget`` so UDP yields the last headroom to interactive TCP.
    static let udpFlowAdmissionWatermark = 352
    /// Admission load at which swarm-shaped work yields: new raw-IP TCP SYNs
    /// are dropped and the UDP cap shrinks to ``udpMaxFlowsUnderPressure``,
    /// reserving the remaining band for domain-routed traffic.
    static let flowPressureWatermark = 288
    /// UDP pressure shedding, once entered, holds until the admission load
    /// falls below this (hysteresis against cap oscillation).
    static let flowPressureExitWatermark = 240
    /// Effective UDP flow cap while pressure shedding.
    static let udpMaxFlowsUnderPressure = 96
    /// Max UDP flows shed per eviction pass; bounds teardown churn.
    static let udpShedBatchLimit = 32
}
