//
//  FlowGauge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/6/26.
//

import Foundation
import Synchronization

nonisolated enum FlowGauge {
    private static let tcpCount = Atomic<Int>(0)
    private static let udpCount = Atomic<Int>(0)
    private static let pendingTCPCount = Atomic<Int>(0)

    static var liveTCP: Int { tcpCount.load(ordering: .relaxed) }
    static var liveUDP: Int { udpCount.load(ordering: .relaxed) }

    /// Total live outbound sockets.
    static var live: Int { liveTCP + liveUDP }

    /// TCP connections admitted at the SYN filter whose outbound dial hasn't
    /// been created yet (3WHS + protocol-sniff window). Without this, a SYN
    /// burst is admitted against a stale low `live` and overshoots the budget
    /// before any of its sockets exist.
    static var pendingTCP: Int { pendingTCPCount.load(ordering: .relaxed) }

    /// What admission control compares against ``TunnelLimits/flowBudget``:
    /// live sockets plus admitted-but-not-yet-dialed TCP connections.
    static var admissionLoad: Int { live + pendingTCP }

    static func incrementTCP() { tcpCount.wrappingAdd(1, ordering: .relaxed) }
    static func decrementTCP() { tcpCount.wrappingSubtract(1, ordering: .relaxed) }
    static func incrementUDP() { udpCount.wrappingAdd(1, ordering: .relaxed) }
    static func decrementUDP() { udpCount.wrappingSubtract(1, ordering: .relaxed) }
    static func incrementPendingTCP() { pendingTCPCount.wrappingAdd(1, ordering: .relaxed) }
    static func decrementPendingTCP() { pendingTCPCount.wrappingSubtract(1, ordering: .relaxed) }
}
