//
//  FlowGauge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/6/26.
//

import Foundation
import Synchronization

nonisolated enum FlowGauge {
    private static let tcpTableCount = Atomic<Int>(0)
    private static let udpTableCount = Atomic<Int>(0)

    static var tcpTable: Int { tcpTableCount.load(ordering: .relaxed) }
    static var udpTable: Int { udpTableCount.load(ordering: .relaxed) }

    static func publishTCPTable(_ count: Int) { tcpTableCount.store(count, ordering: .relaxed) }
    static func publishUDPTable(_ count: Int) { udpTableCount.store(count, ordering: .relaxed) }
}
