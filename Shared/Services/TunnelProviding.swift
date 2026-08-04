//
//  TunnelProviding.swift
//  Anywhere
//
//  Created by NodePassProject on 8/3/26.
//

import Foundation
import NetworkExtension

struct TunnelStartRequest {
    var includeAllNetworks = false
    var excludeLocalNetworks = true
    var excludeAPNs = true
    var excludeCellularServices = true
    var alwaysOn = false
    var startMessage: Data
}

@MainActor
protocol TunnelProviding: AnyObject {
    var status: NEVPNStatus { get }
    func prepare() async
    func statusUpdates() -> AsyncStream<NEVPNStatus>
    func start(_ request: TunnelStartRequest) async throws
    func stop(disablingAlwaysOn: Bool) async
    func send(_ data: Data) async -> Data?
}
