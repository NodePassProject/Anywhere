//
//  TunnelLimits.swift
//  Anywhere
//
//  Created by NodePassProject on 7/5/26.
//

import Foundation

nonisolated enum TunnelLimits {
    static let tcpMaxConnections = 128
    static let udpMaxFlows = 128
    static let udpMaxPendingResolutions = 64
}
