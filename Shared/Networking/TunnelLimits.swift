//
//  TunnelLimits.swift
//  Anywhere
//
//  Created by NodePassProject on 7/5/26.
//

import Foundation

enum TunnelLimits {
    /// Hard ceiling on concurrent TCP connections.
    static let tcpMaxConnections = 512
    /// Hard ceiling on concurrent UDP flows.
    static let udpMaxFlows = 256
}
