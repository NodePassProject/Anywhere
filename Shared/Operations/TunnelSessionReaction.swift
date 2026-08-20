//
//  TunnelSessionReaction.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation
import NetworkExtension

@MainActor
struct TunnelSessionReaction {
    let tunnel: TunnelController
    let stats: ConnectionStatsModel
    let selection: ProxySelection

    func run() {
        let status = tunnel.rawStatus
        if status == .connected {
            stats.startPolling { [weak tunnel] data in
                await tunnel?.sendRaw(data)
            }
        } else {
            stats.stopPolling()
            if status == .disconnected || status == .invalid {
                stats.reset()
                if tunnel.consumePendingReconnect(),
                   let configuration = selection.selectedConfiguration {
                    tunnel.connect(using: configuration)
                }
            }
        }
    }
}
