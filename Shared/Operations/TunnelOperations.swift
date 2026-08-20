//
//  TunnelOperations.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation
import NetworkExtension

@MainActor
struct TunnelOperations {
    let tunnel: TunnelController
    let selection: ProxySelection

    func toggle() {
        switch tunnel.rawStatus {
        case .connected, .connecting:
            tunnel.disconnect()
        case .disconnected, .invalid:
            connect()
        default:
            break
        }
    }

    func connect() {
        guard let configuration = selection.selectedConfiguration else { return }
        tunnel.connect(using: configuration)
    }

    func disconnect() {
        tunnel.disconnect()
    }

    func reconnect() {
        tunnel.reconnect()
    }
}
