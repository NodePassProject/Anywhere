//
//  PacketFlowConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import NetworkExtension

nonisolated enum PacketFlowConcurrencyBridge {
    
    static func read(from flow: NEPacketTunnelFlow) async -> (packets: [Data], protocols: [NSNumber]) {
        await withCheckedContinuation { continuation in
            flow.readPackets { packets, protocols in
                continuation.resume(returning: (packets, protocols))
            }
        }
    }
}
