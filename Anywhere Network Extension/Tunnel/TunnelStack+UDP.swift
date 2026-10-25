//
//  TunnelStack+UDP.swift
//  Anywhere
//
//  Created by NodePassProject on 5/23/26.
//

import Foundation
import AnywhereIP

extension TunnelStack {
    static func isSTUNMessage(_ payload: Data) -> Bool {
        guard payload.count >= 20 else { return false }
        let base = payload.startIndex
        guard payload[base] & 0xC0 == 0 else { return false }
        guard payload[base + 4] == 0x21, payload[base + 5] == 0x12,
              payload[base + 6] == 0xA4, payload[base + 7] == 0x42 else { return false }
        let messageLength = Int(payload[base + 2]) << 8 | Int(payload[base + 3])
        return messageLength & 0x3 == 0 && messageLength + 20 == payload.count
    }
    
    nonisolated func sendICMPPortUnreachable(rejecting datagram: InboundDatagram) {
        guard let packet = OutboundPacket(portUnreachable: datagram) else { return }
        enqueueOutbound(packet)
    }

    nonisolated func writeOutboundUDP(_ payload: Data, from source: IPEndpoint, to destination: IPEndpoint) {
        guard let packet = OutboundPacket(datagram: payload, from: source, to: destination) else { return }
        enqueueOutbound(packet)
    }
}
