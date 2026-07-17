//
//  TunnelStack+UDP.swift
//  Anywhere
//
//  Created by NodePassProject on 5/23/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "TunnelStack+UDP")

extension TunnelStack {

    /// Classifies a STUN message (RFC 5389 §6) by the magic cookie at offset 4
    /// plus structural checks, so no port allow-list is needed. Classic STUN
    /// (RFC 3489, no cookie) is deliberately unmatched — WebRTC always sends
    /// the cookie, and matching cookieless traffic could drop unrelated UDP.
    static func isSTUNMessage(_ payload: Data) -> Bool {
        guard payload.count >= 20 else { return false }
        // A sliced `Data` keeps its parent's indices — address relative to startIndex.
        let base = payload.startIndex
        guard payload[base] & 0xC0 == 0 else { return false }
        // Bytes 4–7: the magic cookie.
        guard payload[base + 4] == 0x21, payload[base + 5] == 0x12,
              payload[base + 6] == 0xA4, payload[base + 7] == 0x42 else { return false }
        // Length must be 4-byte aligned and fill the datagram exactly.
        let messageLength = Int(payload[base + 2]) << 8 | Int(payload[base + 3])
        return messageLength & 0x3 == 0 && messageLength + 20 == payload.count
    }

    // MARK: - Outbound UDP

    /// Answers `datagram` with ICMP port-unreachable — sourced from the
    /// original destination — so the sender abandons the destination fast
    /// (QUIC fallback, stale fake IPs, blocked UDP). Callable from anywhere.
    func sendICMPPortUnreachable(rejecting datagram: UDPPacket.Inbound) {
        guard let packet = ICMPPacket.portUnreachable(
            srcIP: datagram.srcIPData,
            srcPort: datagram.srcPort,
            dstIP: datagram.dstIPData,
            dstPort: datagram.dstPort,
            isIPv6: datagram.isIPv6,
            udpPayloadLength: datagram.payload.count
        ) else { return }
        enqueueOutbound(packet, isIPv6: datagram.isIPv6)
    }

    /// Builds a UDP packet and queues it to the TUN output; callers pass the
    /// original 5-tuple swapped. Callable from anywhere.
    func writeOutboundUDP(srcIP: Data, srcPort: UInt16,
                          dstIP: Data, dstPort: UInt16,
                          isIPv6: Bool, payload: Data) {
        guard let packet = UDPPacket.build(
            srcIP: srcIP, srcPort: srcPort,
            dstIP: dstIP, dstPort: dstPort,
            isIPv6: isIPv6, payload: payload
        ) else {
            logger.debug("[UDP] Dropped outbound datagram: build failed (len=\(payload.count), v6=\(isIPv6))")
            return
        }
        enqueueOutbound(packet, isIPv6: isIPv6)
    }
}
