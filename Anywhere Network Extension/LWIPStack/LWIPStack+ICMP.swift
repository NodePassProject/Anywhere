//
//  LWIPStack+ICMP.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
//

import Foundation

extension LWIPStack {

    // MARK: - ICMP Port Unreachable
    //
    // Sent when UDP arrives at a stale fake IP no longer in the pool (e.g. from a
    // previous VPN session). The ICMP response causes QUIC/UDP clients to abandon
    // the stale connection and re-resolve DNS, instead of retrying indefinitely.

    /// Crafts and queues an ICMP Destination Unreachable (Port Unreachable) response.
    /// Must be called on lwipQueue.
    func sendICMPPortUnreachable(
        srcIP: UnsafeRawPointer,
        srcPort: UInt16,
        dstIP: UnsafeRawPointer,
        dstPort: UInt16,
        isIPv6: Bool,
        udpPayloadLength: Int
    ) {
        let packet: Data
        let proto: NSNumber
        if isIPv6 {
            packet = buildICMPv6PortUnreachable(
                srcIP: srcIP,
                srcPort: srcPort,
                dstIP: dstIP,
                dstPort: dstPort,
                udpPayloadLength: udpPayloadLength
            )
            proto = Self.ipv6Proto
        } else {
            packet = buildICMPv4PortUnreachable(
                srcIP: srcIP,
                srcPort: srcPort,
                dstIP: dstIP,
                dstPort: dstPort,
                udpPayloadLength: udpPayloadLength
            )
            proto = Self.ipv4Proto
        }
        outputPackets.append(packet)
        outputProtocols.append(proto)
        if !outputFlushScheduled {
            outputFlushScheduled = true
            lwipQueue.async { [self] in
                flushOutputPackets()
            }
        }
    }

    /// Builds an IPv4 ICMP Destination Unreachable (Type 3, Code 3) packet.
    /// Contains a reconstructed original IPv4+UDP header per RFC 792.
    private func buildICMPv4PortUnreachable(
        srcIP: UnsafeRawPointer,
        srcPort: UInt16,
        dstIP: UnsafeRawPointer,
        dstPort: UInt16,
        udpPayloadLength: Int
    ) -> Data {
        // Outer IPv4 (20) + ICMP header (8) + inner IPv4 (20) + UDP header (8) = 56
        let packetLen = 56
        var packet = Data(count: packetLen)
        packet.withUnsafeMutableBytes { raw in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!

            // --- Outer IPv4 header (src=fake IP, dst=sender) ---
            p[0] = 0x45                                     // Version 4, IHL 5
            p[1] = 0x00                                     // TOS
            p[2] = UInt8(packetLen >> 8)                    // Total length
            p[3] = UInt8(packetLen & 0xFF)
            p[4] = 0; p[5] = 0                              // Identification
            p[6] = 0; p[7] = 0                              // Flags + Fragment offset
            p[8] = 64                                       // TTL
            p[9] = 1                                        // Protocol: ICMP
            p[10] = 0; p[11] = 0                            // Checksum (below)
            memcpy(p + 12, dstIP, 4)                        // Src = fake IP
            memcpy(p + 16, srcIP, 4)                        // Dst = sender

            // IPv4 header checksum
            var sum: UInt32 = 0
            for i in stride(from: 0, to: 20, by: 2) {
                sum += UInt32(p[i]) << 8 | UInt32(p[i + 1])
            }
            while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16) }
            let ipCksum = ~UInt16(sum)
            p[10] = UInt8(ipCksum >> 8)
            p[11] = UInt8(ipCksum & 0xFF)

            // --- ICMP header (Type 3 = Dest Unreachable, Code 3 = Port Unreachable) ---
            p[20] = 3
            p[21] = 3
            p[22] = 0
            p[23] = 0
            p[24] = 0
            p[25] = 0
            p[26] = 0
            p[27] = 0

            // --- Reconstructed original IPv4 header ---
            let udpTotalLen = 8 + udpPayloadLength
            let innerTotalLen = 20 + udpTotalLen
            p[28] = 0x45
            p[29] = 0x00
            p[30] = UInt8((innerTotalLen >> 8) & 0xFF)
            p[31] = UInt8(innerTotalLen & 0xFF)
            p[32] = 0
            p[33] = 0
            p[34] = 0
            p[35] = 0
            p[36] = 64
            p[37] = 17
            p[38] = 0
            p[39] = 0
            memcpy(p + 40, srcIP, 4)
            memcpy(p + 44, dstIP, 4)

            // --- First 8 bytes of original UDP ---
            p[48] = UInt8(srcPort >> 8)
            p[49] = UInt8(srcPort & 0xFF)
            p[50] = UInt8(dstPort >> 8)
            p[51] = UInt8(dstPort & 0xFF)
            p[52] = UInt8((udpTotalLen >> 8) & 0xFF)
            p[53] = UInt8(udpTotalLen & 0xFF)
            p[54] = 0
            p[55] = 0

            // ICMP checksum (over ICMP header + data, offset 20..55)
            sum = 0
            for i in stride(from: 20, to: packetLen, by: 2) {
                sum += UInt32(p[i]) << 8 | UInt32(p[i + 1])
            }
            while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16) }
            let icmpCksum = ~UInt16(sum)
            p[22] = UInt8(icmpCksum >> 8)
            p[23] = UInt8(icmpCksum & 0xFF)
        }
        return packet
    }

    /// Builds an IPv6 ICMPv6 Destination Unreachable (Type 1, Code 4) packet.
    /// Contains a reconstructed original IPv6+UDP header per RFC 4443.
    private func buildICMPv6PortUnreachable(
        srcIP: UnsafeRawPointer,
        srcPort: UInt16,
        dstIP: UnsafeRawPointer,
        dstPort: UInt16,
        udpPayloadLength: Int
    ) -> Data {
        // Outer IPv6 (40) + ICMPv6 header (8) + inner IPv6 (40) + UDP header (8) = 96
        let icmpLen = 56  // 8 + 40 + 8
        let packetLen = 40 + icmpLen
        var packet = Data(count: packetLen)
        packet.withUnsafeMutableBytes { raw in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!

            // --- Outer IPv6 header (src=fake IP, dst=sender) ---
            p[0] = 0x60; p[1] = 0; p[2] = 0; p[3] = 0
            p[4] = UInt8(icmpLen >> 8)
            p[5] = UInt8(icmpLen & 0xFF)
            p[6] = 58
            p[7] = 64
            memcpy(p + 8, dstIP, 16)
            memcpy(p + 24, srcIP, 16)

            // --- ICMPv6 header (Type 1 = Dest Unreachable, Code 4 = Port Unreachable) ---
            p[40] = 1
            p[41] = 4
            p[42] = 0
            p[43] = 0
            p[44] = 0
            p[45] = 0
            p[46] = 0
            p[47] = 0

            // --- Reconstructed original IPv6 header ---
            let udpTotalLen = 8 + udpPayloadLength
            p[48] = 0x60; p[49] = 0; p[50] = 0; p[51] = 0
            p[52] = UInt8(udpTotalLen >> 8)
            p[53] = UInt8(udpTotalLen & 0xFF)
            p[54] = 17
            p[55] = 64
            memcpy(p + 56, srcIP, 16)
            memcpy(p + 72, dstIP, 16)

            // --- First 8 bytes of original UDP ---
            p[88] = UInt8(srcPort >> 8)
            p[89] = UInt8(srcPort & 0xFF)
            p[90] = UInt8(dstPort >> 8)
            p[91] = UInt8(dstPort & 0xFF)
            p[92] = UInt8((udpTotalLen >> 8) & 0xFF)
            p[93] = UInt8(udpTotalLen & 0xFF)
            p[94] = 0
            p[95] = 0

            // ICMPv6 checksum (includes pseudo-header per RFC 4443 §2.3)
            var sum: UInt32 = 0
            for i in stride(from: 8, to: 24, by: 2) {
                sum += UInt32(p[i]) << 8 | UInt32(p[i + 1])
            }
            for i in stride(from: 24, to: 40, by: 2) {
                sum += UInt32(p[i]) << 8 | UInt32(p[i + 1])
            }
            sum += UInt32(icmpLen)
            sum += 58
            for i in stride(from: 40, to: packetLen, by: 2) {
                sum += UInt32(p[i]) << 8 | UInt32(p[i + 1])
            }
            while sum > 0xFFFF { sum = (sum & 0xFFFF) + (sum >> 16) }
            let cksum = ~UInt16(sum)
            p[42] = UInt8(cksum >> 8)
            p[43] = UInt8(cksum & 0xFF)
        }
        return packet
    }
}
