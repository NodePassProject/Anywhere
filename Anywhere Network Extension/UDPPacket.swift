//
//  UDPPacket.swift
//  Anywhere
//
//  Created by NodePassProject on 5/23/26.
//

import Foundation

/// Parses inbound IP+UDP datagrams arriving from the TUN interface and builds
/// outbound ones, replacing lwIP's UDP path entirely.
///
/// UDP is connectionless, so all flow state (NAT, idle timeout, routing,
/// fake-IP, proxy association) already lives in Swift (``UDPFlow`` /
/// ``TunnelStack/udpFlows``). lwIP only ever contributed header parse-on-input
/// and header-build-on-output — both done here instead, which lets the
/// vendored lwIP build TCP-only (`LWIP_UDP 0`). The hand-built output path
/// mirrors the ICMP packet builder in ``TunnelStack`` (`+ICMP`).
enum UDPPacket {

    static let ipProtocolUDP: UInt8 = 17

    /// A parsed inbound UDP datagram. `srcIP`/`dstIP` are the raw address bytes
    /// held inline (zero-padded; IPv4 occupies the first 4) so the per-packet
    /// flow lookup keys on them with no heap allocation. `payload` is a fresh
    /// copy of the UDP data (the one copy the old `udp_recv_cb` made too).
    struct Inbound {
        let isIPv6: Bool
        let srcIP: SIMD16<UInt8>
        let srcPort: UInt16
        let dstIP: SIMD16<UInt8>
        let dstPort: UInt16
        let payload: Data

        /// Address width in bytes (4 for IPv4, 16 for IPv6).
        var addrLen: Int { isIPv6 ? 16 : 4 }
        /// Source/destination address as `Data`, sized to the family. Allocates
        /// on access — only the cold paths (DNS, ICMP, new-flow creation) need
        /// it; the per-packet fast path keys on the inline bytes directly.
        var srcIPData: Data { UDPPacket.ipData(srcIP, count: addrLen) }
        var dstIPData: Data { UDPPacket.ipData(dstIP, count: addrLen) }
    }

    /// Reads the IP version + transport protocol from a packet's fixed header,
    /// or returns nil for an unrecognised version / too-short buffer. Cheap
    /// enough for the per-packet TCP-vs-UDP routing decision in the read loop.
    static func ipProtocol(of packet: Data) -> (isIPv6: Bool, proto: UInt8)? {
        packet.withUnsafeBytes { raw -> (Bool, UInt8)? in
            guard let p = raw.bindMemory(to: UInt8.self).baseAddress else { return nil }
            let len = raw.count
            guard len >= 1 else { return nil }
            switch (p[0] >> 4) & 0x0F {
            case 4: return len >= 20 ? (false, p[9]) : nil
            case 6: return len >= 40 ? (true, p[6]) : nil
            default: return nil
            }
        }
    }

    /// Parses a UDP datagram into its 5-tuple + payload.
    ///
    /// Returns nil (drop) for fragments, IPv6 extension headers, non-UDP, or
    /// malformed/short packets. This matches lwIP's reassembly-off posture
    /// (`IP_REASSEMBLY` / `LWIP_IPV6_REASS` both 0 in lwipopts.h), under which
    /// such packets were already dropped — so there is no behavioural change,
    /// only the drop now happens here instead of inside lwIP.
    static func parse(_ packet: Data) -> Inbound? {
        packet.withUnsafeBytes { raw -> Inbound? in
            guard let p = raw.bindMemory(to: UInt8.self).baseAddress else { return nil }
            let len = raw.count
            guard len >= 1 else { return nil }

            switch (p[0] >> 4) & 0x0F {
            case 4:
                guard len >= 20 else { return nil }
                let ihl = Int(p[0] & 0x0F) * 4
                guard ihl >= 20, len >= ihl + 8, p[9] == ipProtocolUDP else { return nil }
                // Drop fragments (MF set or non-zero fragment offset): with
                // IP_REASSEMBLY=0 lwIP never reassembled them, and delivering a
                // single fragment as a whole datagram would be wrong.
                let fragWord = (UInt16(p[6]) << 8) | UInt16(p[7])
                guard fragWord & 0x3FFF == 0 else { return nil }
                return finish(p, len: len, headerLen: ihl, isIPv6: false,
                              srcOffset: 12, dstOffset: 16, addrLen: 4)
            case 6:
                // Only bare UDP (next-header 17). Extension headers — including
                // the IPv6 Fragment header (44) — are dropped: with
                // LWIP_IPV6_REASS=0 lwIP wouldn't reassemble, and all real UDP
                // traffic we carry (QUIC, DNS) uses no extension headers.
                guard len >= 48, p[6] == ipProtocolUDP else { return nil }
                return finish(p, len: len, headerLen: 40, isIPv6: true,
                              srcOffset: 8, dstOffset: 24, addrLen: 16)
            default:
                return nil
            }
        }
    }

    private static func finish(_ p: UnsafePointer<UInt8>, len: Int, headerLen: Int,
                               isIPv6: Bool, srcOffset: Int, dstOffset: Int,
                               addrLen: Int) -> Inbound? {
        let u = p + headerLen
        let srcPort = (UInt16(u[0]) << 8) | UInt16(u[1])
        let dstPort = (UInt16(u[2]) << 8) | UInt16(u[3])
        let udpLen = Int((UInt16(u[4]) << 8) | UInt16(u[5]))
        // The UDP length field counts its own 8-byte header; a value below 8 is
        // malformed (lwIP's udp_input dropped these). Clamp the upper bound to the
        // bytes that actually arrived so a bogus length can't over-read the buffer.
        guard udpLen >= 8 else { return nil }
        let payloadLen = min(udpLen, len - headerLen) - 8
        return Inbound(
            isIPv6: isIPv6,
            srcIP: loadIP(p + srcOffset, addrLen),
            srcPort: srcPort,
            dstIP: loadIP(p + dstOffset, addrLen),
            dstPort: dstPort,
            payload: Data(bytes: u + 8, count: payloadLen)
        )
    }

    // MARK: - Inline address storage

    /// Loads `len` address bytes from `p` into zero-padded inline storage.
    private static func loadIP(_ p: UnsafePointer<UInt8>, _ len: Int) -> SIMD16<UInt8> {
        var v = SIMD16<UInt8>()
        withUnsafeMutableBytes(of: &v) { $0.baseAddress!.copyMemory(from: p, byteCount: len) }
        return v
    }

    /// Loads up to 16 address bytes from `data` into zero-padded inline storage.
    /// Used by cold paths (e.g. DNS forwarding) that hold the address as `Data`.
    static func loadIP(_ data: Data) -> SIMD16<UInt8> {
        var v = SIMD16<UInt8>()
        let n = min(data.count, 16)
        guard n > 0 else { return v }
        withUnsafeMutableBytes(of: &v) { dst in
            data.withUnsafeBytes { src in dst.baseAddress!.copyMemory(from: src.baseAddress!, byteCount: n) }
        }
        return v
    }

    /// Extracts the leading `count` bytes of inline address storage as `Data`.
    static func ipData(_ v: SIMD16<UInt8>, count: Int) -> Data {
        withUnsafeBytes(of: v) { Data(bytes: $0.baseAddress!, count: count) }
    }

    /// Builds a complete IPv4/IPv6 UDP packet (header + checksum + payload)
    /// ready for `NEPacketTunnelFlow.writePackets`. `srcIP`/`dstIP` are the
    /// response packet's own source/destination as raw bytes matching
    /// `isIPv6`. Returns nil for a mismatched address length or an
    /// over-MTU-of-UDP payload (>65527 bytes — a single datagram can't exceed
    /// it, and lwIP's IP_FRAG=0 build never fragmented either).
    static func build(srcIP: Data, srcPort: UInt16,
                      dstIP: Data, dstPort: UInt16,
                      isIPv6: Bool, payload: Data) -> Data? {
        let addrLen = isIPv6 ? 16 : 4
        guard srcIP.count == addrLen, dstIP.count == addrLen else { return nil }
        let udpLen = 8 + payload.count
        guard udpLen <= 0xFFFF else { return nil }

        return isIPv6
            ? buildV6(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, payload: payload, udpLen: udpLen)
            : buildV4(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, payload: payload, udpLen: udpLen)
    }

    private static func buildV4(srcIP: Data, srcPort: UInt16,
                                dstIP: Data, dstPort: UInt16,
                                payload: Data, udpLen: Int) -> Data {
        let total = 20 + udpLen
        var pkt = Data(count: total)
        pkt.withUnsafeMutableBytes { raw in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!

            // --- IPv4 header ---
            p[0] = 0x45                                  // Version 4, IHL 5
            p[1] = 0x00                                  // DSCP/ECN
            p[2] = UInt8(total >> 8); p[3] = UInt8(total & 0xFF)
            p[4] = 0; p[5] = 0                           // Identification
            p[6] = 0; p[7] = 0                           // Flags + fragment offset
            p[8] = 64                                    // TTL
            p[9] = ipProtocolUDP                         // Protocol: UDP
            p[10] = 0; p[11] = 0                         // Header checksum (below)
            srcIP.copyBytes(to: p + 12, count: 4)
            dstIP.copyBytes(to: p + 16, count: 4)

            writeUDP(p, udpStart: 20, srcPort: srcPort, dstPort: dstPort, udpLen: udpLen, payload: payload)

            // IPv4 header checksum (0 is a valid result; no all-ones rule here)
            let ipck = fold(sum(p, 0, 20))
            p[10] = UInt8(ipck >> 8); p[11] = UInt8(ipck & 0xFF)

            // UDP checksum: pseudo-header (src+dst+proto+len) + UDP header + payload
            let psum = sum(p, 12, 20) + UInt32(ipProtocolUDP) + UInt32(udpLen) + sum(p, 20, total)
            var udpck = fold(psum)
            if udpck == 0 { udpck = 0xFFFF }             // 0 means "no checksum"; send all-ones
            p[26] = UInt8(udpck >> 8); p[27] = UInt8(udpck & 0xFF)
        }
        return pkt
    }

    private static func buildV6(srcIP: Data, srcPort: UInt16,
                                dstIP: Data, dstPort: UInt16,
                                payload: Data, udpLen: Int) -> Data {
        let total = 40 + udpLen
        var pkt = Data(count: total)
        pkt.withUnsafeMutableBytes { raw in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!

            // --- IPv6 header (no header checksum in IPv6) ---
            p[0] = 0x60; p[1] = 0; p[2] = 0; p[3] = 0    // Version 6, TC/flow 0
            p[4] = UInt8(udpLen >> 8); p[5] = UInt8(udpLen & 0xFF)  // Payload length
            p[6] = ipProtocolUDP                          // Next header: UDP
            p[7] = 64                                     // Hop limit
            srcIP.copyBytes(to: p + 8, count: 16)
            dstIP.copyBytes(to: p + 24, count: 16)

            writeUDP(p, udpStart: 40, srcPort: srcPort, dstPort: dstPort, udpLen: udpLen, payload: payload)

            // UDP checksum is mandatory over IPv6. Pseudo-header per RFC 8200
            // §8.1: src(16) + dst(16) + upper-layer length + next header.
            let psum = sum(p, 8, 40) + UInt32(udpLen) + UInt32(ipProtocolUDP) + sum(p, 40, total)
            var udpck = fold(psum)
            if udpck == 0 { udpck = 0xFFFF }
            p[46] = UInt8(udpck >> 8); p[47] = UInt8(udpck & 0xFF)
        }
        return pkt
    }

    /// Writes the 8-byte UDP header (checksum left zero) and payload at
    /// `udpStart`. The checksum is patched in by the caller after the
    /// pseudo-header sum is known.
    private static func writeUDP(_ p: UnsafeMutablePointer<UInt8>, udpStart: Int,
                                 srcPort: UInt16, dstPort: UInt16, udpLen: Int, payload: Data) {
        p[udpStart + 0] = UInt8(srcPort >> 8); p[udpStart + 1] = UInt8(srcPort & 0xFF)
        p[udpStart + 2] = UInt8(dstPort >> 8); p[udpStart + 3] = UInt8(dstPort & 0xFF)
        p[udpStart + 4] = UInt8(udpLen >> 8);  p[udpStart + 5] = UInt8(udpLen & 0xFF)
        p[udpStart + 6] = 0; p[udpStart + 7] = 0   // checksum placeholder
        if !payload.isEmpty {
            payload.copyBytes(to: p + udpStart + 8, count: payload.count)
        }
    }

    /// Sums 16-bit big-endian words over `p[start..<end]` for the Internet
    /// checksum (RFC 1071). A trailing odd byte is treated as the high byte of
    /// a zero-padded word.
    private static func sum(_ p: UnsafePointer<UInt8>, _ start: Int, _ end: Int) -> UInt32 {
        var acc: UInt32 = 0
        var i = start
        while i + 1 < end { acc += (UInt32(p[i]) << 8) | UInt32(p[i + 1]); i += 2 }
        if i < end { acc += UInt32(p[i]) << 8 }
        return acc
    }

    /// Folds a 32-bit checksum accumulator into the one's-complement 16-bit
    /// result.
    private static func fold(_ acc: UInt32) -> UInt16 {
        var s = acc
        while s > 0xFFFF { s = (s & 0xFFFF) + (s >> 16) }
        return ~UInt16(s & 0xFFFF)
    }
}
