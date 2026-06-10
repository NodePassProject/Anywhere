//
//  UDPPacket.swift
//  Anywhere
//
//  Created by NodePassProject on 5/23/26.
//

import Foundation

/// Parses inbound IP+UDP datagrams from the TUN interface and builds outbound
/// ones, replacing lwIP's UDP path entirely (the vendored lwIP builds with `LWIP_UDP 0`).
enum UDPPacket {

    static let ipProtocolUDP: UInt8 = 17

    /// A parsed inbound UDP datagram. Addresses are zero-padded inline bytes so
    /// the per-packet flow lookup allocates nothing; `payload` is a fresh copy.
    struct Inbound {
        let isIPv6: Bool
        let srcIP: SIMD16<UInt8>
        let srcPort: UInt16
        let dstIP: SIMD16<UInt8>
        let dstPort: UInt16
        let payload: Data

        var addrLen: Int { isIPv6 ? 16 : 4 }
        /// Family-sized address as `Data`; allocates on access, so only cold paths use it.
        var srcIPData: Data { UDPPacket.ipData(srcIP, count: addrLen) }
        var dstIPData: Data { UDPPacket.ipData(dstIP, count: addrLen) }
    }

    /// Reads the IP version + transport protocol, or nil for an unrecognised
    /// version or too-short buffer.
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

    /// Parses a UDP datagram into its 5-tuple + payload. Returns nil (drop) for
    /// fragments, IPv6 extension headers, non-UDP, or malformed packets — matching
    /// lwIP's reassembly-off posture (`IP_REASSEMBLY` / `LWIP_IPV6_REASS` both 0).
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
                // Drop fragments (MF set or non-zero offset); delivering a single
                // fragment as a whole datagram would be wrong.
                let fragWord = (UInt16(p[6]) << 8) | UInt16(p[7])
                guard fragWord & 0x3FFF == 0 else { return nil }
                return finish(p, len: len, headerLen: ihl, isIPv6: false,
                              srcOffset: 12, dstOffset: 16, addrLen: 4)
            case 6:
                // Bare UDP only (next-header 17); extension headers, including the
                // Fragment header (44), are dropped.
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
        // The UDP length field counts its own 8-byte header, so below 8 is malformed.
        // Clamp to the bytes that arrived so a bogus length can't over-read.
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

    /// Builds a complete IPv4/IPv6 UDP packet (header + checksum + payload) ready for
    /// writePackets. Returns nil for a mismatched address length or a payload over
    /// 65527 bytes (a single datagram's limit; lwIP's IP_FRAG=0 build never fragmented either).
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

            // UDP checksum is mandatory over IPv6; pseudo-header per RFC 8200 §8.1.
            let psum = sum(p, 8, 40) + UInt32(udpLen) + UInt32(ipProtocolUDP) + sum(p, 40, total)
            var udpck = fold(psum)
            if udpck == 0 { udpck = 0xFFFF }
            p[46] = UInt8(udpck >> 8); p[47] = UInt8(udpck & 0xFF)
        }
        return pkt
    }

    /// Writes the 8-byte UDP header (checksum zero, patched by the caller) and
    /// payload at `udpStart`.
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

    /// Sums big-endian 16-bit words for the Internet checksum (RFC 1071); a
    /// trailing odd byte is the high byte of a zero-padded word.
    private static func sum(_ p: UnsafePointer<UInt8>, _ start: Int, _ end: Int) -> UInt32 {
        var acc: UInt32 = 0
        var i = start
        while i + 1 < end { acc += (UInt32(p[i]) << 8) | UInt32(p[i + 1]); i += 2 }
        if i < end { acc += UInt32(p[i]) << 8 }
        return acc
    }

    /// Folds a 32-bit accumulator into the one's-complement 16-bit checksum.
    private static func fold(_ acc: UInt32) -> UInt16 {
        var s = acc
        while s > 0xFFFF { s = (s & 0xFFFF) + (s >> 16) }
        return ~UInt16(s & 0xFFFF)
    }
}
