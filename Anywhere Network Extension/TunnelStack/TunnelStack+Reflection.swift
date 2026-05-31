//
//  TunnelStack+Reflection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/31/26.
//

import Foundation

extension TunnelStack {

    // MARK: - Reflection
    //
    // Reflection is a stateless, transport-agnostic IP-layer operation: an
    // inbound packet whose *destination* matches a reflection address has its
    // source and destination addresses swapped and is written straight back
    // into the TUN (``enqueueOutbound``), short-circuiting lwIP / UDP / routing
    // / the proxy entirely. Because we only swap when `dst == reflection
    // address`, the swap is symmetric (new src = old dst = reflection address,
    // new dst = old src), so both legs of a connection hit this branch and
    // reach each other with the reflection address as a mirror — no NAT table,
    // no per-connection state.
    //
    // A pure src⇄dst swap leaves *every* checksum invariant: the IPv4 header
    // checksum (ones-complement sum over the same set of words), and the
    // TCP/UDP/ICMPv6 checksums (src+dst live in the pseudo-header, summed the
    // same either way). ICMPv4 doesn't cover addresses at all. So the
    // reflection rewrites only the address fields and recomputes no checksum.

    /// Immutable set of reflection addresses, published under ``reflectorLock``
    /// on change and read once per inbound batch by ``startReadingPackets``.
    struct Reflector {
        /// IPv4 reflection addresses, each packed big-endian-numerically from
        /// its four header bytes (`b0<<24 | b1<<16 | b2<<8 | b3`) so the
        /// per-packet compare reconstructs the destination the same way.
        let v4: [UInt32]
        /// IPv6 reflection addresses, as their 16 raw header bytes.
        let v6: [SIMD16<UInt8>]

        /// Whether any address is configured. When false, the read loop skips
        /// the reflection check entirely, so a disabled feature costs nothing.
        var isActive: Bool { !v4.isEmpty || !v6.isEmpty }

        static let inactive = Reflector(v4: [], v6: [])

        private init(v4: [UInt32], v6: [SIMD16<UInt8>]) {
            self.v4 = v4
            self.v6 = v6
        }

        /// Parses dotted-quad / colon-hex address strings into the comparison
        /// sets. Blank or unparseable entries are skipped; an all-invalid list
        /// yields ``inactive``.
        init(addresses: [String]) {
            var v4: [UInt32] = []
            var v6: [SIMD16<UInt8>] = []
            for raw in addresses {
                let s = raw.trimmingCharacters(in: .whitespaces)
                guard !s.isEmpty else { continue }
                if s.contains(":") {
                    var a6 = in6_addr()
                    if inet_pton(AF_INET6, s, &a6) == 1 {
                        var bytes = SIMD16<UInt8>()
                        withUnsafeBytes(of: &a6) { buf in
                            for i in 0..<16 { bytes[i] = buf[i] }
                        }
                        v6.append(bytes)
                    }
                } else {
                    var a4 = in_addr()
                    if inet_pton(AF_INET, s, &a4) == 1 {
                        // in_addr holds the address in network (wire) byte order,
                        // matching the header; pack it the same way the compare reads it.
                        let packed: UInt32 = withUnsafeBytes(of: &a4) { buf in
                            UInt32(buf[0]) << 24 | UInt32(buf[1]) << 16 | UInt32(buf[2]) << 8 | UInt32(buf[3])
                        }
                        v4.append(packed)
                    }
                }
            }
            self.v4 = v4
            self.v6 = v6
        }

        /// If `packet`'s destination address matches a reflection address,
        /// returns a copy with source⇄destination swapped — the reflected packet
        /// to write back into the TUN — along with its address family. Returns nil
        /// (no match / too short / unknown version) to let the packet route
        /// normally. Ports, payload, and all checksums are left untouched.
        func reflect(_ packet: Data) -> (data: Data, isIPv6: Bool)? {
            // First borrow: decide whether the destination matches, without
            // copying. nil = no match; false = IPv4 match; true = IPv6 match.
            let match: Bool? = packet.withUnsafeBytes { raw -> Bool? in
                guard let p = raw.bindMemory(to: UInt8.self).baseAddress, raw.count >= 1 else { return nil }
                switch (p[0] >> 4) & 0x0F {
                case 4:
                    guard raw.count >= 20 else { return nil }
                    let dst = UInt32(p[16]) << 24 | UInt32(p[17]) << 16 | UInt32(p[18]) << 8 | UInt32(p[19])
                    return v4.contains(dst) ? false : nil
                case 6:
                    guard raw.count >= 40 else { return nil }
                    var dst = SIMD16<UInt8>()
                    for i in 0..<16 { dst[i] = p[24 + i] }
                    return v6.contains(dst) ? true : nil
                default:
                    return nil
                }
            }
            guard let isIPv6 = match else { return nil }

            // Matched: swap src⇄dst on a copy. IPv4 src [12,16) ⇄ dst [16,20);
            // IPv6 src [8,24) ⇄ dst [24,40).
            var out = packet
            out.withUnsafeMutableBytes { raw in
                guard let p = raw.bindMemory(to: UInt8.self).baseAddress else { return }
                if isIPv6 {
                    for i in 0..<16 { swap(&p[8 + i], &p[24 + i]) }
                } else {
                    for i in 0..<4 { swap(&p[12 + i], &p[16 + i]) }
                }
            }
            return (out, isIPv6)
        }
    }
}
