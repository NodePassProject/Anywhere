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
    // Stateless IP-layer mirror: a packet whose destination matches a
    // reflection address gets src⇄dst swapped and written straight back into
    // the TUN. The swap is symmetric, so both legs of a connection hit this
    // branch — no NAT table. A pure src⇄dst swap leaves every checksum valid:
    // the IPv4 header sums the same words, TCP/UDP/ICMPv6 pseudo-headers sum
    // src+dst either way, and ICMPv4 doesn't cover addresses.

    /// Immutable set of reflection addresses, published under ``reflectorLock``
    /// on change and read once per inbound batch.
    struct Reflector {
        /// IPv4 addresses packed `b0<<24 | b1<<16 | b2<<8 | b3` — the same way
        /// the per-packet compare reconstructs the destination.
        let v4: [UInt32]
        /// IPv6 addresses as their 16 raw header bytes.
        let v6: [SIMD16<UInt8>]

        var isActive: Bool { !v4.isEmpty || !v6.isEmpty }

        static let inactive = Reflector(v4: [], v6: [])

        private init(v4: [UInt32], v6: [SIMD16<UInt8>]) {
            self.v4 = v4
            self.v6 = v6
        }

        /// Parses address strings; blank or unparseable entries are skipped.
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
                        // in_addr is network byte order, matching the header;
                        // pack it the same way the compare reads it.
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

        /// Returns a src⇄dst-swapped copy if the packet's destination matches a
        /// reflection address; nil lets the packet route normally. Ports,
        /// payload, and checksums are untouched.
        func reflect(_ packet: Data) -> (data: Data, isIPv6: Bool)? {
            // Borrow first to decide without copying.
            // nil = no match; false = IPv4 match; true = IPv6 match.
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

            // Swap on a copy: IPv4 src [12,16) ⇄ dst [16,20); IPv6 src [8,24) ⇄ dst [24,40).
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
