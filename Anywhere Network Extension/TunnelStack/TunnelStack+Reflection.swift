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
    // Stateless src⇄dst swap written back into the TUN; symmetric, so both legs
    // hit this branch with no NAT table. A pure swap leaves every checksum
    // valid: the IPv4 header sums the same words, TCP/UDP/ICMPv6 pseudo-headers
    // sum src+dst either way, and ICMPv4 doesn't cover addresses.

    /// Published under ``reflectorLock`` on change, read once per inbound batch.
    struct Reflector {
        /// Packed `b0<<24 | b1<<16 | b2<<8 | b3`, matching the per-packet compare.
        let v4: [UInt32]
        let v6: [SIMD16<UInt8>]

        var isActive: Bool { !v4.isEmpty || !v6.isEmpty }

        static let inactive = Reflector(v4: [], v6: [])

        private init(v4: [UInt32], v6: [SIMD16<UInt8>]) {
            self.v4 = v4
            self.v6 = v6
        }

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
                        withUnsafeBytes(of: &a6) { buffer in
                            for i in 0..<16 { bytes[i] = buffer[i] }
                        }
                        v6.append(bytes)
                    }
                } else {
                    var a4 = in_addr()
                    if inet_pton(AF_INET, s, &a4) == 1 {
                        // in_addr is network byte order, matching the header.
                        let packed: UInt32 = withUnsafeBytes(of: &a4) { buffer in
                            UInt32(buffer[0]) << 24 | UInt32(buffer[1]) << 16 | UInt32(buffer[2]) << 8 | UInt32(buffer[3])
                        }
                        v4.append(packed)
                    }
                }
            }
            self.v4 = v4
            self.v6 = v6
        }

        /// Returns a src⇄dst-swapped copy if the destination matches; nil routes
        /// normally. Ports, payload, and checksums are untouched.
        func reflect(_ packet: Data) -> (data: Data, isIPv6: Bool)? {
            // nil = no match; false = IPv4 match; true = IPv6 match.
            let match: Bool? = packet.withUnsafeBytes { raw -> Bool? in
                guard let p = raw.bindMemory(to: UInt8.self).baseAddress, raw.count >= 1 else { return nil }
                switch (p[0] >> 4) & 0x0F {
                case 4:
                    guard raw.count >= 20 else { return nil }
                    let destination = UInt32(p[16]) << 24 | UInt32(p[17]) << 16 | UInt32(p[18]) << 8 | UInt32(p[19])
                    return v4.contains(destination) ? false : nil
                case 6:
                    guard raw.count >= 40 else { return nil }
                    var destination = SIMD16<UInt8>()
                    for i in 0..<16 { destination[i] = p[24 + i] }
                    return v6.contains(destination) ? true : nil
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
