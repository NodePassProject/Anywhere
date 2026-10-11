//
//  ConnectionKey.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

struct ConnectionKey: Hashable, Sendable {
    let remote: IPEndpoint
    let local: IPEndpoint
    let fingerprint: UInt64

    init(remote: IPEndpoint, local: IPEndpoint) {
        self.remote = remote
        self.local = local
        let ports = (UInt64(remote.port) << 16 | UInt64(local.port)) &* 0x9E37_79B9_7F4A_7C15
        switch (remote.address, local.address) {
        case (.v4(let remote), .v4(let local)):
            fingerprint = Self.mix(ports ^ (UInt64(remote.rawValue) << 32 | UInt64(local.rawValue)))
        case (.v6(let remote), .v6(let local)):
            fingerprint = Self.mix(Self.mix(Self.mix(Self.mix(ports ^ remote.high) ^ remote.low) ^ local.high) ^ local.low)
        default:
            fingerprint = Self.mix(ports)
        }
    }

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.fingerprint == rhs.fingerprint && lhs.remote == rhs.remote && lhs.local == rhs.local
    }

    func hash(into hasher: inout Hasher) { hasher.combine(fingerprint) }

    private static func mix(_ value: UInt64) -> UInt64 {
        var z = value
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
