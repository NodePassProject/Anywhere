//
//  IPRoute.swift
//  Anywhere
//
//  Created by NodePassProject on 9/26/26.
//

import Foundation

nonisolated struct IPRoute: Equatable, Sendable {
    let network: UInt32
    let prefixLength: Int

    var mask: UInt32 { Self.mask(prefixLength: prefixLength) }

    init?(_ string: String) {
        let parts = string.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        var raw = in_addr()
        guard inet_pton(AF_INET, String(parts[0]), &raw) == 1 else { return nil }
        if parts.count == 2 {
            guard let value = Int(parts[1]), (0...32).contains(value) else { return nil }
            prefixLength = value
        } else {
            prefixLength = 32
        }
        network = UInt32(bigEndian: raw.s_addr) & Self.mask(prefixLength: prefixLength)
    }

    private static func mask(prefixLength: Int) -> UInt32 {
        ~UInt32(0) << (32 - prefixLength)
    }
}
