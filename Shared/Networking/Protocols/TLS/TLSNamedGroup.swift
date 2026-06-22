//
//  TLSNamedGroup.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

nonisolated enum TLSNamedGroup {
    static let secp256: UInt16 = 0x0017
    static let secp384: UInt16 = 0x0018
    static let x25519: UInt16 = 0x001D
    static let x25519MLKEM768: UInt16 = 0x11EC
}
