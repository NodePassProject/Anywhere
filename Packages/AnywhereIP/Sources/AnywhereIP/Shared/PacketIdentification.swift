//
//  PacketIdentification.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Synchronization

enum PacketIdentification {
    private static let value = Atomic<UInt16>(0)
    static func next() -> UInt16 { value.wrappingAdd(1, ordering: .relaxed).oldValue }
}
