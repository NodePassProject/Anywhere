//
//  BufferBudget.swift
//  AnywhereIP
//
//  Created by NodePassProject on 10/11/26.
//

import Synchronization

final class BufferBudget: Sendable {
    private let remaining: Atomic<Int>

    init(bytes: Int) {
        remaining = Atomic(max(0, bytes))
    }

    func reserve(_ bytes: Int) -> Bool {
        var current = remaining.load(ordering: .relaxed)
        while current >= bytes {
            let (exchanged, original) = remaining.compareExchange(expected: current, desired: current - bytes, ordering: .relaxed)
            if exchanged { return true }
            current = original
        }
        return false
    }

    func release(_ bytes: Int) {
        guard bytes > 0 else { return }
        remaining.wrappingAdd(bytes, ordering: .relaxed)
    }
}

struct GrowthPolicy: Sendable {
    let budget: BufferBudget
    let maximumWindow: UInt32
    let maximumSendBuffer: UInt32
}
