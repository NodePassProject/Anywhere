//
//  BlockingSyscallConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation

nonisolated final class BlockingSyscallConcurrencyBridge: Sendable {

    private let queue: DispatchQueue

    init(label: String) {
        self.queue = DispatchQueue(label: label, qos: .userInitiated, attributes: .concurrent)
    }
    
    func run<T: Sendable>(_ body: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { continuation in
            queue.async { continuation.resume(returning: body()) }
        }
    }
}
