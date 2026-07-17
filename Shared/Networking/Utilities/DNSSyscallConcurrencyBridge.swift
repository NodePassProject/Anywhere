//
//  DNSSyscallConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation

nonisolated final class DNSSyscallConcurrencyBridge: Sendable {

    private let queue: DispatchQueue = DispatchQueue(
        label: "com.argsment.Anywhere.DNSSyscallConcurrencyBridge",
        qos: .userInitiated,
        attributes: .concurrent
    )
    
    func run<T: Sendable>(_ body: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { continuation in
            queue.async { continuation.resume(returning: body()) }
        }
    }
}
