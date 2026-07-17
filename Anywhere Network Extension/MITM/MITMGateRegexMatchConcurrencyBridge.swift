//
//  MITMGateRegexMatchConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation

nonisolated final class MITMGateRegexMatchConcurrencyBridge: @unchecked Sendable {
    
    static let shared = MITMGateRegexMatchConcurrencyBridge()
    
    private let queue: DispatchQueue = DispatchQueue(
        label: "com.argsment.Anywhere.MITMGateRegexMatchConcurrencyBridge",
        qos: .userInitiated,
        attributes: .concurrent
    )
    
    enum Outcome<T> {
        case completed(T)
        case timedOut
    }
    
    private final class Slot<T>: @unchecked Sendable {
        var value: T?
    }
    
    func runBounded<T: Sendable>(
        deadlineMillis: Int,
        hardCapSeconds: Int,
        hardCapMessage: @escaping @Sendable () -> String,
        _ body: @escaping @Sendable () -> T
    ) -> Outcome<T> {
        let slot = Slot<T>()
        let done = DispatchSemaphore(value: 0)
        queue.async {
            slot.value = body()
            done.signal()
        }
        guard done.wait(timeout: .now() + .milliseconds(deadlineMillis)) == .success else {
            scheduleHardCapCheck(done, hardCapSeconds: hardCapSeconds, message: hardCapMessage)
            return .timedOut
        }
        // `done` succeeded ⇒ `body()` ran and published `slot.value` before signalling.
        return .completed(slot.value!)
    }
    
    private func scheduleHardCapCheck(
        _ done: DispatchSemaphore,
        hardCapSeconds: Int,
        message: @escaping @Sendable () -> String
    ) {
        Task.detached(priority: .utility) {
            try? await Task.sleep(for: .seconds(hardCapSeconds))
            guard done.wait(timeout: .now()) != .success else { return }
            fatalError(message())
        }
    }
}
