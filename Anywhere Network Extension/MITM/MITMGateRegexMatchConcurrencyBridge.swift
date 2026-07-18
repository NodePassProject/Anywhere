//
//  MITMGateRegexMatchConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation
import Synchronization

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

    /// Shared completion flag: `body()` publishes `true` before signalling. The async hard-cap
    /// check reads this instead of the semaphore, which is unavailable from an async context.
    private final class DoneFlag: Sendable {
        let finished = Atomic<Bool>(false)
    }

    func runBounded<T: Sendable>(
        deadlineMillis: Int,
        hardCapSeconds: Int,
        hardCapMessage: @escaping @Sendable () -> String,
        _ body: @escaping @Sendable () -> T
    ) -> Outcome<T> {
        let slot = Slot<T>()
        let done = DispatchSemaphore(value: 0)
        let flag = DoneFlag()
        queue.async {
            slot.value = body()
            flag.finished.store(true, ordering: .sequentiallyConsistent)
            done.signal()
        }
        // Synchronous bounded wait: this is the sanctioned blocking call, in a non-async function.
        guard done.wait(timeout: .now() + .milliseconds(deadlineMillis)) == .success else {
            scheduleHardCapCheck(flag, hardCapSeconds: hardCapSeconds, message: hardCapMessage)
            return .timedOut
        }
        // `done` succeeded ⇒ `body()` ran and published `slot.value` before signalling.
        return .completed(slot.value!)
    }

    private func scheduleHardCapCheck(
        _ flag: DoneFlag,
        hardCapSeconds: Int,
        message: @escaping @Sendable () -> String
    ) {
        Task.detached(priority: .utility) {
            try? await Task.sleep(for: .seconds(hardCapSeconds))
            // A worker still pinned by catastrophic backtracking never published `finished`.
            guard !flag.finished.load(ordering: .sequentiallyConsistent) else { return }
            fatalError(message())
        }
    }
}
