//
//  DownlinkByteGate.swift
//  Anywhere
//
//  Created by NodePassProject on 11/3/26.
//

import Foundation
import Synchronization

nonisolated final class DownlinkByteGate: Sendable {

    // MARK: - Lease

    final class Lease: Sendable {
        private let gate: DownlinkByteGate
        private let held = Mutex(0)

        fileprivate init(gate: DownlinkByteGate) {
            self.gate = gate
        }

        deinit {
            releaseAll()
        }

        func reserve(_ bytes: Int) async -> Bool {
            guard bytes > 0 else { return true }
            guard await gate.reserve(bytes) else { return false }
            held.withLock { $0 += bytes }
            return true
        }

        func release(_ bytes: Int) {
            let freed = held.withLock { held -> Int in
                let freed = min(held, max(0, bytes))
                held -= freed
                return freed
            }
            gate.release(freed)
        }

        func releaseAll() {
            let freed = held.withLock { held -> Int in
                defer { held = 0 }
                return held
            }
            gate.release(freed)
        }
    }

    // MARK: - State

    private struct Waiter {
        let id: UInt64
        let bytes: Int
        let continuation: CheckedContinuation<Bool, Never>
    }

    private struct State {
        var used = 0
        var waiters: [Waiter] = []
        var nextWaiterID: UInt64 = 0
    }

    private let state = Mutex(State())
    private let budget: Int

    init(budget: Int) {
        self.budget = max(1, budget)
    }

    var budgetBytes: Int { budget }
    var usedBytes: Int { state.withLock { $0.used } }

    func makeLease() -> Lease {
        Lease(gate: self)
    }

    // MARK: - Admission

    private func admits(_ bytes: Int, in state: State) -> Bool {
        state.used == 0 || state.used + bytes <= budget
    }

    fileprivate func reserve(_ bytes: Int) async -> Bool {
        let (admitted, id): (Bool, UInt64) = state.withLock { state in
            if state.waiters.isEmpty, admits(bytes, in: state) {
                state.used += bytes
                return (true, 0)
            }
            state.nextWaiterID &+= 1
            return (false, state.nextWaiterID)
        }
        if admitted { return true }

        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                let immediate: Bool? = state.withLock { state in
                    if Task.isCancelled { return false }
                    if state.waiters.isEmpty, admits(bytes, in: state) {
                        state.used += bytes
                        return true
                    }
                    state.waiters.append(Waiter(id: id, bytes: bytes, continuation: continuation))
                    return nil
                }
                if let immediate { continuation.resume(returning: immediate) }
            }
        } onCancel: {
            let (cancelled, granted): (Waiter?, [Waiter]) = state.withLock { state in
                guard let index = state.waiters.firstIndex(where: { $0.id == id }) else { return (nil, []) }
                let cancelled = state.waiters.remove(at: index)
                return (cancelled, grantWaiters(&state))
            }
            cancelled?.continuation.resume(returning: false)
            for waiter in granted { waiter.continuation.resume(returning: true) }
        }
    }

    fileprivate func release(_ bytes: Int) {
        guard bytes > 0 else { return }
        let granted: [Waiter] = state.withLock { state in
            state.used = max(0, state.used - bytes)
            return grantWaiters(&state)
        }
        for waiter in granted { waiter.continuation.resume(returning: true) }
    }

    private func grantWaiters(_ state: inout State) -> [Waiter] {
        var granted: [Waiter] = []
        while let next = state.waiters.first, admits(next.bytes, in: state) {
            state.used += next.bytes
            granted.append(state.waiters.removeFirst())
        }
        return granted
    }
}
