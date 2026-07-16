//
//  AsyncMutex.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation
import Synchronization

nonisolated final class AsyncMutex: Sendable {

    private struct State {
        var locked = false
        var waiters: [CheckedContinuation<Void, Never>] = []
    }

    private let state = Mutex(State())

    /// Runs `body` while holding the lock, releasing it (via `defer`) even if `body`
    /// throws or is cancelled. Non-`throws` bodies keep `withLock` non-`throws`.
    func withLock<T>(_ body: () async throws -> T) async rethrows -> T {
        await acquire()
        defer { release() }
        return try await body()
    }

    private func acquire() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let acquiredImmediately = state.withLock { state -> Bool in
                if !state.locked {
                    state.locked = true
                    return true
                }
                state.waiters.append(continuation)
                return false
            }
            if acquiredImmediately { continuation.resume() }
        }
    }

    private func release() {
        let next: CheckedContinuation<Void, Never>? = state.withLock { state in
            if state.waiters.isEmpty {
                state.locked = false
                return nil
            }
            // Hand the lock straight to the next waiter — stays `locked`.
            return state.waiters.removeFirst()
        }
        next?.resume()
    }
}
