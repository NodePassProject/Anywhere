//
//  AsyncMutex.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation
import Synchronization

// MARK: - AsyncMutex

/// A FIFO async mutex: serializes async critical sections that must stay mutually
/// exclusive *across* an `await` — where a synchronous lock (`UnfairLock`/`Mutex`)
/// can't be held, because you may not suspend while holding it.
///
/// This is the async replacement for the `writeLock.withLock { … blocking I/O … }`
/// pattern the Sudoku core used: a full send (`SudokuRecordStream.send` and friends)
/// mutates sequence/RNG state and must emit contiguous bytes, so the whole method —
/// including the wire `await` — is one critical section. An `actor` cannot express
/// this (reentrancy would interleave two sends across the `await`); a serial send
/// *pump* can, but its teardown abandons in-flight jobs, so a caller awaiting a
/// dropped job would hang. A plain FIFO mutex is the faithful, leak-free translation.
///
/// Cancellation: acquisition does **not** abort on cancel — a waiter stays queued
/// until the lock is handed to it, then the critical-section body observes
/// cancellation and unwinds normally (releasing via `defer`). This is deadlock-free
/// because every holder releases via `defer` in bounded time (on teardown the
/// underlying transport is cancelled, so the holder's I/O unwinds promptly), and it
/// is leak-free because a queued waiter's continuation is always resumed on handoff.
/// The guarantee that matters — *the lock is never left held* — always holds.
nonisolated final class AsyncMutex: @unchecked Sendable {

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
