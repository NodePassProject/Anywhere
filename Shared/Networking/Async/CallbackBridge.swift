//
//  CallbackBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Synchronization

// MARK: - CallbackBridge

// Bridges the codebase's completion-handler APIs to `async`/`await`. These
// primitives are the shared spine: an async caller awaits a callback API through
// `awaitCallback`, while a `PendingResumer` fails whichever await is in flight
// when the owning task is cancelled. Kept `nonisolated` and thread-safe via
// `Mutex` so the off-main transport layer can use them without hopping to the main
// actor (the module defaults to `MainActor` isolation).

/// Cancellation hook that fails whichever phase is currently awaiting.
nonisolated final class PendingResumer: @unchecked Sendable {
    private let hook = Mutex<((Error) -> Void)?>(nil)

    func install(_ hook: @escaping (Error) -> Void) {
        self.hook.withLock { $0 = hook }
    }

    func clear() {
        hook.withLock { $0 = nil }
    }

    func cancel() {
        // Take the hook out under the lock; invoke it outside.
        let capturedHook = hook.withLock { hook -> ((Error) -> Void)? in
            let captured = hook
            hook = nil
            return captured
        }
        capturedHook?(CancellationError())
    }
}

/// One-shot continuation wrapper; the second resume is a no-op, so a cancel
/// during a hung send/receive can't double-resume or leak the continuation.
nonisolated final class OneShotResumer<T>: @unchecked Sendable {
    private let continuation = Mutex<CheckedContinuation<T, Error>?>(nil)

    func arm(_ continuation: CheckedContinuation<T, Error>) {
        self.continuation.withLock { $0 = continuation }
    }

    func resume(_ result: Result<T, Error>) {
        // Take the continuation out under the lock; resume it outside.
        let snapshotContinuation = continuation.withLock { continuation -> CheckedContinuation<T, Error>? in
            let snapshot = continuation
            continuation = nil
            return snapshot
        }
        snapshotContinuation?.resume(with: result)
    }
}

/// Bridges a callback to async/await; the continuation resumes exactly once,
/// from either the callback or the cancellation hook.
nonisolated func awaitCallback<T>(
    resumer pending: PendingResumer,
    operation: (@escaping (Result<T, Error>) -> Void) -> Void
) async throws -> T {
    let oneShot = OneShotResumer<T>()
    return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, Error>) in
        oneShot.arm(continuation)
        pending.install { error in
            oneShot.resume(.failure(error))
        }
        if Task.isCancelled {
            pending.clear()
            oneShot.resume(.failure(CancellationError()))
            return
        }
        operation { result in
            pending.clear()
            oneShot.resume(result)
        }
    }
}
