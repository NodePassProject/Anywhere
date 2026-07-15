//
//  CallbackBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Synchronization

// MARK: - CallbackBridge

// The async-primary migration has retired the general callback→async spine
// (`awaitCallback` / `PendingResumer`): every consumer that once bridged a callback
// API up to `async` now calls the native async surface directly. What remains is a
// single one-shot continuation wrapper used by `ProxyClient.bridged(_:)` — the last
// scaffold bridging the not-yet-native per-protocol *dial* internals to `async`. It
// is deleted once those dial paths convert. Kept `nonisolated` and thread-safe via
// `Mutex` so the off-main transport layer can use it without hopping to the main
// actor (the module defaults to `MainActor` isolation).

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
