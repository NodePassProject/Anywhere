//
//  AsyncTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Synchronization

nonisolated final class AsyncPromise<Value: Sendable>: Sendable {
    private enum Storage {
        case pending
        case waiting(CheckedContinuation<Value, Error>)
        case resolved(Result<Value, Error>)
    }
    private let storage = Mutex(Storage.pending)

    func resolve(_ result: Result<Value, Error>) {
        let continuation: CheckedContinuation<Value, Error>? = storage.withLock { storage -> CheckedContinuation<Value, Error>? in
            switch storage {
            case .pending:
                storage = .resolved(result)
                return nil
            case .waiting(let continuation):
                storage = .resolved(result)
                return continuation
            case .resolved:
                return nil  // first resolve wins
            }
        }
        continuation?.resume(with: result)
    }

    func value() async throws -> Value {
        try await withCheckedThrowingContinuation { continuation in
            let resolved: Result<Value, Error>? = storage.withLock { storage -> Result<Value, Error>? in
                switch storage {
                case .pending:
                    storage = .waiting(continuation)
                    return nil
                case .resolved(let result):
                    return result
                case .waiting:
                    return .failure(TransportError.connectionFailed("AsyncPromise awaited twice"))
                }
            }
            if let resolved { continuation.resume(with: resolved) }
        }
    }
}

// MARK: - AsyncReadinessGate

/// One-shot, multi-awaiter readiness signal. Coalesces every `wait()` behind a single
/// `signal(_:)` — the async replacement for a `[(Error?) -> Void]` callback list, so the
/// waiter continuations live here in the async infra rather than in the callback-driven
/// (ngtcp2 / lwIP / JSC) layers that fulfil them. The first `signal` wins; later waiters
/// get the cached result immediately.
nonisolated final class AsyncReadinessGate: Sendable {
    private enum Storage {
        case pending([CheckedContinuation<Void, Error>])
        case resolved(Result<Void, Error>)
    }
    private let storage = Mutex(Storage.pending([]))

    /// Resolves every parked (and every future) `wait()`. Safe to call from any thread/queue.
    func signal(_ result: Result<Void, Error>) {
        let waiters: [CheckedContinuation<Void, Error>] = storage.withLock { storage in
            switch storage {
            case .pending(let waiters):
                storage = .resolved(result)
                return waiters
            case .resolved:
                return []               // first signal wins
            }
        }
        for waiter in waiters { waiter.resume(with: result) }
    }

    func signalSuccess() { signal(.success(())) }
    func signalFailure(_ error: Error) { signal(.failure(error)) }

    /// Whether the gate has already resolved (in which case `wait()` returns immediately).
    var isResolved: Bool {
        storage.withLock { if case .resolved = $0 { return true } else { return false } }
    }

    func wait() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let resolved: Result<Void, Error>? = storage.withLock { storage in
                switch storage {
                case .pending(var waiters):
                    waiters.append(continuation)
                    storage = .pending(waiters)
                    return nil
                case .resolved(let result):
                    return result
                }
            }
            if let resolved { continuation.resume(with: resolved) }
        }
    }
}

