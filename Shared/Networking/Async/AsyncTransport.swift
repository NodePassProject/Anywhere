//
//  AsyncTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Synchronization

enum TransportChunk: Sendable {
    case bytes(Data)
    /// End-of-stream (remote FIN / half-close). Further reads also return `.end`.
    case end
}

protocol AsyncByteTransport: AnyObject, Sendable {
    nonisolated var isReady: Bool { get }

    nonisolated func send(_ data: Data) async throws

    /// Half-closes the send direction (TCP FIN / end-of-stream), ordered after
    /// every prior send; receive stays open. No sends may follow.
    nonisolated func finishSend() async throws

    /// One read: `.bytes` with data, `.end` at EOF. Reads are issued serially.
    nonisolated func receive() async throws -> TransportChunk

    /// Abortive teardown. Idempotent and safe from any task/thread.
    nonisolated func cancel()
}

protocol AsyncDatagramTransport: AnyObject, Sendable {
    nonisolated var isReady: Bool { get }

    nonisolated func send(_ datagram: Data) async throws

    /// One datagram; throws on terminal failure.
    nonisolated func receive() async throws -> Data

    nonisolated func cancel()
}

nonisolated final class AsyncPromise<Value: Sendable>: @unchecked Sendable {
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

nonisolated func raceDialDeadline<T: Sendable>(
    _ deadline: Duration,
    onExpire: @escaping @Sendable () -> Void = {},
    timeout: @autoclosure @escaping @Sendable () -> Error = TransportError.posixError(.connect, errno: ETIMEDOUT),
    _ body: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await body() }
        group.addTask {
            try await Task.sleep(for: deadline)
            onExpire()
            throw timeout()
        }
        defer { group.cancelAll() }
        // First task to finish wins: `body`'s value/throw, or the deadline throw.
        guard let result = try await group.next() else { throw timeout() }
        return result
    }
}
