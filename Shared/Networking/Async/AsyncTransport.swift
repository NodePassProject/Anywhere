//
//  AsyncTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Synchronization

// MARK: - Async-native transport surface

// The async-native transport surface over iOS 26's `NetworkConnection`, which can
// be stored and awaited directly — `await connection.send(_)` *is* ordering +
// backpressure, `await conn.receive()` *is* the read — so there is no driver task,
// `AsyncStream` send feeder, or hand-rolled state machine.

/// One read off a byte stream.
enum TransportChunk: Sendable {
    case bytes(Data)
    /// End-of-stream (remote FIN / half-close). Further reads also return `.end`.
    case end
}

/// A bidirectional byte-stream transport with an async-native surface. Ordering
/// and backpressure are the `await` itself; teardown is ``cancel()`` (or task
/// cancellation of an in-flight `send`/`receive`).
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

/// A connected datagram transport (UDP / QUIC carrier). Each `send`/`receive`
/// preserves one datagram boundary.
protocol AsyncDatagramTransport: AnyObject, Sendable {
    nonisolated var isReady: Bool { get }

    nonisolated func send(_ datagram: Data) async throws

    /// One datagram; throws on terminal failure.
    nonisolated func receive() async throws -> Data

    nonisolated func cancel()
}

// MARK: - AsyncPromise

/// A one-shot async result. `resolve` and `value()` may happen in either order —
/// a `resolve` before anyone awaits latches the result — and only the first
/// `resolve` wins. Lets a background driver task hand a connect result (or a
/// teardown signal) back across the task boundary without losing the race.
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

// MARK: - Dial deadline

/// Runs `body`, throwing `timeout` if it hasn't finished within `deadline`.
/// On expiry, `onExpire` fires first (to abort the underlying connection) so the
/// racing `body` unwinds promptly. A structured-concurrency dial-deadline backstop.
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

// MARK: - RawToAsyncByteTransport

/// Presents a completion-handler ``RawTransport`` through the async-native
/// ``AsyncByteTransport`` surface, bridging *up* to `async` via the `RawTransport`
/// async extension.
///
/// Temporary scaffolding: the callback ``RawTransport``s that still sit under a
/// ``TLSRecordConnection`` — the proxy-chain ``TunneledTransport`` and the MITM
/// inner-leg transport — go async-native in later stages.
nonisolated final class RawToAsyncByteTransport: AsyncByteTransport, @unchecked Sendable {

    private let transport: any RawTransport

    init(_ transport: any RawTransport) {
        self.transport = transport
    }

    var isReady: Bool { transport.isTransportReady }

    func send(_ data: Data) async throws {
        try await transport.send(data)
    }

    func finishSend() async throws {
        try await transport.closeWrite()
    }

    func receive() async throws -> TransportChunk {
        // `RawTransport.receive` can report a spurious empty read without EOF; loop
        // until real bytes or a clean end, matching `TransportChunk`'s bytes/end contract.
        while true {
            let (data, isComplete) = try await transport.receive()
            if let data, !data.isEmpty { return .bytes(data) }
            if isComplete { return .end }
        }
    }

    func cancel() {
        transport.forceCancel()
    }
}
