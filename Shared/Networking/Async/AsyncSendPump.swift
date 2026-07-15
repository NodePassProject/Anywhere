//
//  AsyncSendPump.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

// MARK: - AsyncSendPump

/// Serializes callback-issued sends onto a single async task, preserving submission
/// order and `await` backpressure.
///
/// A callback consumer can fire-and-forget `send(A); send(B)`, which would race if
/// each were bridged to its own `Task`. This pump drains a submission-ordered
/// `AsyncStream` on one task, so `send(A)` completes before `send(B)` starts, and a
/// `finishSend` (half-close) is ordered after every send already enqueued.
///
/// Kept `nonisolated` and `@unchecked Sendable`: the caller's completion isn't
/// `Sendable`, but each job runs only on the pump task. Used by
/// ``AsyncProxyConnection`` and ``TLSRecordConnection``.
nonisolated final class AsyncSendPump: @unchecked Sendable {

    /// One ordered send job. `@unchecked` because `completion` isn't `Sendable`;
    /// it only ever runs on the pump task.
    private struct Job: @unchecked Sendable {
        let data: Data
        let endOfStream: Bool
        let completion: ((Error?) -> Void)?
    }

    private let continuation: AsyncStream<Job>.Continuation
    private let task: Task<Void, Never>

    /// - Parameters:
    ///   - send: performs one ordered send; awaited to completion before the next job.
    ///   - finish: half-closes the send direction; ordered after every prior send.
    ///
    /// Capture only what the closures need — never the owning adapter strongly — so the
    /// pump task doesn't retain it (see ``AsyncProxyConnection`` for the weak-self form).
    init(
        send: @escaping @Sendable (Data) async throws -> Void,
        finish: @escaping @Sendable () async throws -> Void
    ) {
        let (stream, continuation) = AsyncStream.makeStream(of: Job.self)
        self.continuation = continuation
        task = Task {
            for await job in stream {
                do {
                    if job.endOfStream {
                        try await finish()
                    } else {
                        try await send(job.data)
                    }
                    job.completion?(nil)
                } catch {
                    job.completion?(error)
                }
            }
        }
    }

    /// Enqueues a send; `completion` fires (on the pump task) once it lands or fails.
    func enqueueSend(_ data: Data, completion: ((Error?) -> Void)?) {
        continuation.yield(Job(data: data, endOfStream: false, completion: completion))
    }

    /// Enqueues a half-close, ordered after every send already enqueued.
    func enqueueFinish(completion: ((Error?) -> Void)?) {
        continuation.yield(Job(data: Data(), endOfStream: true, completion: completion))
    }

    /// Stops the pump. In-flight/queued jobs are abandoned (their completions may not
    /// fire), matching abortive teardown; call the underlying `cancel()` alongside.
    func finish() {
        continuation.finish()
        task.cancel()
    }
}
