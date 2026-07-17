//
//  SerialSender.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation

nonisolated final class SerialSender: Sendable {

    /// One-shot outcome latch for a submitted job. Await `value()` at most once (the
    /// underlying signal is single-consumer); it rethrows the job's error.
    struct Pending: Sendable {
        fileprivate let signal: AsyncThrowingStream<Never, Error>

        func value() async throws {
            for try await _ in signal {}
            // A cancelled iteration ends silently; surface it rather than report success.
            try Task.checkCancellation()
        }
    }

    private struct Job: Sendable {
        let body: @Sendable () async throws -> Void
        let done: AsyncThrowingStream<Never, Error>.Continuation
    }

    private let jobs: AsyncStream<Job>.Continuation

    init() {
        let (stream, continuation) = AsyncStream.makeStream(of: Job.self)
        jobs = continuation
        // Captures only the stream — never the sender — so the sender's release ends the loop.
        Task {
            for await job in stream {
                do {
                    try await job.body()
                    job.done.finish()
                } catch {
                    job.done.finish(throwing: error)
                }
            }
        }
    }

    /// Enqueues `body` at the tail of the pipeline, synchronously fixing its FIFO slot, and
    /// returns a handle carrying backpressure and the job's error to whoever awaits it.
    func submit(_ body: @escaping @Sendable () async throws -> Void) -> Pending {
        let (signal, done) = AsyncThrowingStream.makeStream(of: Never.self)
        jobs.yield(Job(body: body, done: done))
        return Pending(signal: signal)
    }

    /// Runs `body` in submission order and awaits its outcome. If the awaiting task is
    /// cancelled the wait ends early (throwing `CancellationError`); the job itself still
    /// runs to completion so the wire never sees a half-submitted sequence.
    func run(_ body: @escaping @Sendable () async throws -> Void) async throws {
        try await submit(body).value()
    }
}
