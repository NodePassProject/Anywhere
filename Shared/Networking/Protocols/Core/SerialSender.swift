//
//  SerialSender.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation

nonisolated final class SerialSender: Sendable {
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

    deinit {
        jobs.finish()
    }
    
    func submit(_ body: @escaping @Sendable () async throws -> Void) -> Pending {
        let (signal, done) = AsyncThrowingStream.makeStream(of: Never.self)
        jobs.yield(Job(body: body, done: done))
        return Pending(signal: signal)
    }
    
    func run(_ body: @escaping @Sendable () async throws -> Void) async throws {
        try await submit(body).value()
    }
}
