//
//  SerialSender.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation
import Synchronization

nonisolated final class SerialSender: Sendable {
    struct Pending: Sendable {
        fileprivate let signal: AsyncThrowingStream<Void, Error>

        func value() async throws {
            for try await _ in signal { return }
            try Task.checkCancellation()
            throw AnywhereError.transport(.terminated)
        }
    }

    private struct Job: Sendable {
        let body: @Sendable () async throws -> Void
        let done: AsyncThrowingStream<Void, Error>.Continuation
    }

    private let jobs: AsyncStream<Job>.Continuation
    private let pump: Mutex<Task<Void, Never>?>

    init() {
        let (stream, continuation) = AsyncStream.makeStream(of: Job.self)
        jobs = continuation
        pump = Mutex(Task {
            for await job in stream {
                do {
                    try await job.body()
                    job.done.yield()
                    job.done.finish()
                } catch {
                    job.done.finish(throwing: error)
                }
            }
        })
    }

    deinit {
        cancel()
    }

    func cancel() {
        jobs.finish()
        let task = pump.withLock { pump -> Task<Void, Never>? in
            let task = pump
            pump = nil
            return task
        }
        task?.cancel()
    }

    func submit(_ body: @escaping @Sendable () async throws -> Void) -> Pending {
        let (signal, done) = AsyncThrowingStream.makeStream(of: Void.self)
        if case .terminated = jobs.yield(Job(body: body, done: done)) {
            done.finish(throwing: AnywhereError.transport(.terminated))
        }
        return Pending(signal: signal)
    }

    func run(_ body: @escaping @Sendable () async throws -> Void) async throws {
        try await submit(body).value()
    }
}
