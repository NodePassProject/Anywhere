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
        fileprivate let completion: Completion

        func value() async throws {
            try await completion.wait()
        }
    }

    fileprivate final class Completion: Sendable {
        private struct State {
            var result: Result<Void, Error>?
            var waiter: CheckedContinuation<Void, Error>?
            var isWaiterCancelled = false
        }

        private let state = Mutex(State())

        func resolve(_ result: Result<Void, Error>) {
            let waiter = state.withLock { state -> CheckedContinuation<Void, Error>? in
                guard state.result == nil else { return nil }
                state.result = result
                defer { state.waiter = nil }
                return state.waiter
            }
            waiter?.resume(with: result)
        }

        func wait() async throws {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    let ready = state.withLock { state -> Result<Void, Error>? in
                        if let result = state.result { return result }
                        if state.isWaiterCancelled { return .failure(CancellationError()) }
                        state.waiter = continuation
                        return nil
                    }
                    if let ready { continuation.resume(with: ready) }
                }
            } onCancel: {
                let waiter = state.withLock { state -> CheckedContinuation<Void, Error>? in
                    state.isWaiterCancelled = true
                    defer { state.waiter = nil }
                    return state.waiter
                }
                waiter?.resume(throwing: CancellationError())
            }
        }
    }

    private struct Job: Sendable {
        let body: @Sendable () async throws -> Void
        let completion: Completion
    }

    private final class Core: Sendable {
        private static let compactHeadThreshold = 32

        private struct State {
            var jobs: [Job] = []
            var head = 0
            var isDraining = false
            var isCancelled = false
            var drain: Task<Void, Never>?
        }

        private let state = Mutex(State())

        func submit(_ job: Job) {
            let accepted = state.withLock { state -> Bool in
                guard !state.isCancelled else { return false }
                state.jobs.append(job)
                if !state.isDraining {
                    state.isDraining = true
                    state.drain = Task { await self.drain() }
                }
                return true
            }
            if !accepted {
                job.completion.resolve(.failure(AnywhereError.transport(.terminated)))
            }
        }

        func cancel() {
            let drain = state.withLock { state -> Task<Void, Never>? in
                guard !state.isCancelled else { return nil }
                state.isCancelled = true
                return state.drain
            }
            drain?.cancel()
        }

        private func drain() async {
            while let job = next() {
                do {
                    try await job.body()
                    job.completion.resolve(.success(()))
                } catch {
                    job.completion.resolve(.failure(error))
                }
            }
        }

        private func next() -> Job? {
            state.withLock { state in
                guard state.head < state.jobs.count else {
                    state.jobs.removeAll(keepingCapacity: !state.isCancelled)
                    state.head = 0
                    state.isDraining = false
                    state.drain = nil
                    return nil
                }
                let job = state.jobs[state.head]
                state.head += 1
                if state.head == state.jobs.count {
                    state.jobs.removeAll(keepingCapacity: true)
                    state.head = 0
                } else if state.head >= Self.compactHeadThreshold, state.head * 2 >= state.jobs.count {
                    state.jobs.removeFirst(state.head)
                    state.head = 0
                }
                return job
            }
        }
    }

    private let core = Core()

    deinit {
        core.cancel()
    }

    func cancel() {
        core.cancel()
    }

    func submit(_ body: @escaping @Sendable () async throws -> Void) -> Pending {
        let completion = Completion()
        core.submit(Job(body: body, completion: completion))
        return Pending(completion: completion)
    }

    func run(_ body: @escaping @Sendable () async throws -> Void) async throws {
        try await submit(body).value()
    }
}
