//
//  AsyncByteChannel.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation
import Synchronization

nonisolated final class AsyncByteChannel: @unchecked Sendable {

    private enum Item {
        case data(Data)
        case eof
        case failure(Error)
    }

    private struct State {
        var queue: [Item] = []
        var waiter: CheckedContinuation<Data?, Error>?
        /// Set once a terminal item (eof/failure) has been queued or delivered; further
        /// data/termination is ignored so the reader sees exactly one end.
        var terminated = false
    }

    private let state = Mutex(State())

    /// Enqueues received bytes. Ignored after termination or if empty.
    func yield(_ data: Data) {
        guard !data.isEmpty else { return }
        let waiter: CheckedContinuation<Data?, Error>? = state.withLock { state in
            guard !state.terminated else { return nil }
            if let waiter = state.waiter {
                state.waiter = nil
                return waiter          // hand off directly to a parked reader
            }
            state.queue.append(.data(data))
            return nil
        }
        waiter?.resume(returning: data)
    }

    /// Marks a clean end-of-stream, ordered after every already-queued chunk.
    func finish() {
        terminate(with: .eof)
    }

    /// Marks a terminal failure, ordered after every already-queued chunk.
    func fail(_ error: Error) {
        terminate(with: .failure(error))
    }

    /// Abortive teardown: any parked reader sees EOF immediately; later reads see EOF.
    /// Distinct from ``finish()`` only in that it discards still-queued chunks.
    func cancel() {
        let waiter: CheckedContinuation<Data?, Error>? = state.withLock { state in
            state.queue.removeAll()
            guard !state.terminated else { return nil }
            state.terminated = true
            let waiter = state.waiter
            state.waiter = nil
            return waiter
        }
        waiter?.resume(returning: nil)
    }

    private func terminate(with item: Item) {
        let waiter: CheckedContinuation<Data?, Error>? = state.withLock { state in
            guard !state.terminated else { return nil }
            state.terminated = true
            if let waiter = state.waiter {
                state.waiter = nil
                return waiter          // deliver the end to a parked reader now
            }
            state.queue.append(item)
            return nil
        }
        // Resume outside the lock.
        if let waiter {
            switch item {
            case .data:            waiter.resume(returning: nil)   // unreachable
            case .eof:             waiter.resume(returning: nil)
            case .failure(let e):  waiter.resume(throwing: e)
            }
        }
    }

    /// Pulls the next chunk; `nil` signals a clean end, a throw a terminal error.
    /// Single-consumer: never call concurrently with another `next()`.
    func next() async throws -> Data? {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            enum Immediate { case data(Data); case eof; case failure(Error) }
            let immediate: Immediate? = state.withLock { state in
                if !state.queue.isEmpty {
                    switch state.queue.removeFirst() {
                    case .data(let data): return .data(data)
                    case .eof:            return .eof
                    case .failure(let e): return .failure(e)
                    }
                }
                if state.terminated {
                    return .eof
                }
                state.waiter = continuation
                return nil
            }
            switch immediate {
            case .data(let data):    continuation.resume(returning: data)
            case .eof:               continuation.resume(returning: nil)
            case .failure(let e):    continuation.resume(throwing: e)
            case nil:                break   // parked; a producer will resume it
            }
        }
    }
}
