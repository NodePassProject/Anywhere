//
//  AsyncInbox.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Synchronization

nonisolated final class AsyncInbox<Element: Sendable>: Sendable {

    private struct State {
        var buffer: [Element] = []
        var finished = false
        var failure: Error?
        var waiter: AsyncStream<Void>.Continuation?
    }

    private enum Step {
        case element(Element)
        case batch([Element])
        case end
        case failure(Error)
        case wait(AsyncStream<Void>)
    }

    private let state = Mutex(State())

    /// When set, a `yield` onto a full buffer drops the incoming element (matching
    /// `AsyncStream.Continuation.BufferingPolicy.bufferingOldest`). `nil` is unbounded.
    private let capacity: Int?

    /// - Parameter capacity: max buffered elements; further `yield`s drop the newest (keeping the
    ///   oldest `capacity`). `nil` (default) buffers without bound.
    init(capacity: Int? = nil) {
        self.capacity = capacity
    }

    /// Appends one element for the consumer, waking it if parked. Drops the element when a bounded
    /// inbox is full. No-op after ``finish(throwing:)``.
    func yield(_ element: Element) {
        let waiter: AsyncStream<Void>.Continuation? = state.withLock { s in
            guard !s.finished else { return nil }
            if let capacity, s.buffer.count >= capacity { return nil }
            s.buffer.append(element)
            let waiter = s.waiter
            s.waiter = nil
            return waiter
        }
        waiter?.finish()
    }

    /// Ends the stream cleanly: the consumer drains any buffered elements, then ``next()`` returns
    /// `nil`. Idempotent — the first `finish` wins.
    func finish() {
        finish(error: nil)
    }

    /// Ends the stream with `error`: the consumer drains any buffered elements, then ``next()`` throws
    /// `error` once and returns `nil` thereafter. Idempotent — the first `finish` wins.
    func finish(throwing error: Error) {
        finish(error: error)
    }

    private func finish(error: Error?) {
        let waiter: AsyncStream<Void>.Continuation? = state.withLock { s in
            guard !s.finished else { return nil }
            s.finished = true
            s.failure = error
            let waiter = s.waiter
            s.waiter = nil
            return waiter
        }
        waiter?.finish()
    }

    /// Pulls the next element, or `nil` at clean end-of-stream; throws the terminal error once.
    /// Buffered elements are always delivered before a terminal error, matching `AsyncThrowingStream`.
    /// Single-consumer: at most one task may await this at a time. Cancellation-aware.
    func next() async throws -> Element? {
        while true {
            let step: Step = state.withLock { s in
                if !s.buffer.isEmpty {
                    return .element(s.buffer.removeFirst())
                }
                if let failure = s.failure {
                    s.failure = nil   // surface once, then behave as a clean end
                    return .failure(failure)
                }
                if s.finished {
                    return .end
                }
                // Enroll a fresh gate under the lock so a `yield`/`finish` racing in can't be lost:
                // it either lands in the buffer (seen on the next turn) or finishes this gate.
                let (gate, continuation) = AsyncStream<Void>.makeStream()
                s.waiter = continuation
                return .wait(gate)
            }
            switch step {
            case .element(let element):
                return element
            case .batch:
                fatalError("next() never produces a batch step")
            case .end:
                return nil
            case .failure(let error):
                throw error
            case .wait(let gate):
                for await _ in gate { break }
                // A finished gate loops to re-check; a cancelled consumer must not spin.
                try Task.checkCancellation()
            }
        }
    }

    /// Like ``next()``, but drains *everything* buffered in one call — one consumer wake-up per
    /// producer burst instead of one per element. Never returns an empty array: waits when the
    /// buffer is empty, `nil` at clean end-of-stream, throws the terminal error once (buffered
    /// elements are always delivered first). Single-consumer, cancellation-aware.
    func nextBatch() async throws -> [Element]? {
        while true {
            let step: Step = state.withLock { s in
                if !s.buffer.isEmpty {
                    let batch = s.buffer
                    s.buffer.removeAll(keepingCapacity: true)
                    return .batch(batch)
                }
                if let failure = s.failure {
                    s.failure = nil   // surface once, then behave as a clean end
                    return .failure(failure)
                }
                if s.finished {
                    return .end
                }
                // Enroll a fresh gate under the lock so a `yield`/`finish` racing in can't be lost:
                // it either lands in the buffer (seen on the next turn) or finishes this gate.
                let (gate, continuation) = AsyncStream<Void>.makeStream()
                s.waiter = continuation
                return .wait(gate)
            }
            switch step {
            case .element:
                fatalError("nextBatch() never produces an element step")
            case .batch(let batch):
                return batch
            case .end:
                return nil
            case .failure(let error):
                throw error
            case .wait(let gate):
                for await _ in gate { break }
                // A finished gate loops to re-check; a cancelled consumer must not spin.
                try Task.checkCancellation()
            }
        }
    }
}
