//
//  BoundedAsyncQueue.swift
//  Anywhere
//
//  Created by NodePassProject on 10/11/26.
//

import Foundation
import Synchronization

nonisolated final class BoundedAsyncQueue<Element: Sendable>: Sendable {
    private enum Role {
        case producer
        case consumer
    }

    private enum Step {
        case element(Element)
        case end
        case failure(Error)
        case wait
    }

    private struct State {
        var buffer: [Element] = []
        var finished = false
        var failure: Error?
        var consumer: CheckedContinuation<Void, Never>?
        var producer: CheckedContinuation<Void, Never>?

        subscript(role: Role) -> CheckedContinuation<Void, Never>? {
            get { role == .producer ? producer : consumer }
            set { if role == .producer { producer = newValue } else { consumer = newValue } }
        }
    }

    private let state = Mutex(State())
    private let capacity: Int

    init(capacity: Int) {
        self.capacity = max(1, capacity)
    }

    func put(_ element: Element) async -> Bool {
        while true {
            let (stored, waiter): (Bool?, CheckedContinuation<Void, Never>?) = state.withLock { state in
                if state.finished { return (false, nil) }
                guard state.buffer.count < capacity else { return (nil, nil) }
                state.buffer.append(element)
                let consumer = state.consumer
                state.consumer = nil
                return (true, consumer)
            }
            waiter?.resume()
            if let stored { return stored }
            await park(.producer)
            if Task.isCancelled { return false }
        }
    }

    func take() async throws -> Element? {
        while true {
            let (step, waiter): (Step, CheckedContinuation<Void, Never>?) = state.withLock { state in
                if !state.buffer.isEmpty {
                    let element = state.buffer.removeFirst()
                    let producer = state.producer
                    state.producer = nil
                    return (.element(element), producer)
                }
                if let failure = state.failure {
                    state.failure = nil
                    return (.failure(failure), nil)
                }
                if state.finished { return (.end, nil) }
                return (.wait, nil)
            }
            waiter?.resume()
            switch step {
            case .element(let element): return element
            case .end: return nil
            case .failure(let error): throw error
            case .wait:
                await park(.consumer)
                try Task.checkCancellation()
            }
        }
    }

    func finish(throwing error: Error? = nil) {
        let waiters: [CheckedContinuation<Void, Never>] = state.withLock { state in
            guard !state.finished else { return [] }
            state.finished = true
            state.failure = error
            var waiters: [CheckedContinuation<Void, Never>] = []
            if let consumer = state.consumer { waiters.append(consumer); state.consumer = nil }
            if let producer = state.producer { waiters.append(producer); state.producer = nil }
            return waiters
        }
        for waiter in waiters { waiter.resume() }
    }

    private func park(_ role: Role) async {
        await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let ready: Bool = state.withLock { state in
                    if state.finished || Task.isCancelled { return true }
                    switch role {
                    case .producer: if state.buffer.count < capacity { return true }
                    case .consumer: if !state.buffer.isEmpty || state.failure != nil { return true }
                    }
                    state[role] = continuation
                    return false
                }
                if ready { continuation.resume() }
            }
        } onCancel: {
            let waiter: CheckedContinuation<Void, Never>? = state.withLock { state in
                defer { state[role] = nil }
                return state[role]
            }
            waiter?.resume()
        }
    }
}
