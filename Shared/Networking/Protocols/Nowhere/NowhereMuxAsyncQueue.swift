//
//  NowhereMuxAsyncQueue.swift
//  Anywhere
//
//  Created by NodePassProject on 8/24/26.
//

import Foundation
import Synchronization

nonisolated final class NowhereMuxAsyncQueue<Element: Sendable>: Sendable {
    private struct State {
        var elements: [Element] = []
        var headIndex = 0
        var finished = false
        var failure: Error?
        var producerGate = H2FlowGate()
        var consumerGate = H2FlowGate()

        var bufferedCount: Int { elements.count - headIndex }

        mutating func popFirst() -> Element? {
            guard headIndex < elements.count else { return nil }
            let element = elements[headIndex]
            headIndex += 1

            if headIndex == elements.count {
                elements.removeAll(keepingCapacity: true)
                headIndex = 0
            } else if headIndex >= 64, headIndex * 2 >= elements.count {
                elements.removeFirst(headIndex)
                headIndex = 0
            }
            return element
        }

        mutating func discardBuffered() -> [Element] {
            guard headIndex < elements.count else {
                elements.removeAll(keepingCapacity: false)
                headIndex = 0
                return []
            }
            let discarded = Array(elements[headIndex...])
            elements.removeAll(keepingCapacity: false)
            headIndex = 0
            return discarded
        }
    }

    private enum SendStep {
        case sent
        case closed(Error)
        case wait(AsyncStream<Never>)
    }

    private enum ReceiveStep {
        case element(Element)
        case end
        case failed(Error)
        case wait(AsyncStream<Never>)
    }

    private let capacity: Int
    private let state = Mutex(State())

    init(capacity: Int) {
        precondition(capacity > 0)
        self.capacity = capacity
    }

    func send(_ element: Element) async throws {
        while true {
            try Task.checkCancellation()
            let step: SendStep = state.withLock { state in
                guard !state.finished else {
                    return .closed(state.failure ?? AnywhereError.proxy(.nowhere, .streamClosed))
                }
                guard state.bufferedCount >= capacity else {
                    state.elements.append(element)
                    state.consumerGate.wakeAll()
                    return .sent
                }
                return .wait(state.producerGate.enroll())
            }
            switch step {
            case .sent:
                return
            case .closed(let error):
                throw error
            case .wait(let gate):
                for await _ in gate {}
            }
        }
    }

    func next() async throws -> Element? {
        while true {
            try Task.checkCancellation()
            let step: ReceiveStep = state.withLock { state in
                if let element = state.popFirst() {
                    state.producerGate.wakeAll()
                    return .element(element)
                }
                if let failure = state.failure {
                    state.failure = nil
                    return .failed(failure)
                }
                if state.finished { return .end }
                return .wait(state.consumerGate.enroll())
            }
            switch step {
            case .element(let element):
                return element
            case .end:
                return nil
            case .failed(let error):
                throw error
            case .wait(let gate):
                for await _ in gate {}
            }
        }
    }

    @discardableResult
    func finish(throwing error: Error? = nil, discardingBuffered: Bool = false) -> [Element] {
        state.withLock { state in
            if !state.finished {
                state.finished = true
                state.failure = error
            }
            let discarded: [Element]
            if discardingBuffered {
                discarded = state.discardBuffered()
            } else {
                discarded = []
            }
            state.producerGate.wakeAll()
            state.consumerGate.wakeAll()
            return discarded
        }
    }
}
