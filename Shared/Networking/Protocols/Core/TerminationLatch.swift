//
//  TerminationLatch.swift
//  Anywhere
//
//  Created by NodePassProject on 8/14/26.
//

import Foundation
import Synchronization

nonisolated final class OneShotLatch: Sendable {
    private let claimed = Atomic<Bool>(false)

    @discardableResult
    func claim() -> Bool {
        !claimed.exchange(true, ordering: .acquiringAndReleasing)
    }

    var isClaimed: Bool { claimed.load(ordering: .acquiring) }
}

nonisolated final class TerminationLatch: Sendable {

    private struct State {
        var handler: (@Sendable (Error?) -> Void)?
        var terminated = false
        var error: Error?
    }
    private let state = Mutex(State())

    @discardableResult
    func install(_ handler: (@Sendable (Error?) -> Void)?) -> Bool {
        enum Outcome {
            case installed
            case alreadyTerminated(fire: (@Sendable (Error?) -> Void)?, error: Error?)
        }
        let outcome: Outcome = state.withLock { state in
            guard !state.terminated else {
                return .alreadyTerminated(fire: handler, error: state.error)
            }
            state.handler = handler
            return .installed
        }
        switch outcome {
        case .installed:
            return true
        case .alreadyTerminated(let fire, let error):
            fire?(error)
            return false
        }
    }

    @discardableResult
    func fire(_ error: Error?) -> Bool {
        let taken: (claimed: Bool, handler: (@Sendable (Error?) -> Void)?) = state.withLock { state in
            guard !state.terminated else { return (false, nil) }
            state.terminated = true
            state.error = error
            let handler = state.handler
            state.handler = nil
            return (true, handler)
        }
        taken.handler?(error)
        return taken.claimed
    }

    var isTerminated: Bool { state.withLock { $0.terminated } }

    var hasHandler: Bool { state.withLock { !$0.terminated && $0.handler != nil } }
}
