//
//  QUICState.swift
//  Anywhere
//
//  Created by NodePassProject on 10/5/26.
//

import Dispatch
import Synchronization

nonisolated protocol QUICPublishingState: AnyObject, SendableMetatype {
    var publications: [@Sendable () -> Void] { get set }
}

nonisolated final class QUICState<Core: QUICPublishingState>: Sendable {
    private struct Storage {
        let core: Core
        var draining = false
    }
    private let storage: Mutex<Storage>
    private let queue: DispatchQueue

    init(_ core: sending Core, queue: DispatchQueue) {
        storage = Mutex(Storage(core: core))
        self.queue = queue
    }

    func read<T: Sendable>(_ body: (Core) throws -> T) rethrows -> T {
        try storage.withLock { try body($0.core) }
    }

    func update<T: Sendable>(_ body: (Core) -> T) -> T {
        let (result, drain) = storage.withLock { state in
            let result = body(state.core)
            let drain = !state.draining && !state.core.publications.isEmpty
            if drain { state.draining = true }
            return (result, drain)
        }
        if drain { queue.async { self.drain() } }
        return result
    }

    private func drain() {
        while true {
            let batch = storage.withLock { state in
                let batch = state.core.publications
                state.core.publications.removeAll(keepingCapacity: true)
                if batch.isEmpty { state.draining = false }
                return batch
            }
            if batch.isEmpty { return }
            for action in batch { action() }
        }
    }
}
