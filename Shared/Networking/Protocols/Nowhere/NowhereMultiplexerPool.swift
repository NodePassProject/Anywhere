//
//  NowhereMultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 8/24/26.
//

import Foundation
import Synchronization

nonisolated final class NowhereMultiplexerRegistry: Sendable {
    static let shared = NowhereMultiplexerRegistry()

    private struct Key: Hashable {
        let configurationID: UUID
        let configuration: NowhereRuntimeConfiguration
        let connectHost: String
        let chain: [ProxyConfiguration]
    }

    private struct State {
        var pools: [Key: NowhereMultiplexerPool] = [:]
        var sealed = false
    }

    private let state = Mutex(State())

    private init() {}

    func seal() {
        state.withLock { $0.sealed = true }
    }

    func unseal() {
        state.withLock { $0.sealed = false }
    }

    func acquire(
        configurationID: UUID,
        configuration: NowhereRuntimeConfiguration,
        connectHost: String,
        chain: [ProxyConfiguration],
        flowID: UInt32,
        builder: @escaping @Sendable () async throws -> NowhereMultiplexer
    ) async throws -> NowhereMultiplexerStream {
        let key = Key(
            configurationID: configurationID,
            configuration: configuration,
            connectHost: connectHost,
            chain: chain
        )

        var replaced: [NowhereMultiplexerPool] = []
        let selected = state.withLock { state -> NowhereMultiplexerPool? in
            if let existing = state.pools[key] { return existing }
            guard !state.sealed else { return nil }

            let staleKeys = state.pools.keys.filter { $0.configurationID == configurationID }
            for staleKey in staleKeys {
                guard let stale = state.pools.removeValue(forKey: staleKey) else { continue }
                replaced.append(stale)
            }
            let created = NowhereMultiplexerPool(builder: builder)
            state.pools[key] = created
            return created
        }

        for stale in replaced { stale.closeAll() }
        guard let selected else { throw AnywhereError.transport(.terminated) }
        return try await selected.acquire(flowID: flowID)
    }

    func invalidate(configurationID: UUID) {
        let removed: [NowhereMultiplexerPool] = state.withLock { state in
            let keys = state.pools.keys.filter { $0.configurationID == configurationID }
            return keys.compactMap { state.pools.removeValue(forKey: $0) }
        }
        for pool in removed { pool.closeAll() }
    }

    func closeAll() {
        let snapshot: [NowhereMultiplexerPool] = state.withLock { state in
            let pools = Array(state.pools.values)
            state.pools.removeAll(keepingCapacity: false)
            return pools
        }
        for pool in snapshot { pool.closeAll() }
    }
}

nonisolated extension NowhereMultiplexerRegistry: TransportPool {
    func reclaim() { closeAll() }
}

nonisolated private final class NowhereMultiplexerPool: Sendable {
    private struct PendingBuild: Sendable {
        let identifier: UInt64
        let task: Task<NowhereMultiplexer, Error>
    }

    private struct Extra: Sendable {
        var nextBuildIdentifier: UInt64 = 0
        var pendingBuilds: [UInt64: PendingBuild] = [:]
    }

    private typealias Base = MultiplexerPool<NowhereMultiplexer, Extra>
    private typealias ReservedStream = (
        multiplexer: NowhereMultiplexer,
        reservation: NowhereMultiplexer.StreamReservation
    )

    private enum Acquisition {
        case reserved(ReservedStream)
        case build(PendingBuild)
    }

    private static let bucket = "nowhere"
    private static let policy = MultiplexerPolicy(
        idleTimeout: NowhereMultiplexerConstants.idleTimeout,
        idleCheckInterval: 5
    )

    private let pool = Base(extra: Extra())
    private let builder: @Sendable () async throws -> NowhereMultiplexer

    init(builder: @escaping @Sendable () async throws -> NowhereMultiplexer) {
        self.builder = builder
        pool.startIdleEviction(Self.policy)
    }

    func acquire(flowID: UInt32) async throws -> NowhereMultiplexerStream {
        while true {
            try Task.checkCancellation()
            switch try acquisition(flowID: flowID) {
            case .reserved(let reserved):
                do {
                    return try await reserved.multiplexer.openStream(reserved.reservation)
                } catch {
                    if reserved.multiplexer.isClosed {
                        pool.removeMultiplexer(reserved.multiplexer, key: Self.bucket)
                    }
                    throw error
                }

            case .build(let pending):
                let multiplexer: NowhereMultiplexer
                do {
                    multiplexer = try await waitForBuild(pending)
                } catch {
                    if Task.isCancelled {
                        adoptWhenBuilt(pending)
                    } else {
                        clearPendingBuild(identifier: pending.identifier)
                    }
                    throw error
                }

                let adoption = adopt(multiplexer, from: pending)
                guard adoption.accepted else {
                    multiplexer.close()
                    throw AnywhereError.transport(.terminated)
                }
                if adoption.inserted {
                    installRemoval(on: multiplexer)
                }
            }
        }
    }

    private func installRemoval(on multiplexer: NowhereMultiplexer) {
        multiplexer.installCloseHandler { [weak self, weak multiplexer] in
            guard let multiplexer else { return }
            self?.pool.removeMultiplexer(multiplexer, key: Self.bucket)
        }
    }
    
    private func adoptWhenBuilt(_ pending: PendingBuild) {
        Task { [weak self] in
            guard let multiplexer = try? await pending.task.value else {
                self?.clearPendingBuild(identifier: pending.identifier)
                return
            }
            guard let self else {
                multiplexer.close()
                return
            }
            let adoption = self.adopt(multiplexer, from: pending)
            guard adoption.accepted else {
                multiplexer.close()
                return
            }
            if adoption.inserted {
                self.installRemoval(on: multiplexer)
            }
        }
    }

    func closeAll() {
        pool.retire()
        let pending = pool.state.withLock { state -> [Task<NowhereMultiplexer, Error>] in
            let tasks = state.extra.pendingBuilds.values.map(\.task)
            state.extra.pendingBuilds.removeAll(keepingCapacity: false)
            return tasks
        }
        for task in pending { task.cancel() }
    }

    private func acquisition(flowID: UInt32) throws -> Acquisition {
        try pool.state.withLock { state in
            guard state.phase == .open else { throw AnywhereError.transport(.terminated) }

            let existing = state.multiplexers[Self.bucket] ?? []
            let live = existing.filter { !$0.isClosed }
            for closed in existing where closed.isClosed {
                state.lastActivity.removeValue(forKey: ObjectIdentifier(closed))
            }
            state.multiplexers[Self.bucket] = live

            let sorted = live.sorted { lhs, rhs in
                let left = lhs.loadSnapshot
                let right = rhs.loadSnapshot
                if left.connectionCredit != right.connectionCredit {
                    return left.connectionCredit > right.connectionCredit
                }
                if left.outboundFrames != right.outboundFrames {
                    return left.outboundFrames < right.outboundFrames
                }
                return left.activeStreams < right.activeStreams
            }
            for multiplexer in sorted {
                let onEnd: @Sendable () -> Void = { [weak self, weak multiplexer] in
                    guard let self, let multiplexer else { return }
                    self.noteStreamEnded(multiplexer)
                }
                do {
                    if let reservation = try multiplexer.reserveStream(
                        flowID: flowID,
                        maximumActiveFlows: NowhereMultiplexerConstants.maximumActiveFlowsPerMultiplexer,
                        onEnd: onEnd
                    ) {
                        state.lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
                        return .reserved((multiplexer, reservation))
                    }
                } catch {
                    if multiplexer.isClosed { continue }
                    throw error
                }
            }

            if live.count + state.extra.pendingBuilds.count >= NowhereMultiplexerConstants.maximumMultiplexers {
                if let pending = state.extra.pendingBuilds.values.min(by: { $0.identifier < $1.identifier }) {
                    return .build(pending)
                }
                throw AnywhereError.proxy(.nowhere, .streamIDsExhausted)
            }
            state.extra.nextBuildIdentifier &+= 1
            let pending = PendingBuild(
                identifier: state.extra.nextBuildIdentifier,
                task: Task { [builder] in try await builder() }
            )
            state.extra.pendingBuilds[pending.identifier] = pending
            return .build(pending)
        }
    }

    private func clearPendingBuild(identifier: UInt64) {
        _ = pool.state.withLock { state in
            state.extra.pendingBuilds.removeValue(forKey: identifier)
        }
    }

    private func waitForBuild(_ pending: PendingBuild) async throws -> NowhereMultiplexer {
        let resultInbox = AsyncInbox<Result<NowhereMultiplexer, Error>>()
        let observer = Task {
            let result: Result<NowhereMultiplexer, Error>
            do {
                result = .success(try await pending.task.value)
            } catch {
                result = .failure(error)
            }
            resultInbox.yield(result)
            resultInbox.finish()
        }
        defer { observer.cancel() }

        guard let result = try await resultInbox.next() else {
            throw CancellationError()
        }
        return try result.get()
    }

    private func adopt(
        _ multiplexer: NowhereMultiplexer,
        from pending: PendingBuild
    ) -> (accepted: Bool, inserted: Bool) {
        var inserted = false
        let accepted = pool.state.withLock { state -> Bool in
            state.extra.pendingBuilds.removeValue(forKey: pending.identifier)
            guard state.phase == .open, !multiplexer.isClosed else { return false }

            let identifier = ObjectIdentifier(multiplexer)
            if state.multiplexers[Self.bucket]?.contains(where: { $0 === multiplexer }) != true {
                state.multiplexers[Self.bucket, default: []].append(multiplexer)
                state.lastActivity[identifier] = MonotonicClock.now
                inserted = true
            }
            return true
        }
        if inserted { pool.noteMultiplexersChanged() }
        return (accepted, inserted)
    }

    private func noteStreamEnded(_ multiplexer: NowhereMultiplexer) {
        pool.state.withLock { state in
            let identifier = ObjectIdentifier(multiplexer)
            if state.lastActivity[identifier] != nil {
                state.lastActivity[identifier] = MonotonicClock.now
            }
        }
    }
}
