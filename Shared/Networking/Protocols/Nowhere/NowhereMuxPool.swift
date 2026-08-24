//
//  NowhereMuxPool.swift
//  Anywhere
//
//  Created by NodePassProject on 8/24/26.
//

import Foundation
import Synchronization

nonisolated final class NowhereMuxShardRegistry: Sendable {
    static let shared = NowhereMuxShardRegistry()

    private struct Key: Hashable {
        let configurationID: UUID
        let configuration: NowhereConfiguration
        let connectHost: String
        let chain: [ProxyConfiguration]
    }

    private struct State {
        var pools: [Key: NowhereMuxShardPool] = [:]
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
        configuration: NowhereConfiguration,
        connectHost: String,
        chain: [ProxyConfiguration],
        flowID: UInt32,
        builder: @escaping @Sendable () async throws -> NowhereMuxCarrier
    ) async throws -> NowhereMuxStream {
        let key = Key(
            configurationID: configurationID,
            configuration: configuration,
            connectHost: connectHost,
            chain: chain
        )

        var replaced: [NowhereMuxShardPool] = []
        let selected = state.withLock { state -> NowhereMuxShardPool? in
            if let existing = state.pools[key] { return existing }
            guard !state.sealed else { return nil }

            let staleKeys = state.pools.keys.filter { $0.configurationID == configurationID }
            for staleKey in staleKeys {
                guard let stale = state.pools.removeValue(forKey: staleKey) else { continue }
                replaced.append(stale)
            }
            let created = NowhereMuxShardPool(builder: builder)
            state.pools[key] = created
            return created
        }

        for stale in replaced { stale.closeAll() }
        guard let selected else { throw AnywhereError.transport(.terminated) }
        return try await selected.acquire(flowID: flowID)
    }

    func invalidate(configurationID: UUID) {
        let removed: [NowhereMuxShardPool] = state.withLock { state in
            let keys = state.pools.keys.filter { $0.configurationID == configurationID }
            return keys.compactMap { state.pools.removeValue(forKey: $0) }
        }
        for pool in removed { pool.closeAll() }
    }

    func closeAll() {
        let snapshot: [NowhereMuxShardPool] = state.withLock { state in
            let pools = Array(state.pools.values)
            state.pools.removeAll(keepingCapacity: false)
            return pools
        }
        for pool in snapshot { pool.closeAll() }
    }
}

nonisolated extension NowhereMuxShardRegistry: TransportPool {
    func reclaim() { closeAll() }
}

nonisolated private final class NowhereMuxShardPool: Sendable {
    private struct PendingBuild: Sendable {
        let identifier: UInt64
        let task: Task<NowhereMuxCarrier, Error>
    }

    private struct Extra: Sendable {
        var nextBuildIdentifier: UInt64 = 0
        var pendingBuild: PendingBuild?
    }

    private typealias Base = MultiplexerPool<NowhereMuxCarrier, Extra>
    private typealias ReservedStream = (
        carrier: NowhereMuxCarrier,
        reservation: NowhereMuxCarrier.StreamReservation
    )

    private enum Acquisition {
        case reserved(ReservedStream)
        case build(PendingBuild)
    }

    private static let bucket = "nowhere"
    private static let policy = MultiplexerPolicy(
        idleTimeout: NowhereMuxConstants.idleTimeout,
        idleCheckInterval: 5
    )

    private let pool = Base(extra: Extra())
    private let builder: @Sendable () async throws -> NowhereMuxCarrier

    init(builder: @escaping @Sendable () async throws -> NowhereMuxCarrier) {
        self.builder = builder
        pool.startIdleEviction(Self.policy)
    }

    func acquire(flowID: UInt32) async throws -> NowhereMuxStream {
        while true {
            try Task.checkCancellation()
            switch try acquisition(flowID: flowID) {
            case .reserved(let reserved):
                do {
                    return try await reserved.carrier.openStream(reserved.reservation)
                } catch {
                    if reserved.carrier.isClosed {
                        pool.removeMultiplexer(reserved.carrier, key: Self.bucket)
                    }
                    throw error
                }

            case .build(let pending):
                let carrier: NowhereMuxCarrier
                do {
                    carrier = try await waitForBuild(pending)
                } catch {
                    if !Task.isCancelled {
                        clearPendingBuild(identifier: pending.identifier)
                    }
                    throw error
                }

                let adoption = adopt(carrier, from: pending)
                guard adoption.accepted else {
                    carrier.close()
                    throw AnywhereError.transport(.terminated)
                }
                if adoption.inserted {
                    carrier.installCloseHandler { [weak self, weak carrier] in
                        guard let carrier else { return }
                        self?.pool.removeMultiplexer(carrier, key: Self.bucket)
                    }
                }
            }
        }
    }

    func closeAll() {
        pool.retire()
        let pending = pool.state.withLock { state -> Task<NowhereMuxCarrier, Error>? in
            let task = state.extra.pendingBuild?.task
            state.extra.pendingBuild = nil
            return task
        }
        pending?.cancel()
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

            let candidates = live.sorted { lhs, rhs in
                lhs.activeStreamCount < rhs.activeStreamCount
            }
            for carrier in candidates {
                let onEnd: @Sendable () -> Void = { [weak self, weak carrier] in
                    guard let self, let carrier else { return }
                    self.noteStreamEnded(carrier)
                }
                do {
                    if let reservation = try carrier.reserveStream(
                        flowID: flowID,
                        maximumActiveFlows: NowhereMuxConstants.maximumActiveFlowsPerShard,
                        onEnd: onEnd
                    ) {
                        state.lastActivity[ObjectIdentifier(carrier)] = MonotonicClock.now
                        return .reserved((carrier, reservation))
                    }
                } catch {
                    if carrier.isClosed { continue }
                    throw error
                }
            }

            if let pending = state.extra.pendingBuild {
                return .build(pending)
            }
            state.extra.nextBuildIdentifier &+= 1
            let pending = PendingBuild(
                identifier: state.extra.nextBuildIdentifier,
                task: Task { [builder] in try await builder() }
            )
            state.extra.pendingBuild = pending
            return .build(pending)
        }
    }

    private func clearPendingBuild(identifier: UInt64) {
        pool.state.withLock { state in
            guard state.extra.pendingBuild?.identifier == identifier else { return }
            state.extra.pendingBuild = nil
        }
    }

    private func waitForBuild(_ pending: PendingBuild) async throws -> NowhereMuxCarrier {
        let resultInbox = AsyncInbox<Result<NowhereMuxCarrier, Error>>()
        let observer = Task {
            let result: Result<NowhereMuxCarrier, Error>
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
        _ carrier: NowhereMuxCarrier,
        from pending: PendingBuild
    ) -> (accepted: Bool, inserted: Bool) {
        var inserted = false
        let accepted = pool.state.withLock { state -> Bool in
            if state.extra.pendingBuild?.identifier == pending.identifier {
                state.extra.pendingBuild = nil
            }
            guard state.phase == .open, !carrier.isClosed else { return false }

            let identifier = ObjectIdentifier(carrier)
            if state.multiplexers[Self.bucket]?.contains(where: { $0 === carrier }) != true {
                state.multiplexers[Self.bucket, default: []].append(carrier)
                state.lastActivity[identifier] = MonotonicClock.now
                inserted = true
            }
            return true
        }
        return (accepted, inserted)
    }

    private func noteStreamEnded(_ carrier: NowhereMuxCarrier) {
        pool.state.withLock { state in
            let identifier = ObjectIdentifier(carrier)
            if state.lastActivity[identifier] != nil {
                state.lastActivity[identifier] = MonotonicClock.now
            }
        }
    }
}
