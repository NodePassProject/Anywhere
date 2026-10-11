//
//  DNSLookupCache.swift
//  Anywhere
//
//  Created by NodePassProject on 10/9/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "DNSLookupCache")

nonisolated final class DNSLookupCache<Key: Hashable & Sendable, Value: Sendable>: Sendable {
    typealias Lookup = @Sendable () async -> (value: Value, ttl: TimeInterval)?

    private struct Entry: Sendable {
        let value: Value
        let expiry: TimeInterval
    }

    private enum Outcome: Sendable {
        case resolved(Value)
        case failed
    }

    private struct State: Sendable {
        var entries: [Key: Entry] = [:]
        var inFlight: [Key: LookupBroadcast<Outcome>] = [:]
        var upstream: DNSUpstream?
        var generation: UInt64 = 0
    }

    private enum Join {
        case hit(Value)
        case wait(LookupBroadcast<Outcome>, stale: Value?)
    }

    private let state = Mutex(State())
    private let name: String
    private let capacity: Int
    private let missing: Value
    private let servesStaleOnFailure: Bool
    private let waitLimit: Duration?
    
    init(name: String, capacity: Int, missing: Value, servesStaleOnFailure: Bool = false, waitLimit: Duration? = nil) {
        self.name = name
        self.capacity = capacity
        self.missing = missing
        self.servesStaleOnFailure = servesStaleOnFailure
        self.waitLimit = waitLimit
    }

    // MARK: - Public API

    func cachedValue(for key: Key, from upstream: DNSUpstream) -> Value? {
        state.withLock { state in
            adopt(upstream, in: &state)
            guard let entry = state.entries[key], entry.expiry > MonotonicClock.now else { return nil }
            return entry.value
        }
    }
    
    func value(
        for key: Key,
        from upstream: DNSUpstream,
        forceFresh: Bool = false,
        lookup: @escaping Lookup
    ) async -> Value {
        switch join(key, from: upstream, forceFresh: forceFresh, lookup: lookup) {
        case .hit(let value):
            return value
        case .wait(let pending, let stale):
            if case .resolved(let value) = await wait(for: pending) { return value }
            return servesStaleOnFailure ? (stale ?? missing) : missing
        }
    }

    func warm(_ key: Key, from upstream: DNSUpstream, lookup: @escaping Lookup) {
        _ = join(key, from: upstream, forceFresh: false, lookup: lookup)
    }

    @discardableResult
    func flush() -> Int {
        state.withLock { state in
            let count = state.entries.count
            Self.reset(&state)
            return count
        }
    }

    // MARK: - Internal

    private func join(_ key: Key, from upstream: DNSUpstream, forceFresh: Bool, lookup: @escaping Lookup) -> Join {
        state.withLock { state in
            adopt(upstream, in: &state)
            let entry = state.entries[key]
            if let entry, !forceFresh, entry.expiry > MonotonicClock.now { return .hit(entry.value) }
            if let existing = state.inFlight[key] {
                return .wait(existing, stale: entry?.value)
            }

            let pending = LookupBroadcast<Outcome>()
            let scheduledGeneration = state.generation
            state.inFlight[key] = pending
            Task { [self] in
                let result = await lookup()
                store(result, for: key, scheduledGeneration: scheduledGeneration, pending: pending)
                let outcome: Outcome = result.map { .resolved($0.value) } ?? .failed
                pending.publish(outcome)
            }
            return .wait(pending, stale: entry?.value)
        }
    }

    private func wait(for pending: LookupBroadcast<Outcome>) async -> Outcome {
        guard let waitLimit else { return await pending.value(orOnCancel: .failed) }
        return await withTaskGroup(of: Outcome.self) { group in
            group.addTask { await pending.value(orOnCancel: .failed) }
            group.addTask {
                try? await Task.sleep(for: waitLimit, precision: .relaxed)
                return .failed
            }
            defer { group.cancelAll() }
            return await group.next() ?? .failed
        }
    }

    private func store(
        _ result: (value: Value, ttl: TimeInterval)?,
        for key: Key,
        scheduledGeneration: UInt64,
        pending: LookupBroadcast<Outcome>
    ) {
        state.withLock { state in
            if state.inFlight[key] === pending { state.inFlight.removeValue(forKey: key) }
            guard scheduledGeneration == state.generation, let result else { return }
            let now = MonotonicClock.now
            state.entries[key] = Entry(value: result.value, expiry: now + result.ttl)
            Self.compact(&state.entries, now: now, capacity: capacity)
        }
    }
    
    private func adopt(_ upstream: DNSUpstream, in state: inout State) {
        guard state.upstream != upstream else { return }
        if state.upstream != nil {
            logger.info("[DNS] \(name) DNS upstream changed; cache flushed")
        }
        state.upstream = upstream
        Self.reset(&state)
    }

    private static func reset(_ state: inout State) {
        state.generation &+= 1
        state.entries.removeAll(keepingCapacity: true)
        state.inFlight.removeAll(keepingCapacity: true)
    }

    private static func compact(_ entries: inout [Key: Entry], now: TimeInterval, capacity: Int) {
        if entries.contains(where: { $0.value.expiry <= now }) {
            entries = entries.filter { $0.value.expiry > now }
        }

        while entries.count > capacity {
            guard let coldest = entries.min(by: { $0.value.expiry < $1.value.expiry })?.key
            else { break }
            entries.removeValue(forKey: coldest)
        }
    }
}

private nonisolated final class LookupBroadcast<Value: Sendable>: Sendable {
    private enum Enrollment: Sendable {
        case published(Value)
        case enrolled
    }

    private struct State {
        var value: Value?
        var waiters: [UInt64: CheckedContinuation<Value, Never>] = [:]
        var nextWaiterID: UInt64 = 0
    }

    private let state = Mutex(State())

    func publish(_ value: Value) {
        let waiters: [CheckedContinuation<Value, Never>] = state.withLock { state in
            state.value = value
            let drained = Array(state.waiters.values)
            state.waiters.removeAll()
            return drained
        }
        for waiter in waiters { waiter.resume(returning: value) }
    }

    func value(orOnCancel fallback: Value) async -> Value {
        let waiterID: UInt64 = state.withLock { state in
            state.nextWaiterID &+= 1
            return state.nextWaiterID
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Value, Never>) in
                let enrollment: Enrollment = state.withLock { state in
                    if let value = state.value { return .published(value) }
                    state.waiters[waiterID] = continuation
                    return .enrolled
                }
                switch enrollment {
                case .published(let value):
                    continuation.resume(returning: value)
                case .enrolled:
                    if Task.isCancelled { withdraw(waiterID, fallback: fallback) }
                }
            }
        } onCancel: {
            withdraw(waiterID, fallback: fallback)
        }
    }

    private func withdraw(_ waiterID: UInt64, fallback: Value) {
        let waiter = state.withLock { $0.waiters.removeValue(forKey: waiterID) }
        waiter?.resume(returning: fallback)
    }
}
