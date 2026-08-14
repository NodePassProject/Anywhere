//
//  NaiveHTTP3MultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP3MultiplexerPool")

nonisolated final class NaiveHTTP3MultiplexerPool: TransportPool {

    static let shared = NaiveHTTP3MultiplexerPool()

    private typealias Base = MultiplexerPool<HTTP3Multiplexer, Void>
    private typealias PoolState = Base.PoolState
    private let pool = Base(extra: ())

    private static let poolPolicy = MultiplexerPolicy(
        idleTimeout: 60,
        idleCheckInterval: 60,
        softCapPerKey: 8,
        hardCapPerKey: 16
    )

    private init() {
        pool.startIdleEviction(Self.poolPolicy)
    }

    func reclaim() { pool.drainAll() }

    // MARK: - Acquire

    func acquireStream(
        host: String,
        port: UInt16,
        sni: String,
        configuration: NaiveConfiguration,
        destination: String
    ) async throws -> NaiveHTTP3Stream {
        let key = Base.makeKey(host: host, port: port, sni: sni)

        enum Plan { case ready(HTTP3Multiplexer); case closeVictimThenCreate(HTTP3Multiplexer) }
        var prunedVictims: [HTTP3Multiplexer] = []
        let plan: Plan = pool.state.withLock { state in
            prunedVictims = pruneDead(key: key, &state)

            if let existing = state.multiplexers[key]?.first(where: { $0.tryReserveStream() }) {
                state.lastActivity[ObjectIdentifier(existing)] = MonotonicClock.now
                return .ready(existing)
            }
            if let overflow = overflowSession(key: key, &state) {
                state.lastActivity[ObjectIdentifier(overflow)] = MonotonicClock.now
                return .ready(overflow)
            }

            let currentCount = state.multiplexers[key]?.count ?? 0
            let softCap = state.policy?.softCapPerKey ?? 0
            if softCap > 0, currentCount >= softCap,
               let victim = state.multiplexers[key]?.first(where: { !$0.hasActiveStreams }) {
                return .closeVictimThenCreate(victim)
            }
            return .ready(makeAndRegisterMultiplexer(key: key, host: host, port: port, sni: sni, &state))
        }

        for victim in prunedVictims { victim.close() }

        let multiplexer: HTTP3Multiplexer
        switch plan {
        case .ready(let ready):
            multiplexer = ready
        case .closeVictimThenCreate(let victim):
            victim.close()
            multiplexer = pool.state.withLock { st in
                st.multiplexers[key]?.removeAll { $0 === victim }
                st.lastActivity.removeValue(forKey: ObjectIdentifier(victim))
                return makeAndRegisterMultiplexer(key: key, host: host, port: port, sni: sni, &st)
            }
        }

        guard multiplexer.noteStreamStarted() else {
            throw AnywhereError.proxy(.http3, .connectionClosed(detail: "Session closed"))
        }
        return NaiveHTTP3Stream(multiplexer: multiplexer, configuration: configuration, destination: destination)
    }

    private func makeAndRegisterMultiplexer(key: String, host: String, port: UInt16, sni: String, _ st: inout PoolState) -> HTTP3Multiplexer {
        let new = HTTP3Multiplexer(host: host, port: port, serverName: sni)
        new.setOnClose { [weak self, weak new] in
            guard let self, let new else { return }
            self.pool.removeMultiplexer(new, key: key)
        }
        st.multiplexers[key, default: []].append(new)
        st.lastActivity[ObjectIdentifier(new)] = MonotonicClock.now
        _ = new.tryReserveStream()
        return new
    }

    private func overflowSession(key: String, _ state: inout PoolState) -> HTTP3Multiplexer? {
        let hardCap = state.policy?.hardCapPerKey ?? 0
        guard hardCap > 0, let pool = state.multiplexers[key], pool.count >= hardCap else {
            return nil
        }
        let candidate = pool
            .filter { !$0.isClosed && !$0.poolIsStreamBlocked }
            .min(by: { $0.activeStreamCount < $1.activeStreamCount })
        guard let candidate, candidate.forceReserveStream() else { return nil }
        logger.warning("[HTTP3Pool] Pool hit hard cap (\(hardCap)) for \(key); overflowing onto existing multiplexer")
        return candidate
    }

    // MARK: - Eviction

    private func pruneDead(key: String, _ state: inout PoolState) -> [HTTP3Multiplexer] {
        guard let current = state.multiplexers[key] else { return [] }
        var toClose: [HTTP3Multiplexer] = []
        var survivors: [HTTP3Multiplexer] = []
        for multiplexer in current {
            if multiplexer.isClosed {
                state.lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
                continue
            }
            if multiplexer.poolIsStreamBlocked && !multiplexer.hasActiveStreams {
                state.lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
                toClose.append(multiplexer)
                continue
            }
            survivors.append(multiplexer)
        }
        if survivors.isEmpty {
            state.multiplexers.removeValue(forKey: key)
        } else {
            state.multiplexers[key] = survivors
        }
        return toClose
    }
}
