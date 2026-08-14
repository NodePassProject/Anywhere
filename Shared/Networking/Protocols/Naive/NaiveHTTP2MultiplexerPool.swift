//
//  NaiveHTTP2MultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 3/18/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP2Pool")

nonisolated final class NaiveHTTP2MultiplexerPool: TransportPool {

    static let shared = NaiveHTTP2MultiplexerPool()

    private typealias Base = MultiplexerPool<NaiveHTTP2Multiplexer, [ObjectIdentifier: NaiveHTTP2Multiplexer]>
    private let pool = Base(extra: [:])

    /// Unbounded mux count per key — H2 multiplexes heavily, so no soft/hard cap.
    private static let poolPolicy = MultiplexerPolicy(
        idleTimeout: 60,
        idleCheckInterval: 60
    )

    private init() {
        pool.startIdleEviction(Self.poolPolicy)
    }

    func reclaim() { closeAll() }

    // MARK: - Acquire

    /// Returns a stream on a pooled (or new) multiplexer. Chained connections (`tunnel != nil`)
    /// get a dedicated multiplexer because their transport path is unique.
    func acquireStream(
        host: String,
        port: UInt16,
        sni: String,
        tunnel: ProxyConnection?,
        connectHeaders: @escaping @Sendable () -> [(name: String, value: String)],
        destination: String
    ) async throws -> NaiveHTTP2Stream {
        if tunnel != nil {
            let multiplexer = NaiveHTTP2Multiplexer(
                host: host, port: port, sni: sni,
                tunnel: tunnel, connectHeaders: connectHeaders,
                onClose: { [weak self] multiplexer in
                    guard let self else { return }
                    self.pool.state.withLock { _ = $0.extra.removeValue(forKey: ObjectIdentifier(multiplexer)) }
                    logger.debug("[NaiveHTTP2Pool] Evicted dedicated multiplexer")
                }
            )
            pool.state.withLock { $0.extra[ObjectIdentifier(multiplexer)] = multiplexer }
            _ = multiplexer.tryReserveStream()
            return openStream(on: multiplexer, destination: destination)
        }

        let key = Base.makeKey(host: host, port: port, sni: sni)

        // Reserve the multiplexer under the gate; the async open runs after the gate is released
        // (never hold `state` across an `await`).
        let multiplexer: NaiveHTTP2Multiplexer = pool.state.withLock { st in
            // Park GOAWAY multiplexers in the dedicated map to drain, then evict them from the active bucket.
            if let array = st.multiplexers[key] {
                for s in array where s.poolIsGoingAway {
                    st.extra[ObjectIdentifier(s)] = s
                }
            }
            st.multiplexers[key]?.removeAll { $0.isClosed || $0.poolIsGoingAway }

            if let existing = st.multiplexers[key]?.first(where: { $0.tryReserveStream() }) {
                st.lastActivity[ObjectIdentifier(existing)] = MonotonicClock.now
                return existing
            } else {
                let capturedKey = key
                let new = NaiveHTTP2Multiplexer(
                    host: host, port: port, sni: sni,
                    tunnel: nil, connectHeaders: connectHeaders,
                    onClose: { [weak self] multiplexer in
                        self?.removeMultiplexer(multiplexer, key: capturedKey)
                    }
                )
                st.multiplexers[key, default: []].append(new)
                st.lastActivity[ObjectIdentifier(new)] = MonotonicClock.now
                _ = new.tryReserveStream()
                return new
            }
        }

        return openStream(on: multiplexer, destination: destination)
    }

    /// Creates a stream on the multiplexer (off the pool gate) and returns it. `openStream` now
    /// locks internally, so there is no queue hop to await.
    private func openStream(on multiplexer: NaiveHTTP2Multiplexer, destination: String) -> NaiveHTTP2Stream {
        multiplexer.openStream(destination: destination)
    }

    // MARK: - Eviction

    func removeMultiplexer(_ multiplexer: NaiveHTTP2Multiplexer, key: String) {
        pool.removeMultiplexer(multiplexer, key: key)
        pool.state.withLock { _ = $0.extra.removeValue(forKey: ObjectIdentifier(multiplexer)) }
        logger.debug("[NaiveHTTP2Pool] Evicted multiplexer for \(key)")
    }

    func closeAll() {
        let dedicated: [NaiveHTTP2Multiplexer] = pool.state.withLock { st in
            let dedicated = Array(st.extra.values)
            st.extra.removeAll()
            return dedicated
        }

        pool.drainAll()

        for multiplexer in dedicated {
            multiplexer.close()
        }
    }
}
