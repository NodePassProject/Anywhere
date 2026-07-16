//
//  NaiveHTTP2MultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 3/18/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP2Pool")

/// Pools HTTP/2 multiplexers keyed by `host:port:sni` so many CONNECT tunnels share one
/// TCP/TLS connection; multiplexers self-evict via `onClose` on GOAWAY or transport close.
nonisolated final class NaiveHTTP2MultiplexerPool: MultiplexerPool<NaiveHTTP2Multiplexer> {

    static let shared = NaiveHTTP2MultiplexerPool()

    /// Dedicated (non-pooled) multiplexers for chained connections, and
    /// post-GOAWAY multiplexers retained until their in-flight streams drain.
    private var dedicatedMultiplexers: [ObjectIdentifier: NaiveHTTP2Multiplexer] = [:]

    /// Unbounded mux count per key — H2 multiplexes heavily, so no soft/hard cap.
    private static let poolPolicy = MultiplexerPolicy(
        idleTimeout: 60,
        idleCheckInterval: 60
    )

    private override init() {
        super.init()
        startIdleEviction(Self.poolPolicy)
    }

    // MARK: - Acquire

    /// Returns a stream on a pooled (or new) multiplexer. Chained connections (`tunnel != nil`)
    /// get a dedicated multiplexer because their transport path is unique.
    func acquireStream(
        host: String,
        port: UInt16,
        sni: String,
        tunnel: ProxyConnection?,
        connectHeaders: @escaping () -> [(name: String, value: String)],
        destination: String
    ) async throws -> NaiveHTTP2Stream {
        if tunnel != nil {
            let multiplexer = NaiveHTTP2Multiplexer(
                host: host, port: port, sni: sni,
                tunnel: tunnel, connectHeaders: connectHeaders
            )
            let multiplexerID = ObjectIdentifier(multiplexer)
            lock.withLock { _ in dedicatedMultiplexers[multiplexerID] = multiplexer }
            multiplexer.onClose = { [weak self] in
                guard let self else { return }
                self.lock.withLock { _ in self.dedicatedMultiplexers.removeValue(forKey: multiplexerID) }
                logger.debug("[NaiveHTTP2Pool] Evicted dedicated multiplexer")
            }
            return openStream(on: multiplexer, destination: destination)
        }

        let key = Self.makeKey(host: host, port: port, sni: sni)

        // Reserve the multiplexer under the gate; the async open runs after the gate is released
        // (never hold `lock` across an `await`).
        let multiplexer: NaiveHTTP2Multiplexer = lock.withLock { _ in
            // Park GOAWAY multiplexers in dedicatedMultiplexers to drain, then evict them from the active bucket.
            if let array = multiplexers[key] {
                for s in array where s.poolIsGoingAway {
                    dedicatedMultiplexers[ObjectIdentifier(s)] = s
                }
            }
            multiplexers[key]?.removeAll { $0.isClosed || $0.poolIsGoingAway }

            if let existing = multiplexers[key]?.first(where: { $0.tryReserveStream() }) {
                lastActivity[ObjectIdentifier(existing)] = MonotonicClock.now
                return existing
            } else {
                let new = NaiveHTTP2Multiplexer(
                    host: host, port: port, sni: sni,
                    tunnel: nil, connectHeaders: connectHeaders
                )
                let capturedKey = key
                new.onClose = { [weak self, weak new] in
                    guard let self, let new else { return }
                    self.removeMultiplexer(new, key: capturedKey)
                }
                multiplexers[key, default: []].append(new)
                lastActivity[ObjectIdentifier(new)] = MonotonicClock.now
                return new
            }
        }

        return await openStream(on: multiplexer, destination: destination)
    }

    /// Creates a stream on the multiplexer (off the pool gate) and returns it. `openStream` now
    /// locks internally, so there is no queue hop to await.
    private func openStream(on multiplexer: NaiveHTTP2Multiplexer, destination: String) -> NaiveHTTP2Stream {
        multiplexer.openStream(destination: destination)
    }

    // MARK: - Eviction

    override func removeMultiplexer(_ multiplexer: NaiveHTTP2Multiplexer, key: String) {
        super.removeMultiplexer(multiplexer, key: key)
        lock.withLock { _ in dedicatedMultiplexers.removeValue(forKey: ObjectIdentifier(multiplexer)) }
        logger.debug("[NaiveHTTP2Pool] Evicted multiplexer for \(key)")
    }

    override func closeAll() {
        let dedicated: [NaiveHTTP2Multiplexer] = lock.withLock { _ in
            let dedicated = Array(dedicatedMultiplexers.values)
            dedicatedMultiplexers.removeAll()
            return dedicated
        }

        super.closeAll()

        for multiplexer in dedicated {
            multiplexer.close()
        }
    }
}
