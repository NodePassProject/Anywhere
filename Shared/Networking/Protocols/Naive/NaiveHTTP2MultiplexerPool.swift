//
//  NaiveHTTP2MultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 3/18/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP2Pool")

/// Pools HTTP/2 multiplexers keyed by `host:port:sni` so many CONNECT tunnels share one
/// TCP/TLS connection; multiplexers self-evict via `onClose` on GOAWAY or transport close.
nonisolated final class NaiveHTTP2MultiplexerPool: MultiplexerPool<NaiveHTTP2Multiplexer> {

    static let shared = NaiveHTTP2MultiplexerPool()

    /// Dedicated (non-pooled) multiplexers for chained connections, and
    /// post-GOAWAY multiplexers retained until their in-flight streams drain.
    private var dedicatedMultiplexers: [ObjectIdentifier: NaiveHTTP2Multiplexer] = [:]

    private override init() {}

    // MARK: - Acquire

    /// Returns a stream on a pooled (or new) multiplexer. Chained connections (`tunnel != nil`)
    /// get a dedicated multiplexer because their transport path is unique.
    func acquireStream(
        host: String,
        port: UInt16,
        sni: String,
        tunnel: ProxyConnection?,
        connectHeaders: @escaping () -> [(name: String, value: String)],
        destination: String,
        completion: @escaping (NaiveHTTP2Stream) -> Void
    ) {
        if tunnel != nil {
            let multiplexer = NaiveHTTP2Multiplexer(
                host: host, port: port, sni: sni,
                tunnel: tunnel, connectHeaders: connectHeaders
            )
            let multiplexerID = ObjectIdentifier(multiplexer)
            lock.lock()
            dedicatedMultiplexers[multiplexerID] = multiplexer
            lock.unlock()
            multiplexer.onClose = { [weak self] in
                guard let self else { return }
                self.lock.lock()
                self.dedicatedMultiplexers.removeValue(forKey: multiplexerID)
                self.lock.unlock()
                logger.debug("[NaiveHTTP2Pool] Evicted dedicated multiplexer")
            }
            multiplexer.queue.async {
                let stream = multiplexer.openStream(destination: destination)
                completion(stream)
            }
            return
        }

        let key = Self.makeKey(host: host, port: port, sni: sni)
        let multiplexer: NaiveHTTP2Multiplexer

        lock.lock()
        // Park GOAWAY multiplexers in dedicatedMultiplexers to drain, then evict them from the active bucket.
        if let array = multiplexers[key] {
            for s in array where s.poolIsGoingAway {
                dedicatedMultiplexers[ObjectIdentifier(s)] = s
            }
        }
        multiplexers[key]?.removeAll { $0.isClosed || $0.poolIsGoingAway }

        if let existing = multiplexers[key]?.first(where: { $0.tryReserveStream() }) {
            multiplexer = existing
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
            multiplexer = new
        }
        lock.unlock()

        multiplexer.queue.async {
            let stream = multiplexer.openStream(destination: destination)
            completion(stream)
        }
    }

    // MARK: - Eviction

    /// Removes the multiplexer from both the pool bucket and ``dedicatedMultiplexers``.
    override func removeMultiplexer(_ multiplexer: NaiveHTTP2Multiplexer, key: String) {
        super.removeMultiplexer(multiplexer, key: key)
        lock.lock()
        dedicatedMultiplexers.removeValue(forKey: ObjectIdentifier(multiplexer))
        lock.unlock()
        logger.debug("[NaiveHTTP2Pool] Evicted multiplexer for \(key)")
    }

    override func closeAll() {
        lock.lock()
        let dedicated = Array(dedicatedMultiplexers.values)
        dedicatedMultiplexers.removeAll()
        lock.unlock()

        super.closeAll()

        for multiplexer in dedicated {
            multiplexer.close()
        }
    }
}
