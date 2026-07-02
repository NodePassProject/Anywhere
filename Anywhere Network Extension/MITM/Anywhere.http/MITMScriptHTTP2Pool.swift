//
//  MITMScriptHTTP2Pool.swift
//  Anywhere
//
//  Created by NodePassProject on 7/2/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "MITMScriptHTTP2Pool")

enum MITMScriptHTTP2Outcome {
    case response(MITMScriptHTTPClient.Response)
    /// The origin doesn't speak `h2`; the caller should retry over HTTP/1.1.
    case fallbackToHTTP1
    case failure(Error)
}

/// Pools multiplexed HTTP/2 connections per origin so concurrent script requests share one TCP+TLS connection.
nonisolated final class MITMScriptHTTP2Pool: MultiplexerPool<MITMScriptHTTP2Connection> {

    static let shared = MITMScriptHTTP2Pool()

    /// No per-key connection cap; h2 multiplexes heavily.
    private static let poolPolicy = MultiplexerPolicy(idleTimeout: 60, idleCheckInterval: 60)

    /// HTTP/1.1-only origins → expiry time (`MonotonicClock`). Guarded by the base `lock`.
    private var http1Origins: [String: TimeInterval] = [:]
    private static let http1TTL: TimeInterval = 600
    private static let maxHTTP1Origins = 256

    private override init() {
        super.init()
        startIdleEviction(Self.poolPolicy)
    }

    private static func originKey(host: String, port: UInt16, insecure: Bool) -> String {
        "\(host):\(port):\(insecure)"
    }

    // MARK: - Perform

    /// Runs one request over a pooled (or newly dialed) HTTP/2 connection. `completion` fires once.
    func perform(
        request: URLRequest,
        host: String,
        port: UInt16,
        hostHeader: String,
        insecure: Bool,
        maxBytes: Int,
        resourceTimeout: TimeInterval,
        completion: @escaping (MITMScriptHTTP2Outcome) -> Void
    ) {
        let key = Self.originKey(host: host, port: port, insecure: insecure)
        if isKnownHTTP1(key) {
            completion(.fallbackToHTTP1)
            return
        }

        let connection: MITMScriptHTTP2Connection
        lock.lock()
        multiplexers[key]?.removeAll { $0.isClosed || $0.poolIsGoingAway }

        if let existing = multiplexers[key]?.first(where: { $0.tryReserveStream() }) {
            lastActivity[ObjectIdentifier(existing)] = MonotonicClock.now
            connection = existing
        } else {
            let new = MITMScriptHTTP2Connection(host: host, port: port, insecure: insecure)
            new.onClose = { [weak self, weak new] in
                guard let self, let new else { return }
                self.removeMultiplexer(new, key: key)
            }
            new.onNegotiatedHTTP1 = { [weak self] in self?.markHTTP1(key) }
            _ = new.tryReserveStream()   // fresh connection always has capacity
            multiplexers[key, default: []].append(new)
            lastActivity[ObjectIdentifier(new)] = MonotonicClock.now
            connection = new
        }
        lock.unlock()

        connection.perform(
            request: request,
            hostHeader: hostHeader,
            maxBytes: maxBytes,
            resourceTimeout: resourceTimeout
        ) { result in
            switch result {
            case .success(let response):
                completion(.response(response))
            case .failure(let error):
                if case MITMScriptHTTP2Error.needsHTTP1Fallback = error {
                    completion(.fallbackToHTTP1)
                } else {
                    completion(.failure(error))
                }
            }
        }
    }

    // MARK: - HTTP/1.1-only origin cache

    private func isKnownHTTP1(_ key: String) -> Bool {
        lock.withLock {
            guard let expiry = http1Origins[key] else { return false }
            if MonotonicClock.now < expiry { return true }
            http1Origins.removeValue(forKey: key)
            return false
        }
    }

    private func markHTTP1(_ key: String) {
        lock.withLock {
            if http1Origins[key] == nil, http1Origins.count >= Self.maxHTTP1Origins {
                if let oldest = http1Origins.min(by: { $0.value < $1.value })?.key {
                    http1Origins.removeValue(forKey: oldest)
                }
            }
            http1Origins[key] = MonotonicClock.now + Self.http1TTL
        }
        logger.debug("[MITMScriptHTTP2Pool] cached HTTP/1.1-only origin \(key)")
    }
}
