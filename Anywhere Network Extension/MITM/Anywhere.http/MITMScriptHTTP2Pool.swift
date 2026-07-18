//
//  MITMScriptHTTP2Pool.swift
//  Anywhere
//
//  Created by NodePassProject on 7/2/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMScriptHTTP2Pool")

nonisolated enum MITMScriptHTTP2Outcome {
    case response(MITMScriptHTTPClient.Response)
    case fallbackToHTTP1
}

nonisolated final class MITMScriptHTTP2Pool: TransportPool {

    static let shared = MITMScriptHTTP2Pool()

    private typealias Base = MultiplexerPool<MITMScriptHTTP2Connection, [String: TimeInterval]>
    private let pool = Base(extra: [:])

    private static let poolPolicy = MultiplexerPolicy(idleTimeout: 60, idleCheckInterval: 60)

    private static let http1TTL: TimeInterval = 600
    private static let maxHTTP1Origins = 256

    private init() {
        pool.startIdleEviction(Self.poolPolicy)
    }

    func reclaim() { pool.closeAll() }

    private static func originKey(host: String, port: UInt16, insecure: Bool) -> String {
        "\(host):\(port):\(insecure)"
    }

    // MARK: - Perform
    
    func perform(
        request: URLRequest,
        host: String,
        port: UInt16,
        hostHeader: String,
        insecure: Bool,
        maxBytes: Int,
        resourceTimeout: TimeInterval
    ) async throws -> MITMScriptHTTP2Outcome {
        let key = Self.originKey(host: host, port: port, insecure: insecure)
        if isKnownHTTP1(key) {
            return .fallbackToHTTP1
        }
        
        let connection: MITMScriptHTTP2Connection = pool.state.withLock { st in
            st.multiplexers[key]?.removeAll { $0.isClosed || $0.poolIsGoingAway }

            if let existing = st.multiplexers[key]?.first(where: { $0.tryReserveStream() }) {
                st.lastActivity[ObjectIdentifier(existing)] = MonotonicClock.now
                return existing
            } else {
                let new = MITMScriptHTTP2Connection(
                    host: host, port: port, insecure: insecure,
                    onClose: { [weak self] connection in
                        self?.pool.removeMultiplexer(connection, key: key)
                    },
                    onNegotiatedHTTP1: { [weak self] in self?.markHTTP1(key) }
                )
                _ = new.tryReserveStream()   // fresh connection always has capacity
                st.multiplexers[key, default: []].append(new)
                st.lastActivity[ObjectIdentifier(new)] = MonotonicClock.now
                return new
            }
        }

        do {
            let response = try await connection.perform(
                request: request,
                hostHeader: hostHeader,
                maxBytes: maxBytes,
                resourceTimeout: resourceTimeout
            )
            return .response(response)
        } catch MITMScriptHTTP2Error.needsHTTP1Fallback {
            return .fallbackToHTTP1
        }
    }

    // MARK: - HTTP/1.1-only origin cache

    private func isKnownHTTP1(_ key: String) -> Bool {
        pool.state.withLock { st in
            guard let expiry = st.extra[key] else { return false }
            if MonotonicClock.now < expiry { return true }
            st.extra.removeValue(forKey: key)
            return false
        }
    }

    private func markHTTP1(_ key: String) {
        pool.state.withLock { st in
            if st.extra[key] == nil, st.extra.count >= Self.maxHTTP1Origins {
                if let oldest = st.extra.min(by: { $0.value < $1.value })?.key {
                    st.extra.removeValue(forKey: oldest)
                }
            }
            st.extra[key] = MonotonicClock.now + Self.http1TTL
        }
        logger.debug("[MITMScriptHTTP2Pool] cached HTTP/1.1-only origin \(key)")
    }
}
