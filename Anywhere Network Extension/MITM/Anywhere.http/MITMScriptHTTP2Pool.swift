//
//  MITMScriptHTTP2Pool.swift
//  Anywhere
//
//  Created by NodePassProject on 7/2/26.
//

import Foundation
import Synchronization

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

    func reclaim() { pool.drainAll() }

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

        let (connection, didDial): (MITMScriptHTTP2Connection, Bool) = pool.state.withLock { state in
            state.multiplexers[key]?.removeAll { $0.isClosed || $0.poolIsGoingAway }

            if let existing = state.multiplexers[key]?.first(where: { $0.tryReserveStream() }) {
                state.lastActivity[ObjectIdentifier(existing)] = MonotonicClock.now
                return (existing, false)
            } else {
                let created = MITMScriptHTTP2Connection(
                    host: host, port: port, insecure: insecure,
                    onClose: { [weak self] connection in
                        self?.pool.removeMultiplexer(connection, key: key)
                    },
                    onNegotiatedHTTP1: { [weak self] in self?.markHTTP1(key) }
                )
                _ = created.tryReserveStream()
                state.multiplexers[key, default: []].append(created)
                state.lastActivity[ObjectIdentifier(created)] = MonotonicClock.now
                return (created, true)
            }
        }
        if didDial { pool.noteMultiplexersChanged() }

        do {
            let response = try await connection.perform(
                request: request,
                hostHeader: hostHeader,
                maxBytes: maxBytes,
                resourceTimeout: resourceTimeout
            )
            return .response(response)
        } catch AnywhereError.mitm(.needsHTTP1Fallback) {
            return .fallbackToHTTP1
        }
    }

    // MARK: - HTTP/1.1-only origin cache

    private func isKnownHTTP1(_ key: String) -> Bool {
        pool.state.withLock { state in
            guard let expiry = state.extra[key] else { return false }
            if MonotonicClock.now < expiry { return true }
            state.extra.removeValue(forKey: key)
            return false
        }
    }

    private func markHTTP1(_ key: String) {
        pool.state.withLock { state in
            if state.extra[key] == nil, state.extra.count >= Self.maxHTTP1Origins {
                if let oldest = state.extra.min(by: { $0.value < $1.value })?.key {
                    state.extra.removeValue(forKey: oldest)
                }
            }
            state.extra[key] = MonotonicClock.now + Self.http1TTL
        }
    }
}
