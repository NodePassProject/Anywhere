//
//  RuleResolver.swift
//  Anywhere
//
//  Created by NodePassProject on 7/1/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "RuleResolver")

nonisolated final class RuleResolver: Sendable {
    static let shared = RuleResolver()

    static let maxEntries = 1024

    private struct State {
        /// Lowercased domain → IPv4 string.
        var cache: [String: String] = [:]
        /// Insertion order of cached keys, for cheap FIFO eviction at the cap.
        var order: [String] = []
        /// Domains with a background resolve in flight; coalesces duplicate lookups.
        var inFlight: Set<String> = []
    }

    private let state = Mutex(State())

    private init() {}

    // MARK: - Public API

    /// Cached IPv4 for `domain`, or `nil` if not yet resolved. Never blocks.
    func cachedIPv4(for domain: String) -> String? {
        let key = Self.key(for: domain)
        return state.withLock { $0.cache[key] }
    }

    /// Ensures `domain` is (being) resolved so a later ``cachedIPv4(for:)`` can
    /// hit. No-op when already cached or already in flight. Never blocks.
    func warm(_ domain: String) {
        let key = Self.key(for: domain)
        let shouldResolve: Bool = state.withLock { state in
            if state.cache[key] != nil || state.inFlight.contains(key) { return false }
            state.inFlight.insert(key)
            return true
        }
        guard shouldResolve else { return }

        Task.detached(priority: .utility) { [self] in
            let ip = Self.resolveIPv4(key)
            state.withLock { state in
                state.inFlight.remove(key)
                guard let ip else { return }
                Self.store(&state, key: key, ip: ip)
            }
            if let ip {
                logger.debug("[RuleResolver] Resolved \(key) → \(ip) for IP-rule matching")
            }
        }
    }

    // MARK: - Internal

    /// Inserts `key`, then evicts oldest entries past the cap.
    private static func store(_ state: inout State, key: String, ip: String) {
        if state.cache[key] == nil { state.order.append(key) }
        state.cache[key] = ip

        while state.cache.count > Self.maxEntries, !state.order.isEmpty {
            let oldest = state.order.removeFirst()
            state.cache.removeValue(forKey: oldest)
        }
    }

    /// Lowercased lookup key, avoiding an allocation for the common
    /// all-lowercase-ASCII case.
    private static func key(for domain: String) -> String {
        for byte in domain.utf8
        where (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z")) || byte >= 0x80 {
            return domain.lowercased()
        }
        return domain
    }

    /// Blocking A-record resolution on the physical interface, returning the
    /// first IPv4 only. Runs on a background queue.
    private static func resolveIPv4(_ host: String) -> String? {
        var hints = addrinfo()
        hints.ai_family = AF_INET          // IPv4 only
        hints.ai_socktype = SOCK_STREAM

        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0, let res = result else { return nil }
        defer { freeaddrinfo(res) }

        var current: UnsafeMutablePointer<addrinfo>? = res
        while let info = current {
            if info.pointee.ai_family == AF_INET {
                var address = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &address.sin_addr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil {
                    return String(cString: buffer)   // first IPv4 wins — one IP per domain
                }
            }
            current = info.pointee.ai_next
        }
        return nil
    }
}
