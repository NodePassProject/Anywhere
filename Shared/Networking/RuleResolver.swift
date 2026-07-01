//
//  RuleResolver.swift
//  Anywhere
//
//  Created by NodePassProject on 7/1/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "RuleResolver")

nonisolated final class RuleResolver {
    static let shared = RuleResolver()
    
    static let maxEntries = 1024

    /// Lowercased domain → IPv4 string.
    private var cache: [String: String] = [:]
    /// Insertion order of cached keys, for cheap FIFO eviction at the cap.
    private var order: [String] = []
    /// Domains with a background resolve in flight; coalesces duplicate lookups.
    private var inFlight: Set<String> = []

    private let lock = ReadWriteLock()

    private init() {}

    // MARK: - Public API

    /// Cached IPv4 for `domain`, or `nil` if not yet resolved. Never blocks.
    func cachedIPv4(for domain: String) -> String? {
        let key = Self.key(for: domain)
        return lock.withReadLock { cache[key] }
    }

    /// Ensures `domain` is (being) resolved so a later ``cachedIPv4(for:)`` can
    /// hit. No-op when already cached or already in flight. Never blocks.
    func warm(_ domain: String) {
        let key = Self.key(for: domain)
        let shouldResolve: Bool = lock.withWriteLock {
            if cache[key] != nil || inFlight.contains(key) { return false }
            inFlight.insert(key)
            return true
        }
        guard shouldResolve else { return }

        DispatchQueue.global(qos: .utility).async { [self] in
            let ip = Self.resolveIPv4(key)
            lock.withWriteLock {
                inFlight.remove(key)
                guard let ip else { return }
                store(key: key, ip: ip)
            }
            if let ip {
                logger.debug("[RuleResolver] Resolved \(key) → \(ip) for IP-rule matching")
            }
        }
    }

    // MARK: - Internal

    /// Inserts `key`, then evicts oldest entries past the cap. Caller must hold
    /// the write lock.
    private func store(key: String, ip: String) {
        if cache[key] == nil { order.append(key) }
        cache[key] = ip

        while cache.count > Self.maxEntries, !order.isEmpty {
            let oldest = order.removeFirst()
            cache.removeValue(forKey: oldest)
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
