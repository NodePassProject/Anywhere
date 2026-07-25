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
    
    static let entryTTL: TimeInterval = DNSResolver.defaultTTL
    
    static let lookupDeadline: Duration = .seconds(4)

    private enum Outcome {
        case address(String)
        case failed
    }

    private struct Entry {
        let outcome: Outcome
        let expiry: CFAbsoluteTime
    }

    private struct State {
        var cache: [String: Entry] = [:]
        var order: [String] = []
        var inFlight: [String: Task<String?, Never>] = [:]
        var upstream: DNSUpstream = .system
        var generation: UInt64 = 0
    }

    private let state = Mutex(State())
    
    private let blockingBridge = DNSSyscallConcurrencyBridge()

    private init() {}

    // MARK: - Public API
    
    func cachedIPv4(for domain: String) -> String? {
        let key = Self.key(for: domain)
        return state.withLock { state in
            guard let entry = state.cache[key], entry.expiry > CFAbsoluteTimeGetCurrent(),
                  case .address(let ip) = entry.outcome
            else { return nil }
            return ip
        }
    }
    
    func resolveIPv4(for domain: String, within deadline: Duration = RuleResolver.lookupDeadline) async -> String? {
        switch lookupAction(for: Self.key(for: domain)) {
        case .cached(let ip):
            return ip
        case .join(let task):
            return await Self.value(of: task, within: deadline)
        }
    }
    
    func warm(_ domain: String) {
        _ = lookupAction(for: Self.key(for: domain))
    }

    func setUpstream(_ upstream: DNSUpstream) {
        let changed: Bool = state.withLock { state in
            guard state.upstream != upstream else { return false }
            state.upstream = upstream
            state.generation &+= 1
            state.cache.removeAll(keepingCapacity: true)
            state.order.removeAll(keepingCapacity: true)
            state.inFlight.removeAll(keepingCapacity: true)
            return true
        }
        guard changed else { return }
        logger.debug("[RuleResolver] Upstream changed; cache flushed")
    }

    // MARK: - Internal

    private enum Action {
        case cached(String?)
        case join(Task<String?, Never>)
    }
    
    private func lookupAction(for key: String) -> Action {
        state.withLock { state in
            if let entry = state.cache[key], entry.expiry > CFAbsoluteTimeGetCurrent() {
                switch entry.outcome {
                case .address(let ip): return .cached(ip)
                case .failed: return .cached(nil)
                }
            }
            if let existing = state.inFlight[key] {
                return .join(existing)          // await the in-flight leader
            }
            let upstream = state.upstream
            let scheduledGeneration = state.generation
            let task = Task<String?, Never> { [self] in
                await lookup(key, upstream: upstream, scheduledGeneration: scheduledGeneration)
            }
            state.inFlight[key] = task
            return .join(task)
        }
    }
    
    private static func value(of task: Task<String?, Never>, within deadline: Duration) async -> String? {
        await withCheckedContinuation { continuation in
            let winner = RaceClaim()
            let expiry = Task {
                do { try await Task.sleep(for: deadline) } catch { return }
                if winner.claim() { continuation.resume(returning: nil) }
            }
            Task {
                let ip = await task.value
                expiry.cancel()
                if winner.claim() { continuation.resume(returning: ip) }
            }
        }
    }

    private func lookup(_ key: String, upstream: DNSUpstream, scheduledGeneration: UInt64) async -> String? {
        let ip = await resolve(key, upstream: upstream)
        state.withLock { state in
            guard scheduledGeneration == state.generation else { return }
            state.inFlight[key] = nil
            Self.store(&state, key: key, outcome: ip.map(Outcome.address) ?? .failed)
        }
        if let ip {
            logger.debug("[RuleResolver] Resolved \(key) → \(ip) for IP-rule matching")
        }
        return ip
    }

    private func resolve(_ key: String, upstream: DNSUpstream) async -> String? {
        guard !upstream.isSystem else {
            return await blockingBridge.run { Self.resolveIPv4(key) }
        }
        do {
            return try await DNSUpstreamClient.resolve(key, via: upstream, family: .ipv4).first
        } catch {
            logger.warning("[RuleResolver] IP-rule lookup for \(key) failed, skipping IP matching: \(error)")
            return nil
        }
    }
    
    private static func store(_ state: inout State, key: String, outcome: Outcome) {
        let now = CFAbsoluteTimeGetCurrent()
        if state.cache[key] == nil { state.order.append(key) }
        state.cache[key] = Entry(outcome: outcome, expiry: now + Self.entryTTL)

        if state.cache.contains(where: { $0.value.expiry <= now }) {
            state.cache = state.cache.filter { $0.value.expiry > now }
            let live = state.cache
            state.order.removeAll { live[$0] == nil }
        }

        while state.cache.count > Self.maxEntries, !state.order.isEmpty {
            let oldest = state.order.removeFirst()
            state.cache.removeValue(forKey: oldest)
        }
    }
    
    private static func key(for domain: String) -> String {
        for byte in domain.utf8
        where (byte >= UInt8(ascii: "A") && byte <= UInt8(ascii: "Z")) || byte >= 0x80 {
            return domain.lowercased()
        }
        return domain
    }
    
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
                    return String(nulTerminated: buffer)   // first IPv4 wins — one IP per domain
                }
            }
            current = info.pointee.ai_next
        }
        return nil
    }
}
