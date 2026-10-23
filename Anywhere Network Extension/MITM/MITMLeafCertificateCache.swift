//
//  MITMLeafCertificateCache.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import CryptoKit
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMLeafCertificateCache")

nonisolated final class MITMLeafCertificateCache: Sendable {

    // MARK: - Public Types

    struct Leaf: Sendable {
        let certificateDER: Data
        let privateKey: P256.Signing.PrivateKey
        let expiry: Date
    }

    // MARK: - Init

    private let store: MITMCertificateStore
    private let leafPrivateKey: P256.Signing.PrivateKey

    private static let maxEntries = 256
    private static let validity: TimeInterval = 7 * 24 * 60 * 60
    private static let refreshThreshold: TimeInterval = 24 * 60 * 60

    private struct State {
        var entries: [String: CacheEntry] = [:]
        var inFlight: [String: [CheckedContinuation<Leaf, Error>]] = [:]
    }
    private let state = Mutex(State())

    private let mintQueue = DispatchQueue(label: "com.argsment.Anywhere.MITMLeafCertificateCache", qos: .userInitiated)

    private struct CacheEntry {
        let leaf: Leaf
        var lastAccess: TimeInterval
    }

    private enum Lookup {
        case cached(Leaf)
        case joined
        case mint
    }

    init(store: MITMCertificateStore) throws(AnywhereError) {
        self.store = store
        self.leafPrivateKey = P256.Signing.PrivateKey()
    }

    func leaf(for hostname: String) async throws -> Leaf {
        let normalized = hostname.lowercased()
        return try await withCheckedThrowingContinuation { continuation in
            let lookup: Lookup = state.withLock { state in
                if let cached = Self.freshLeaf(for: normalized, in: &state.entries) {
                    return .cached(cached)
                }
                if state.inFlight[normalized] != nil {
                    state.inFlight[normalized]?.append(continuation)
                    return .joined
                }
                state.inFlight[normalized] = [continuation]
                return .mint
            }
            switch lookup {
            case .cached(let leaf):
                continuation.resume(returning: leaf)
            case .joined:
                break
            case .mint:
                mintQueue.async { [self] in
                    mintAndStore(for: normalized)
                }
            }
        }
    }

    // MARK: - Internals

    private static func freshLeaf(for normalized: String, in entries: inout [String: CacheEntry]) -> Leaf? {
        guard let entry = entries[normalized],
              entry.leaf.expiry.timeIntervalSince(Date()) > refreshThreshold else {
            return nil
        }
        entries[normalized]?.lastAccess = MonotonicClock.now
        return entry.leaf
    }

    private func mintAndStore(for normalized: String) {
        let result = Result { try mintLeaf(for: normalized) }
        let waiters = state.withLock { state -> [CheckedContinuation<Leaf, Error>] in
            if case .success(let leaf) = result {
                state.entries[normalized] = CacheEntry(leaf: leaf, lastAccess: MonotonicClock.now)
                Self.evictIfNeeded(&state.entries)
            }
            return state.inFlight.removeValue(forKey: normalized) ?? []
        }
        for waiter in waiters {
            waiter.resume(with: result)
        }
    }

    private func mintLeaf(for hostname: String) throws -> Leaf {
        guard let (caPrivateKey, caCertificateDER) = store.loadCA() else {
            throw AnywhereError.certificate(.missingCAComponents)
        }

        let now = Date()
        let serial = store.nextSerial()
        let der = try X509Builder.buildLeafCertificate(
            leafPublicKey: leafPrivateKey.publicKey,
            caPrivateKey: caPrivateKey,
            caCertificateDER: caCertificateDER,
            hostname: hostname,
            serial: serial,
            notBefore: now.addingTimeInterval(-60 * 60),
            notAfter: now.addingTimeInterval(Self.validity)
        )

        return Leaf(
            certificateDER: der,
            privateKey: leafPrivateKey,
            expiry: now.addingTimeInterval(Self.validity)
        )
    }

    private static func evictIfNeeded(_ entries: inout [String: CacheEntry]) {
        while entries.count > Self.maxEntries {
            guard let oldest = entries.min(by: {
                $0.value.lastAccess < $1.value.lastAccess
            })?.key else { break }
            entries.removeValue(forKey: oldest)
        }
    }
}
