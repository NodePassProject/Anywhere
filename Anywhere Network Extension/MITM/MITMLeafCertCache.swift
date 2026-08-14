//
//  MITMLeafCertCache.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import CryptoKit
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMLeafCertCache")

nonisolated final class MITMLeafCertCache: Sendable {

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

    private let entries = Mutex<[String: CacheEntry]>([:])

    private struct CacheEntry {
        let leaf: Leaf
        var lastAccess: Date
    }

    init(store: MITMCertificateStore) throws(AnywhereError) {
        self.store = store
        self.leafPrivateKey = P256.Signing.PrivateKey()
    }

    func leaf(for hostname: String) async throws -> Leaf {
        let normalized = hostname.lowercased()
        if let cached = cachedLeaf(for: normalized) {
            return cached
        }
        return try await Task.detached(priority: .userInitiated) { [self] in
            try mintAndStore(for: normalized)
        }.value
    }

    // MARK: - Internals

    private func cachedLeaf(for normalized: String) -> Leaf? {
        entries.withLock { entries in
            guard let entry = entries[normalized],
                  entry.leaf.expiry.timeIntervalSince(Date()) > Self.refreshThreshold else {
                return nil
            }
            entries[normalized]?.lastAccess = Date()
            return entry.leaf
        }
    }

    private func mintAndStore(for normalized: String) throws -> Leaf {
        let leaf = try mintLeaf(for: normalized)
        entries.withLock { entries in
            entries[normalized] = CacheEntry(leaf: leaf, lastAccess: Date())
            Self.evictIfNeeded(&entries)
        }
        return leaf
    }

    private func mintLeaf(for hostname: String) throws -> Leaf {
        guard let (caKey, caCertDER) = store.loadCA() else {
            throw AnywhereError.certificate(.missingCAComponents)
        }

        let now = Date()
        let serial = store.nextSerial()
        let der = try X509Builder.buildLeafCertificate(
            leafPublicKey: leafPrivateKey.publicKey,
            caPrivateKey: caKey,
            caCertificateDER: caCertDER,
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
