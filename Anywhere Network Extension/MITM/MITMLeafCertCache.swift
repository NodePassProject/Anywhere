//
//  MITMLeafCertCache.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import CryptoKit
import Security
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMLeafCertCache")

nonisolated final class MITMLeafCertCache: Sendable {

    // MARK: - Public Types
    
    struct Leaf: Sendable {
        let certificate: SecCertificate
        let certificateDER: Data
        let privateKeySecKey: SecKey
        let privateKey: P256.Signing.PrivateKey
        let expiry: Date
    }

    // MARK: - Init

    private let store: MITMCertificateStore
    private let leafPrivateKey: P256.Signing.PrivateKey
    private let leafPrivateKeySecKey: SecKey

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
        let key = P256.Signing.PrivateKey()
        self.leafPrivateKey = key
        self.leafPrivateKeySecKey = try Self.importSoftwareP256(key)
    }

    /// Resolves a leaf for `hostname`, minting one off the caller if the cache misses.
    func leaf(for hostname: String) async throws -> Leaf {
        let normalized = hostname.lowercased()
        if let cached = cachedLeaf(for: normalized) {
            return cached
        }
        // Minting (X.509 build + Security import) runs off the caller so the lwIP queue isn't blocked.
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
        // Minting stays outside the lock; only the cache insert is locked.
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

        guard let secCert = SecCertificateCreateWithData(nil, der as CFData) else {
            throw AnywhereError.certificate(.asn1ParseFailed(detail: "SecCertificateCreateWithData failed"))
        }

        return Leaf(
            certificate: secCert,
            certificateDER: der,
            privateKeySecKey: leafPrivateKeySecKey,
            privateKey: leafPrivateKey,
            expiry: now.addingTimeInterval(Self.validity)
        )
    }

    private static func evictIfNeeded(_ entries: inout [String: CacheEntry]) {
        // O(n) scan tolerated: only runs on a cache miss past the cap.
        while entries.count > Self.maxEntries {
            guard let oldest = entries.min(by: {
                $0.value.lastAccess < $1.value.lastAccess
            })?.key else { break }
            entries.removeValue(forKey: oldest)
        }
    }

    private static func importSoftwareP256(_ key: P256.Signing.PrivateKey) throws(AnywhereError) -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, &error) else {
            let reason = error.map { ($0.takeRetainedValue() as Error).localizedDescription } ?? "SecKeyCreateWithData failed"
            throw AnywhereError.certificate(.keyGenerationFailed(detail: "leaf key import: \(reason)"))
        }
        return secKey
    }
}
