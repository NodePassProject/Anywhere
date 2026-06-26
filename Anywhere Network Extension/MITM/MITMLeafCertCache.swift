//
//  MITMLeafCertCache.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import CryptoKit
import Security

nonisolated private let logger = AnywhereLogger(category: "MITMLeafCertCache")

final class MITMLeafCertCache {

    // MARK: - Public Types

    struct Leaf {
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
    
    private static let mintQueue = DispatchQueue(
        label: AWCore.Identifier.mitmCertMintQueue,
        qos: .userInitiated,
        attributes: .concurrent,
        autoreleaseFrequency: .workItem
    )

    private let lock = UnfairLock()
    private var entries: [String: CacheEntry] = [:]

    private struct CacheEntry {
        let leaf: Leaf
        var lastAccess: Date
    }

    init(store: MITMCertificateStore) throws {
        self.store = store
        let key = P256.Signing.PrivateKey()
        self.leafPrivateKey = key
        self.leafPrivateKeySecKey = try Self.importSoftwareP256(key)
    }

    /// Resolves a leaf for `hostname`, minting one if the cache misses.
    func leaf(for hostname: String, completion: @escaping (Result<Leaf, Error>) -> Void) {
        let normalized = hostname.lowercased()
        if let cached = cachedLeaf(for: normalized) {
            completion(.success(cached))
            return
        }
        Self.mintQueue.async { [self] in
            completion(Result { try mintAndStore(for: normalized) })
        }
    }

    // MARK: - Internals

    private func cachedLeaf(for normalized: String) -> Leaf? {
        lock.lock()
        defer { lock.unlock() }
        guard let entry = entries[normalized],
              entry.leaf.expiry.timeIntervalSince(Date()) > Self.refreshThreshold else {
            return nil
        }
        entries[normalized]?.lastAccess = Date()
        return entry.leaf
    }

    private func mintAndStore(for normalized: String) throws -> Leaf {
        let leaf = try mintLeaf(for: normalized)
        lock.lock()
        entries[normalized] = CacheEntry(leaf: leaf, lastAccess: Date())
        evictIfNeededUnlocked()
        lock.unlock()
        return leaf
    }

    private func mintLeaf(for hostname: String) throws -> Leaf {
        guard let (caKey, caCertDER) = store.loadCA() else {
            throw MITMCertificateStoreError.missingCAComponents
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
            throw X509BuilderError.asn1ParseFailed("SecCertificateCreateWithData failed")
        }

        return Leaf(
            certificate: secCert,
            certificateDER: der,
            privateKeySecKey: leafPrivateKeySecKey,
            privateKey: leafPrivateKey,
            expiry: now.addingTimeInterval(Self.validity)
        )
    }

    private func evictIfNeededUnlocked() {
        // O(n) scan tolerated: only runs on a cache miss past the cap.
        while entries.count > Self.maxEntries {
            guard let oldest = entries.min(by: {
                $0.value.lastAccess < $1.value.lastAccess
            })?.key else { break }
            entries.removeValue(forKey: oldest)
        }
    }

    private static func importSoftwareP256(_ key: P256.Signing.PrivateKey) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, &error) else {
            _ = error?.takeRetainedValue()
            throw MITMCertificateStoreError.keyGenerationFailed("Failed to import leaf key")
        }
        return secKey
    }
}
