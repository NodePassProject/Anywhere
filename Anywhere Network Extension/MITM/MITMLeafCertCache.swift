//
//  MITMLeafCertCache.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import CryptoKit
import Security

private let logger = AnywhereLogger(category: "MITMLeafCertCache")

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
    private static let validity: TimeInterval = 7 * 24 * 60 * 60         // 7 days
    private static let refreshThreshold: TimeInterval = 24 * 60 * 60     // refresh within 1 day of expiry

    private let lock = NSLock()
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

    /// Returns a cached leaf for the SNI, minting one if absent or near expiry; throws on CA/signing failure.
    func leaf(for hostname: String) throws -> Leaf {
        let normalized = hostname.lowercased()
        lock.lock()
        if let entry = entries[normalized],
           entry.leaf.expiry.timeIntervalSince(Date()) > Self.refreshThreshold {
            entries[normalized]?.lastAccess = Date()
            let leaf = entry.leaf
            lock.unlock()
            return leaf
        }
        lock.unlock()

        // Mint outside the lock; deliberately no single-flight — racing mints both produce
        // valid leaves, while blocking a waiter on the serial lwIP queue would deadlock.
        let leaf = try mintLeaf(for: normalized)

        lock.lock()
        entries[normalized] = CacheEntry(leaf: leaf, lastAccess: Date())
        evictIfNeededUnlocked()
        lock.unlock()

        return leaf
    }

    // Intentionally no reset(): a naive clear races the lock-free mint path and could
    // repopulate with a pre-rotation leaf; CA rotation would need a generation token.

    // MARK: - Internals

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
        // O(n) LRU eviction; only runs on a cache miss past the cap.
        while entries.count > Self.maxEntries {
            guard let oldest = entries.min(by: {
                $0.value.lastAccess < $1.value.lastAccess
            })?.key else { break }
            entries.removeValue(forKey: oldest)
        }
    }

    /// Wraps the ephemeral P256 key as a Security.framework `SecKey`.
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
