//
//  MITMLeafCertCache.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import CryptoKit
import Security

private let logger = AnywhereLogger(category: "MITM")

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

    /// Returns a leaf certificate for the given SNI, minting one if no
    /// fresh entry is cached.
    ///
    /// Throws if the CA is missing or signing fails — caller should treat
    /// it as a fatal handshake error.
    func leaf(for hostname: String) throws -> Leaf {
        let normalized = hostname.lowercased()
        lock.lock()
        if let entry = entries[normalized],
           entry.leaf.expiry.timeIntervalSince(Date()) > Self.refreshThreshold {
            // Touch the recency timestamp in place. Storing recency on the
            // entry keeps the cache-hit path O(1) and defers the O(n) scan for
            // an eviction victim to eviction time, which only runs on a cache
            // miss past the cap. On a browser launch hitting hundreds of hosts
            // the hit path is hot, so an O(n) update per hit would dominate it.
            entries[normalized]?.lastAccess = Date()
            let leaf = entry.leaf
            lock.unlock()
            return leaf
        }
        lock.unlock()

        // Mint outside the lock so a slow CA signature (worst case a
        // Secure-Enclave key) doesn't block lookups for *other* hosts. This is
        // the sole caller path and runs on the shared serial lwIP queue
        // (``MITMSession.start`` is documented "Must be called on lwipQueue"),
        // so there is no concurrency to dedup. A prior NSCondition single-flight
        // here was unreachable on a serial queue, and would have *deadlocked*
        // the whole tunnel the day ``leaf(for:)`` was ever called from a second
        // thread (a waiter blocking the very queue the leader needs to finish
        // on). If a second caller is ever added, two racing mints for the same
        // host each produce a valid leaf and the later store wins — harmless
        // duplicate work, never a deadlock.
        let leaf = try mintLeaf(for: normalized)

        lock.lock()
        entries[normalized] = CacheEntry(leaf: leaf, lastAccess: Date())
        evictIfNeededUnlocked()
        lock.unlock()

        return leaf
    }

    // NB: there is intentionally no `reset()`. CA rotation is not wired today,
    // and a naive cache clear would race a leader minting outside the lock —
    // its post-mint write would land a leaf signed by the *pre-rotation* CA. If
    // CA rotation is added later, gate the post-mint cache write on a CA
    // generation/fingerprint token so a mint started under the old CA can't
    // repopulate the cache, then add the clear.

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
        // Evict the LRU entry — the one whose ``lastAccess`` is
        // smallest — until we're back at or below the cap. ``min(by:)``
        // is O(n) but eviction runs only on cache miss past the cap,
        // and we evict at most one entry per miss in the steady state.
        while entries.count > Self.maxEntries {
            guard let oldest = entries.min(by: {
                $0.value.lastAccess < $1.value.lastAccess
            })?.key else { break }
            entries.removeValue(forKey: oldest)
        }
    }

    /// Imports the ephemeral leaf key into a Security.framework key reference.
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
