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

        if let entry = entries[normalized] {
            let now = Date()
            if entry.leaf.expiry.timeIntervalSince(now) > Self.refreshThreshold {
                // Touch the recency timestamp in place. Previously
                // this also walked an ``accessOrder`` array via
                // ``firstIndex(of:)`` + ``remove(at:)`` + ``append`` —
                // O(n) per hit, which on a browser launch hitting
                // hundreds of hosts dominates the hot path. Storing
                // recency directly on the entry makes the hit path
                // O(1) and defers the O(n) walk to eviction time,
                // which only runs once per cache miss past the cap.
                entries[normalized]?.lastAccess = now
                lock.unlock()
                return entry.leaf
            }
            entries.removeValue(forKey: normalized)
        }
        lock.unlock()

        let minted = try mintLeaf(for: normalized)

        lock.lock()
        defer { lock.unlock() }
        entries[normalized] = CacheEntry(leaf: minted, lastAccess: Date())
        evictIfNeededUnlocked()
        return minted
    }

    func reset() {
        lock.lock()
        entries.removeAll()
        lock.unlock()
    }

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
