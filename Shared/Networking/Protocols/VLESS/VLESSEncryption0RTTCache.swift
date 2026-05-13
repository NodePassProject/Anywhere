//
//  VLESSEncryption0RTTCache.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/13/26.
//

import Foundation

/// Process-wide cache of VLESS-encryption session resumption tickets.
///
/// When a server's response carries a non-zero ticket lifetime (set by
/// `SecondsFrom`/`SecondsTo` on the server side, returned in the 16-byte
/// ticket payload), the client may skip the PFS key exchange on subsequent
/// dials to the same `(host, port, encryption-config)` and instead replay
/// the cached ticket — the 0-RTT path in
/// `proxy/vless/encryption/client.go:113-129`.
///
/// Cache entries are keyed by the destination address plus the
/// canonical encryption config string so two outbounds talking to the
/// same host with different keys / xor / rtt settings don't collide.
final class VLESSEncryption0RTTCache {

    static let shared = VLESSEncryption0RTTCache()

    /// Snapshot of cached state. Returned by ``lookup(key:)`` and consumed
    /// by ``invalidate(key:matching:)`` so callers can prove they're
    /// invalidating the entry they actually used (not a newer one that
    /// raced in between).
    struct Entry {
        let pfsKey: Data
        let ticket: Data       // 16 bytes (encrypted form, used as AEAD context)
        let expire: Date
    }

    private let lock = UnfairLock()
    private var entries: [String: Entry] = [:]

    private init() {}

    /// Build the lookup key. Lowercases the host so DNS-style "Host" vs "host"
    /// captures don't fragment the cache; the colon separator keeps the host
    /// and port distinct even for IPv6 literals.
    static func cacheKey(host: String, port: UInt16, config: VLESSEncryptionConfig) -> String {
        "\(host.lowercased()):\(port)|\(config.encoded())"
    }

    /// Return the cached entry if it hasn't expired. An expired entry is
    /// proactively evicted so the next dial doesn't have to re-check the
    /// clock.
    func lookup(key: String) -> Entry? {
        lock.withLock {
            guard let entry = entries[key] else { return nil }
            if entry.expire <= Date() {
                entries.removeValue(forKey: key)
                return nil
            }
            return entry
        }
    }

    /// Store a fresh ticket. Overwrites any prior entry for the same key —
    /// this matches Go's `i.RWLock.Lock(); i.PfsKey = ...; i.Ticket = ...`
    /// pattern where the latest 1-RTT win takes over.
    func store(key: String, pfsKey: Data, ticket: Data, expire: Date) {
        lock.withLock {
            entries[key] = Entry(pfsKey: pfsKey, ticket: ticket, expire: expire)
        }
    }

    /// Drop a cached entry, but only if it still equals what the caller
    /// took out earlier — matches Go's `bytes.HasPrefix(c.UnitedKey,
    /// c.Client.PfsKey)` guard, which prevents stomping on a newer ticket
    /// installed by a successful concurrent 1-RTT handshake.
    func invalidate(key: String, matching pfsKey: Data) {
        lock.withLock {
            guard let entry = entries[key], entry.pfsKey == pfsKey else { return }
            entries.removeValue(forKey: key)
        }
    }

    /// Drop everything. Wired to the "disconnect VPN" path so a fresh
    /// connect doesn't reuse stale tickets from a previous session.
    func clear() {
        lock.withLock { entries.removeAll(keepingCapacity: false) }
    }
}
