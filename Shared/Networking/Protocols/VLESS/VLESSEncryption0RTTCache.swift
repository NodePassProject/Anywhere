//
//  VLESSEncryption0RTTCache.swift
//  Anywhere
//
//  Created by NodePassProject on 5/13/26.
//

import Foundation
import Synchronization

/// Process-wide cache of 0-RTT resumption tickets, keyed by
/// `(host, port, encryption config)` so differing configs don't collide.
final class VLESSEncryption0RTTCache {

    static let shared = VLESSEncryption0RTTCache()

    /// Snapshot used for compare-and-invalidate, so callers remove the entry they
    /// actually used and not a newer one that raced in.
    struct Entry {
        let pfsKey: Data
        let ticket: Data       // 16 bytes
        let expire: CFAbsoluteTime
    }

    private let entries = Mutex<[String: Entry]>([:])

    private init() {}

    /// Lowercases the host to avoid case-fragmented entries.
    static func cacheKey(host: String, port: UInt16, config: VLESSEncryptionConfig) -> String {
        "\(host.lowercased()):\(port)|\(config.encoded())"
    }

    func lookup(key: String) -> Entry? {
        entries.withLock { entries in
            guard let entry = entries[key] else { return nil }
            if entry.expire <= CFAbsoluteTimeGetCurrent() {
                entries.removeValue(forKey: key)
                return nil
            }
            return entry
        }
    }

    /// Stores a fresh ticket; the latest 1-RTT handshake always wins.
    func store(key: String, pfsKey: Data, ticket: Data, expire: CFAbsoluteTime) {
        entries.withLock { entries in
            entries[key] = Entry(pfsKey: pfsKey, ticket: ticket, expire: expire)
        }
    }

    /// Drops the entry only if its pfsKey still matches, so a newer ticket from a
    /// concurrent 1-RTT handshake isn't stomped.
    func invalidate(key: String, matching pfsKey: Data) {
        entries.withLock { entries in
            guard let entry = entries[key], entry.pfsKey == pfsKey else { return }
            entries.removeValue(forKey: key)
        }
    }

    /// Wired to VPN disconnect so a fresh connect doesn't reuse stale tickets.
    func clear() {
        entries.withLock { $0.removeAll(keepingCapacity: false) }
    }
}
