//
//  MITMOriginCapabilityCache.swift
//  Anywhere
//
//  Created by NodePassProject on 6/3/26.
//

import Foundation

/// Origins that declined h2 at the ALPN layer; the next inner handshake drops h2 up front so
/// the client's retry completes instead of looping. Keyed by SNI; TTL'd, LRU-bounded, thread-safe.
final class MITMOriginCapabilityCache {

    /// Only HTTP/1.1-only origins land here, so 256 is generous; LRU-evicted at the cap.
    private static let maxEntries = 256

    /// Long enough to avoid per-session re-probes; short enough that an origin enabling h2 is noticed within the hour.
    private static let validity: TimeInterval = 60 * 60

    private struct Entry {
        var expiry: Date
        var lastAccess: Date
    }

    private let lock = UnfairLock()
    private var http1Only: [String: Entry] = [:]

    /// Records that `host` is HTTP/1.1-only; future inner legs will not offer `h2`.
    func markHTTP1Only(_ host: String) {
        let key = host.lowercased()
        let now = Date()
        lock.withLock {
            http1Only[key] = Entry(expiry: now.addingTimeInterval(Self.validity), lastAccess: now)
            if http1Only.count > Self.maxEntries {
                evictLocked(now: now)
            }
        }
    }

    /// True if `host` is known HTTP/1.1-only within its TTL; a hit refreshes LRU recency.
    func isHTTP1Only(_ host: String) -> Bool {
        let key = host.lowercased()
        let now = Date()
        return lock.withLock {
            guard let entry = http1Only[key] else { return false }
            if entry.expiry <= now {
                http1Only.removeValue(forKey: key)
                return false
            }
            http1Only[key]?.lastAccess = now
            return true
        }
    }

    /// Caller must hold `lock`; O(n) scans are fine on the rare over-capacity insert.
    private func evictLocked(now: Date) {
        http1Only = http1Only.filter { $0.value.expiry > now }
        while http1Only.count > Self.maxEntries {
            guard let oldest = http1Only.min(by: { $0.value.lastAccess < $1.value.lastAccess })?.key else { break }
            http1Only.removeValue(forKey: oldest)
        }
    }
}
