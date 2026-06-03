//
//  MITMOriginCapabilityCache.swift
//  Anywhere
//
//  Created by NodePassProject on 6/3/26.
//

import Foundation

/// Per-origin memory of upstreams that declined HTTP/2 at the ALPN layer.
///
/// The MITM negotiates the inner (client-facing) TLS leg *before* it dials the
/// upstream — the dial target only resolves once the first request has been
/// parsed (after URL rewrite), which requires a completed inner handshake. So
/// the inner leg has to commit to an ALPN from the client's offer alone,
/// preferring `h2`. If the upstream then turns out to be HTTP/1.1-only the legs
/// can't be bridged (there is no h2 ⇄ http/1.1 translation) and the session
/// tears down. The client retries — but with nothing remembered it re-offers
/// `h2`, the inner leg commits to `h2` again, and it loops.
///
/// This cache breaks the loop. When an upstream declines `h2` — either by
/// returning an empty ALPN or by sending `no_application_protocol` — the origin
/// is recorded here, and the next inner handshake for the same host drops `h2`
/// from the offer up front. The client then negotiates `http/1.1`, the upstream
/// accepts it, and the connection completes without a teardown.
///
/// Entries expire after ``validity`` so an origin that later enables HTTP/2 is
/// re-probed (costing a single teardown+retry). The map is bounded by
/// ``maxEntries`` with least-recently-used eviction. Keyed by the client's SNI
/// (the only host known at inner-handshake time, and stable across the client's
/// retries). Shared by every session and safe for concurrent use.
final class MITMOriginCapabilityCache {

    /// Upper bound on remembered hosts. Only HTTP/1.1-only origins land here
    /// (the h2 majority never does), so this is generous; past the cap the
    /// least-recently-looked-up entry is evicted.
    private static let maxEntries = 256

    /// How long an HTTP/1.1-only verdict stays trusted. Long enough to cover a
    /// browsing session — so a host isn't re-probed (i.e. torn down) every few
    /// requests — and short enough that enabling HTTP/2 on an origin is noticed
    /// within the hour.
    private static let validity: TimeInterval = 60 * 60

    private struct Entry {
        var expiry: Date
        var lastAccess: Date
    }

    private let lock = UnfairLock()
    private var http1Only: [String: Entry] = [:]

    /// Records that `host` could not bridge `h2`, so its inner leg should offer
    /// only `http/1.1` from now until the entry expires.
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

    /// Whether `host` is known — within the TTL — to be HTTP/1.1-only, so the
    /// inner leg should not offer `h2`. A hit refreshes the entry's recency.
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

    /// Cap enforcement, called under ``lock`` from ``markHTTP1Only`` only — and
    /// only on the rare insert that tips the map over ``maxEntries``, so the
    /// O(n) scans are cold. Reclaims expired entries first (free), then evicts
    /// the least-recently-looked-up host until back under the cap.
    private func evictLocked(now: Date) {
        http1Only = http1Only.filter { $0.value.expiry > now }
        while http1Only.count > Self.maxEntries {
            guard let oldest = http1Only.min(by: { $0.value.lastAccess < $1.value.lastAccess })?.key else { break }
            http1Only.removeValue(forKey: oldest)
        }
    }
}
