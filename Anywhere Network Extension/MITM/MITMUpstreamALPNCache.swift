//
//  MITMUpstreamALPNCache.swift
//  Anywhere
//
//  Created by NodePassProject on 10/24/26.
//

import Foundation
import Synchronization

nonisolated final class MITMUpstreamALPNCache: Sendable {
    private static let maxEntries = 256

    private struct Key: Hashable {
        let host: String
        let port: UInt16

        init(host: String, port: UInt16) {
            self.host = host.lowercased()
            self.port = port
        }
    }

    private let http1OnlyLastAccess = Mutex<[Key: TimeInterval]>([:])

    func lacksHTTP2(host: String, port: UInt16) -> Bool {
        let key = Key(host: host, port: port)
        return http1OnlyLastAccess.withLock { entries in
            guard entries[key] != nil else { return false }
            entries[key] = MonotonicClock.now
            return true
        }
    }

    func record(negotiatedALPN: String, host: String, port: UInt16) {
        let key = Key(host: host, port: port)
        http1OnlyLastAccess.withLock { entries in
            guard negotiatedALPN != "h2" else {
                entries.removeValue(forKey: key)
                return
            }
            entries[key] = MonotonicClock.now
            Self.evictIfNeeded(&entries)
        }
    }

    private static func evictIfNeeded(_ entries: inout [Key: TimeInterval]) {
        while entries.count > maxEntries {
            guard let oldest = entries.min(by: { $0.value < $1.value })?.key else { break }
            entries.removeValue(forKey: oldest)
        }
    }
}
