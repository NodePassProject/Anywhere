//
//  RequestLog.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation
import Synchronization

final class RequestLog {

    typealias Entry = TunnelRequestEntry

    private let entries = Mutex<[Entry]>([])

    /// Records one routing decision; `host` is the domain if known, else the IP literal.
    func record(
        protocolName: String,
        host: String,
        port: UInt16,
        routeTarget: RouteTarget,
        viaDefault: Bool = false
    ) {
        let now = CFAbsoluteTimeGetCurrent()
        let entry = Entry(
            timestamp: now,
            protocolName: protocolName,
            host: host,
            port: port,
            routeTarget: routeTarget,
            viaDefault: viaDefault
        )
        entries.withLock { entries in
            entries.append(entry)
            Self.compact(&entries, now: now)
        }
    }

    /// Returns all entries within the retention window; safe from any thread.
    func snapshot() -> [Entry] {
        let now = CFAbsoluteTimeGetCurrent()
        return entries.withLock { entries in
            Self.compact(&entries, now: now)
            return entries
        }
    }

    private static func compact(_ entries: inout [Entry], now: CFAbsoluteTime) {
        let cutoff = now - TunnelConstants.requestLogRetentionInterval
        entries.removeAll { $0.timestamp < cutoff }
        if entries.count > TunnelConstants.requestLogMaxEntries {
            entries.removeFirst(entries.count - TunnelConstants.requestLogMaxEntries)
        }
    }
}
