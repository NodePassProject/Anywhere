//
//  RequestLog.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation

final class RequestLog {

    typealias Entry = TunnelRequestEntry

    private let lock = NSLock()
    private var entries: [Entry] = []

    /// Records one routing decision. Caller supplies the protocol, resolved host
    /// (domain if known, else IP literal), port, the route the connection took,
    /// and whether it fell through to the default outbound.
    func record(
        proto: String,
        host: String,
        port: UInt16,
        routeTarget: RouteTarget,
        viaDefault: Bool = false
    ) {
        let now = CFAbsoluteTimeGetCurrent()
        let entry = Entry(
            timestamp: now,
            proto: proto,
            host: host,
            port: port,
            routeTarget: routeTarget,
            viaDefault: viaDefault
        )
        lock.lock()
        entries.append(entry)
        compact(now: now)
        lock.unlock()
    }

    /// Returns all entries within the retention window. Safe to call
    /// from any thread.
    func snapshot() -> [Entry] {
        let now = CFAbsoluteTimeGetCurrent()
        lock.lock()
        compact(now: now)
        let result = entries
        lock.unlock()
        return result
    }

    /// Caller must hold ``lock``. Drops aged-out entries, then trims
    /// the oldest if the buffer still exceeds the entry cap.
    private func compact(now: CFAbsoluteTime) {
        let cutoff = now - TunnelConstants.requestLogRetentionInterval
        entries.removeAll { $0.timestamp < cutoff }
        if entries.count > TunnelConstants.requestLogMaxEntries {
            entries.removeFirst(entries.count - TunnelConstants.requestLogMaxEntries)
        }
    }
}
