//
//  RequestLog.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation

final class RequestLog {

    typealias Entry = TunnelRequestEntry

    private let lock = UnfairLock()
    private var entries: [Entry] = []

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
        lock.lock()
        entries.append(entry)
        compact(now: now)
        lock.unlock()
    }

    /// Returns all entries within the retention window; safe from any thread.
    func snapshot() -> [Entry] {
        let now = CFAbsoluteTimeGetCurrent()
        lock.lock()
        compact(now: now)
        let result = entries
        lock.unlock()
        return result
    }

    /// Caller must hold `lock`.
    private func compact(now: CFAbsoluteTime) {
        let cutoff = now - TunnelConstants.requestLogRetentionInterval
        entries.removeAll { $0.timestamp < cutoff }
        if entries.count > TunnelConstants.requestLogMaxEntries {
            entries.removeFirst(entries.count - TunnelConstants.requestLogMaxEntries)
        }
    }
}
