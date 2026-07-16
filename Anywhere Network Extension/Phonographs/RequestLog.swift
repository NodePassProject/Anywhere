//
//  RequestLog.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation
import Synchronization

nonisolated final class RequestLog {

    typealias Entry = TunnelRequestEntry

    private let entries = Mutex<[Entry]>([])

    /// Records one routing decision; `host` is the domain if known, else the IP literal.
    /// `ruleSetName` names the rule set behind the decision, nil for default routes.
    func record(
        protocol: TunnelRequestProtocol,
        host: String,
        port: UInt16,
        routeTarget: RouteTarget,
        viaDefault: Bool = false,
        ruleSetName: String? = nil
    ) {
        let now = CFAbsoluteTimeGetCurrent()
        let entry = Entry(
            timestamp: now,
            protocol: `protocol`,
            host: host,
            port: port,
            routeTarget: routeTarget,
            viaDefault: viaDefault,
            ruleSetName: ruleSetName
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
