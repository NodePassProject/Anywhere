//
//  RequestLog.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation
import Synchronization

nonisolated final class RequestLog: Sendable {

    typealias Entry = TunnelRequestEntry

    private let entries = Mutex<[Entry]>([])
    private let defaultRouteTarget = Mutex<RouteTarget>(.direct)
    
    func setDefaultRouteTarget(_ target: RouteTarget) {
        defaultRouteTarget.withLock { $0 = target }
    }

    func record(
        protocol: TunnelRequestProtocol,
        host: String,
        port: UInt16,
        routeTarget: RouteTarget,
        ruleSetName: String? = nil
    ) {
        let now = CFAbsoluteTimeGetCurrent()
        let entry = Entry(
            timestamp: now,
            protocol: `protocol`,
            host: host,
            port: port,
            routeTarget: routeTarget,
            ruleSetName: ruleSetName,
            defaultRouteTarget: defaultRouteTarget.withLock { $0 }
        )
        entries.withLock { entries in
            entries.append(entry)
            Self.compact(&entries, now: now)
        }
    }
    
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
