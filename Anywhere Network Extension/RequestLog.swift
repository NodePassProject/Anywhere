//
//  RequestLog.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation

/// Bounded ring buffer of recent per-connection routing decisions. One
/// instance per ``LWIPStack``; the main app pulls a snapshot via the
/// ``TunnelMessage/fetchRequests`` IPC and renders it in the Requests
/// view under Advanced Settings.
///
/// Mirrors the in-process log buffer pattern (``LWIPStack``'s log
/// entries): entries older than ``TunnelConstants/requestLogRetentionInterval``
/// or beyond ``TunnelConstants/requestLogMaxEntries`` are pruned on
/// each append and each fetch. Appends happen on ``lwipQueue`` (TCP
/// accept, UDP recv) and on the connection's own callback thread (SNI
/// override) — an ``NSLock`` keeps the per-append cost in the tens of
/// nanoseconds without ordering constraints.
final class RequestLog {

    typealias Entry = TunnelRequestEntry
    typealias Action = TunnelRequestAction

    private let lock = NSLock()
    private var entries: [Entry] = []

    /// Records one routing decision. Caller supplies the protocol,
    /// resolved host (domain if known, else IP literal), port, action,
    /// and optional configuration name.
    func record(
        proto: String,
        host: String,
        port: UInt16,
        action: Action,
        configurationName: String? = nil
    ) {
        let now = CFAbsoluteTimeGetCurrent()
        let entry = Entry(
            timestamp: now,
            proto: proto,
            host: host,
            port: port,
            action: action,
            configurationName: configurationName
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
