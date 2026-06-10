//
//  FDPressureRelief.swift
//  Anywhere
//
//  Created by NodePassProject on 5/15/26.
//

import Foundation
import Darwin

// MARK: - FDReliefPriority

/// Priority tier for FD relief, keyed to failure visibility rather than wire
/// protocol (QUIC is `.userVisible` despite being UDP).
nonisolated enum FDReliefPriority {
    /// Failure is user-visible (TCP, or QUIC carrying proxied traffic).
    case userVisible
    /// Failure is tolerable (direct UDP; the app retransmits transparently).
    case bestEffort
}

// MARK: - FDPressureRelief

/// Process-wide hook invoked when `socket(2)` fails with `EMFILE`/`ENFILE`;
/// the handler evicts idle UDP flows and returns whether any FDs were freed.
/// The handler's `udpQueue.sync` hop is deadlock-safe: udpQueue never
/// sync-waits back on the caller's I/O queues.
enum FDPressureRelief {

    /// Must only be accessed under `handlerLock`.
    private static var _handler: ((FDReliefPriority) -> Bool)?
    private static let handlerLock = UnfairLock()

    /// Process-wide relief handler. `nil` outside of an active tunnel.
    static var handler: ((FDReliefPriority) -> Bool)? {
        get { handlerLock.withLock { _handler } }
        set { handlerLock.withLock { _handler = newValue } }
    }

    /// Invokes ``handler`` if set; returns whether any FDs were freed. The
    /// handler is snapshotted, then invoked outside the lock so a long relief
    /// doesn't block other lock users.
    @inline(__always)
    static func relieve(for priority: FDReliefPriority) -> Bool {
        let snapshot = handlerLock.withLock { _handler }
        return snapshot?(priority) ?? false
    }

    /// True when `errno` indicates per-process or system-wide FD exhaustion.
    @inline(__always)
    static func isFDExhaustion(_ err: Int32) -> Bool {
        err == EMFILE || err == ENFILE
    }
}
