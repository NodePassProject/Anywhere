//
//  FDPressureRelief.swift
//  Anywhere
//
//  Created by NodePassProject on 5/15/26.
//

import Foundation
import Darwin

// MARK: - FDReliefCaller

/// Identifies which transport hit `EMFILE` and is asking for relief. The
/// handler uses it to bias TCP over UDP — TCP failures are user-visible
/// (apps treat them as connection refused), while UDP is best-effort and
/// applications retransmit transparently.
enum FDReliefCaller {
    case tcp
    case udp
}

// MARK: - FDPressureRelief

/// Process-wide hook invoked when a raw `socket(2)` call fails with `EMFILE`
/// or `ENFILE`. The handler frees FDs (in practice by evicting idle
/// direct-bypass UDP flows from the lwIP stack) and returns whether anything
/// was freed; the socket layer then retries `socket(2)` once.
///
/// ``LWIPStack`` installs a handler at start that calls
/// ``LWIPStack/evictDirectUDPFlowsForFDPressure(caller:)`` on its serial
/// `lwipQueue`. Callers (``RawUDPSocket``, ``RawTCPSocket``,
/// ``QUICConnection``) invoke ``relieve(for:)`` from their own I/O queues;
/// the handler's `lwipQueue.sync` cross-hop is deadlock-safe because the
/// lwIP path never sync-waits on those queues.
enum FDPressureRelief {

    /// Backs ``handler``. Access only under ``handlerLock`` — the handler
    /// is mutated from `lwipQueue` (start/stop) while being read from
    /// arbitrary socket-creation queues; unsynchronized access to a Swift
    /// optional closure is a data race.
    private static var _handler: ((FDReliefCaller) -> Bool)?
    private static let handlerLock = UnfairLock()

    /// Process-wide relief handler. `nil` outside of an active tunnel.
    /// Setting and clearing happen on `lwipQueue` at tunnel start/stop;
    /// reads come from socket-creation queues via ``relieve(for:)``.
    static var handler: ((FDReliefCaller) -> Bool)? {
        get { handlerLock.withLock { _handler } }
        set { handlerLock.withLock { _handler = newValue } }
    }

    /// Invokes ``handler`` if set. Returns whether any FDs were freed.
    ///
    /// The handler reference is snapshotted under the lock and then
    /// invoked outside the lock so a long-running relief (which crosses
    /// into `lwipQueue.sync`) doesn't block concurrent reads or the
    /// `stop()` path's `handler = nil` write.
    @inline(__always)
    static func relieve(for caller: FDReliefCaller) -> Bool {
        let snapshot = handlerLock.withLock { _handler }
        return snapshot?(caller) ?? false
    }

    /// True when `errno` indicates per-process or system-wide FD exhaustion.
    @inline(__always)
    static func isFDExhaustion(_ err: Int32) -> Bool {
        err == EMFILE || err == ENFILE
    }
}
