//
//  FDPressureRelief.swift
//  Anywhere
//
//  Created by NodePassProject on 5/15/26.
//

import Foundation
import Darwin

// MARK: - FDReliefPriority

/// Priority tier of the connection asking for FD-pressure relief — *not* its
/// wire protocol. It names how user-visible a failure is so the relief handler
/// can bias eviction:
///
/// - ``userVisible``: a TCP connection, or QUIC carrying HTTP/3 or a proxy hop
///   — a failure surfaces to the user as "connection refused" or a stalled
///   page. Evicted for aggressively.
/// - ``bestEffort``: a direct UDP flow the application retransmits
///   transparently — failing it is acceptable. Evicted for conservatively.
///
/// Note that QUIC is `.userVisible` despite being UDP on the wire: the tier
/// tracks the consequence of failure, not the socket type.
nonisolated enum FDReliefPriority {
    /// Failure is user-visible (TCP, or QUIC carrying proxied traffic). The
    /// handler evicts aggressively so the caller's retry is likely to succeed.
    case userVisible
    /// Failure is tolerable (direct UDP, retransmitted by the app). The handler
    /// evicts conservatively; failing the new flow is fine when no truly-idle
    /// victim exists.
    case bestEffort
}

// MARK: - FDPressureRelief

/// Process-wide hook invoked when a raw `socket(2)` call fails with `EMFILE`
/// or `ENFILE`. The handler frees FDs (in practice by evicting idle
/// direct-bypass UDP flows from the lwIP stack) and returns whether anything
/// was freed; the socket layer then retries `socket(2)` once.
///
/// ``LWIPStack`` installs a handler at start that calls
/// ``LWIPStack/evictDirectUDPFlowsForFDPressure(priority:)`` on its serial
/// `lwipQueue`. Callers (``RawUDPSocket``, ``RawTCPSocket``,
/// ``QUICSocket``) invoke ``relieve(for:)`` from their own I/O queues;
/// the handler's `lwipQueue.sync` cross-hop is deadlock-safe because the
/// lwIP path never sync-waits on those queues.
enum FDPressureRelief {

    /// Backs ``handler``. Access only under ``handlerLock`` — the handler
    /// is mutated from `lwipQueue` (start/stop) while being read from
    /// arbitrary socket-creation queues; unsynchronized access to a Swift
    /// optional closure is a data race.
    private static var _handler: ((FDReliefPriority) -> Bool)?
    private static let handlerLock = UnfairLock()

    /// Process-wide relief handler. `nil` outside of an active tunnel.
    /// Setting and clearing happen on `lwipQueue` at tunnel start/stop;
    /// reads come from socket-creation queues via ``relieve(for:)``.
    static var handler: ((FDReliefPriority) -> Bool)? {
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
