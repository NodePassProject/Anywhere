//
//  QUICDatagramTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 5/19/26.
//

import Foundation

/// Datagram transport `QUICConnection` can ride in place of a kernel socket.
/// `sendDatagram` is fire-and-forget for transient pressure — QUIC's loss
/// recovery handles those — but terminal transport failures (peer reset,
/// TLS broken, chain hop closed) MUST surface through the `errorHandler`
/// installed by `startReceiving` so the QUIC layer fails fast instead of
/// idling out on the keep-alive PING. `startReceiving` MUST deliver exactly
/// one whole datagram per `handler` call (empty datagrams forbidden — use
/// `errorHandler` to express EOF). Callbacks may fire on any queue.
protocol QUICDatagramTransport: AnyObject {
    func sendDatagram(_ data: Data)

    /// `errorHandler` fires on terminal failure; do not `sendDatagram` after.
    func startReceiving(handler: @escaping (Data) -> Void,
                        errorHandler: @escaping (Error?) -> Void)

    /// Tears down the transport. Idempotent.
    func cancel()
}

/// Adapts a `ProxyConnection` (e.g. from a chain's UDP-relay last hop) to
/// `QUICDatagramTransport`. The wrapped connection has already encoded its
/// destination, so each datagram is opaque payload to/from one fixed peer.
final class ProxyConnectionDatagramTransport: QUICDatagramTransport {
    private let connection: ProxyConnection

    /// Latched on the first terminal transport failure. Send-side and
    /// receive-side errors funnel through `surfaceFailure` so the QUIC
    /// layer's `errorHandler` fires at most once even when both sides
    /// observe the break (which is common: a TLS write failure on the
    /// inner usually also breaks the read side a moment later).
    ///
    /// Without this, a chained Hysteria whose inner relay died between
    /// receives would sit idle until ngtcp2's 10 s keep-alive PING failed —
    /// a UDP-only workload (no receive in flight to surface the error)
    /// could stall for the full keep-alive window plus PTO.
    private let failureLock = UnfairLock()
    private var failureHandler: ((Error?) -> Void)?
    private var failed = false

    init(connection: ProxyConnection) {
        self.connection = connection
    }

    func sendDatagram(_ data: Data) {
        connection.send(data: data) { [weak self] error in
            guard let error else { return }
            // Per-datagram failures from the inner are NOT terminal: they
            // mean the inner couldn't carry THIS packet (PMTU shrank, the
            // outer-QUIC packet doesn't fit in 255 Hysteria fragments, the
            // inner's send queue overflowed under burst, …). The outer
            // QUIC's loss recovery handles the drop the same way it'd
            // handle a regular packet loss — surfacing it as a terminal
            // transport failure here would tear down the outer connection
            // on what is, on the wire, a single dropped datagram. Mostly
            // hit by double-chained Hysteria where the inner's per-packet
            // path MTU is more variable than the outer's ngtcp2 PMTUD
            // has had time to discover.
            if Self.isTransientDatagramError(error) { return }
            self?.surfaceFailure(error)
        }
    }

    /// Errors from `connection.send` that indicate "this one datagram
    /// didn't fit" rather than "the transport is broken". The outer QUIC
    /// must NOT close on these — it should just lose the datagram and
    /// let its own loss recovery decide what to do.
    ///
    /// The terminal set is small and explicit: anything that proves the
    /// inner connection is gone (`streamClosed`, the outer-QUIC's own
    /// `closed`, auth-rejection from a re-handshaked inner session).
    /// Everything else — fragmentation refusals, queue overflows, MTU
    /// collapses — is per-packet.
    private static func isTransientDatagramError(_ error: Error) -> Bool {
        if let qErr = error as? QUICConnection.QUICError {
            switch qErr {
            case .closed, .streamReset, .streamClosedWithError, .handshakeFailed:
                return false
            case .datagramTooLarge, .connectionFailed, .streamError, .timeout:
                return true
            }
        }
        if let hErr = error as? HysteriaError {
            switch hErr {
            case .streamClosed, .authRejected, .udpNotSupported,
                 .destinationTooLargeForDatagram:
                // `destinationTooLargeForDatagram` is permanent for this
                // flow's destination — the header size never shrinks —
                // and propagating it terminal lets the QUIC layer fail
                // fast on the per-flow address being unusable, instead
                // of silently retrying every loss-recovery cycle.
                return false
            case .notReady, .connectionFailed, .tunnelFailed:
                // `connectionFailed` from Hysteria's UDP path carries
                // per-packet outcomes like "UDP payload too large to
                // fragment". `notReady` is a transient session-state
                // window. None of these warrant killing the outer
                // transport.
                return true
            }
        }
        return false
    }

    func startReceiving(handler: @escaping (Data) -> Void,
                        errorHandler: @escaping (Error?) -> Void) {
        failureLock.withLock { self.failureHandler = errorHandler }
        connection.startReceiving(handler: handler, errorHandler: { [weak self] err in
            self?.surfaceFailure(err)
        })
    }

    func cancel() {
        connection.cancel()
    }

    /// Forwards the latched `errorHandler` exactly once, regardless of
    /// whether the failure was observed on the send or receive side.
    private func surfaceFailure(_ error: Error?) {
        let handler: ((Error?) -> Void)? = failureLock.withLock {
            guard !failed else { return nil }
            failed = true
            let h = failureHandler
            failureHandler = nil
            return h
        }
        handler?(error)
    }
}
