//
//  QUICDatagramTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 5/19/26.
//

import Foundation

/// Datagram transport used by `QUICConnection` in place of a kernel socket. Terminal failures
/// MUST surface through `errorHandler` so QUIC fails fast rather than idling on keep-alive PINGs;
/// `startReceiving` delivers exactly one whole, non-empty datagram per call (use `errorHandler`
/// for EOF). Callbacks may fire on any queue.
protocol QUICDatagramTransport: AnyObject {
    func sendDatagram(_ data: Data)

    /// `errorHandler` fires on terminal failure; do not `sendDatagram` after.
    func startReceiving(handler: @escaping (Data) -> Void,
                        errorHandler: @escaping (Error?) -> Void)

    /// Tears down the transport. Idempotent.
    func cancel()
}

/// Adapts a `ProxyConnection` whose destination is already encoded; each datagram
/// is opaque payload to/from one fixed peer.
final class ProxyConnectionDatagramTransport: QUICDatagramTransport {
    private let connection: ProxyConnection

    /// Guards `errorHandler` so it fires at most once across send- and receive-side failures.
    private let failureLock = UnfairLock()
    private var failureHandler: ((Error?) -> Void)?
    private var failed = false

    init(connection: ProxyConnection) {
        self.connection = connection
    }

    func sendDatagram(_ data: Data) {
        connection.send(data: data) { [weak self] error in
            guard let error else { return }
            // Transient errors (PMTU shrink, fragmentation refusal, queue overflow) are
            // NOT terminal — outer QUIC loss recovery treats the drop as ordinary loss.
            if Self.isTransientDatagramError(error) { return }
            self?.surfaceFailure(error)
        }
    }

    /// True for per-datagram errors ("this packet didn't fit"), false for terminal
    /// ones ("the transport is broken"); the outer QUIC must NOT close on transient errors.
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
                // destinationTooLargeForDatagram is permanent — the Hysteria header
                // never shrinks for this destination — so fail fast.
                return false
            case .notReady, .connectionFailed, .tunnelFailed:
                // connectionFailed covers per-packet outcomes; notReady is a
                // transient session-state window.
                return true
            }
        }
        if let nErr = error as? NowhereError {
            switch nErr {
            case .streamClosed, .authFailed, .invalidTargetLength,
                 .destinationTooLargeForDatagram:
                return false
            case .notReady, .connectionFailed:
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

    /// Forwards the latched `errorHandler` exactly once.
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
