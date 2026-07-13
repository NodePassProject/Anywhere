//
//  QUICDatagramTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 5/19/26.
//

import Foundation
import Synchronization

/// Terminal failures MUST surface through `errorHandler` so QUIC fails fast rather than idling on
/// keep-alive PINGs; `startReceiving` delivers exactly one whole, non-empty datagram per call (use
/// `errorHandler` for EOF). Callbacks may fire on any queue.
protocol QUICDatagramTransport: AnyObject {
    func sendDatagram(_ data: Data)

    /// `errorHandler` fires on terminal failure; do not `sendDatagram` after.
    func startReceiving(handler: @escaping (Data) -> Void,
                        errorHandler: @escaping (Error?) -> Void)

    /// Tears down the transport. Idempotent.
    func cancel()
}

final class ProxyConnectionDatagramTransport: QUICDatagramTransport {
    private let connection: ProxyConnection

    /// Guards `errorHandler` so it fires at most once across send- and receive-side failures.
    private struct FailureState {
        var handler: ((Error?) -> Void)?
        var failed = false
    }

    private let failureState = Mutex(FailureState())

    init(connection: ProxyConnection) {
        self.connection = connection
    }

    func sendDatagram(_ data: Data) {
        connection.send(data: data) { [weak self] error in
            guard let error else { return }
            // Transient errors (PMTU shrink, fragmentation refusal, queue overflow) are not
            // terminal — outer QUIC loss recovery treats the drop as ordinary loss.
            if Self.isTransientDatagramError(error) { return }
            self?.surfaceFailure(error)
        }
    }

    /// True for per-datagram errors (packet didn't fit), false for terminal ones; the outer
    /// QUIC must not close on transient errors.
    private static func isTransientDatagramError(_ error: Error) -> Bool {
        if let quicError = error as? QUICConnection.QUICError {
            switch quicError {
            case .handshakeFailed, .streamReset, .streamClosedWithError, .closed, .closedOK:
                return false
            case .datagramTooLarge, .datagramQueueFull, .connectionFailed, .streamError, .timeout:
                return true
            }
        }
        if let hysteriaError = error as? HysteriaError {
            switch hysteriaError {
            case .authRejected, .udpNotSupported, .destinationTooLargeForDatagram, .streamClosed:
                return false
            case .notReady, .connectionFailed, .tunnelFailed:
                // connectionFailed covers per-packet outcomes; notReady is a
                // transient session-state window.
                return true
            }
        }
        if let nowhereError = error as? NowhereError {
            // Conservatively allowlist only errors that describe a transient
            // per-datagram/session window. New protocol errors remain terminal
            // without coupling this transport adapter to every Nowhere case.
            if case .notReady = nowhereError { return true }
            if case .connectionFailed = nowhereError { return true }
            return false
        }
        return false
    }

    func startReceiving(handler: @escaping (Data) -> Void,
                        errorHandler: @escaping (Error?) -> Void) {
        failureState.withLock { $0.handler = errorHandler }
        connection.startReceiving(handler: handler, errorHandler: { [weak self] err in
            self?.surfaceFailure(err)
        })
    }

    func cancel() {
        connection.cancel()
    }

    /// Forwards the latched `errorHandler` exactly once; taken out under the lock, invoked outside.
    private func surfaceFailure(_ error: Error?) {
        let handler: ((Error?) -> Void)? = failureState.withLock { state in
            guard !state.failed else { return nil }
            state.failed = true
            let h = state.handler
            state.handler = nil
            return h
        }
        handler?(error)
    }
}
