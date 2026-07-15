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

final class ProxyConnectionDatagramTransport: QUICDatagramTransport, @unchecked Sendable {
    private let connection: ProxyConnection

    /// Guards `errorHandler` so it fires at most once across send- and receive-side failures.
    private struct FailureState {
        var handler: ((Error?) -> Void)?
        var failed = false
    }

    private let failureState = Mutex(FailureState())

    /// Ordered async send funnel — datagrams reach the wire in submission order (the base
    /// `send(data:completion:)` this replaced serialized through the connection's own pump).
    private let sendPump: AsyncSendPump

    /// Push handler + receive loop, stored so the loop's `Task` captures only `self`
    /// (the raw closures aren't `Sendable`).
    private let receiveHandler = Mutex<((Data) -> Void)?>(nil)
    private let receiveTask = Mutex<Task<Void, Never>?>(nil)

    init(connection: ProxyConnection) {
        self.connection = connection
        // Weak: the pump task must not retain the connection through this closure (the
        // connection strongly owns this transport, hence the pump), else it can't dealloc.
        self.sendPump = AsyncSendPump(
            send: { [weak connection] data in
                guard let connection else { throw CancellationError() }
                try await connection.send(data)
            },
            finish: {}
        )
    }

    deinit {
        sendPump.finish()
        receiveTask.withLock { $0?.cancel() }
    }

    func sendDatagram(_ data: Data) {
        sendPump.enqueueSend(data) { [weak self] error in
            guard let error, let self else { return }
            // Transient errors (PMTU shrink, fragmentation refusal, queue overflow) are not
            // terminal — outer QUIC loss recovery treats the drop as ordinary loss.
            if Self.isTransientDatagramError(error) { return }
            self.surfaceFailure(error)
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
        receiveHandler.withLock { $0 = handler }
        let task = Task { [weak self] in
            guard let self else { return }
            do {
                while true {
                    guard let data = try await self.connection.receive() else {
                        self.surfaceFailure(nil)   // clean EOF
                        return
                    }
                    self.receiveHandler.withLock { $0 }?(data)
                }
            } catch {
                self.surfaceFailure(error)
            }
        }
        receiveTask.withLock { $0 = task }
    }

    func cancel() {
        // Swallow the teardown-driven EOF/error the receive loop will observe once the
        // connection is cancelled, so it isn't surfaced as a spurious transport failure.
        failureState.withLock { $0.failed = true; $0.handler = nil }
        receiveTask.withLock { $0?.cancel(); $0 = nil }
        sendPump.finish()
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
