//
//  NWUDPTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 6/30/26.
//

import Foundation
import Network

nonisolated private let logger = AnywhereLogger(category: "NWUDPTransport")

// MARK: - NWUDPTransport

/// UDP transport over a connected `NWConnection`. All callbacks and state
/// transitions run on the internal `queue`; `send`, `startReceiving`, and `cancel`
/// are safe from any thread. Datagrams arriving before `startReceiving` arms a
/// handler are buffered (bounded) and flushed when it does.
nonisolated final class NWUDPTransport: @unchecked Sendable {

    enum State {
        case setup
        case ready
        case cancelled
    }

    // MARK: Constants

    private static let maxPendingDatagrams = 1024

    // MARK: State

    private let stateLock = UnfairLock()
    private var _state: State = .setup

    private var state: State {
        stateLock.withLock { _state }
    }

    var isReady: Bool {
        if case .ready = state { return true }
        return false
    }

    // MARK: Concurrency

    /// Serial queue for all connection callbacks and state transitions.
    private let queue = DispatchQueue(label: AWCore.Identifier.nwUDPTransportQueue,
                                      qos: .userInitiated)

    // MARK: Connection

    private var connection: NWConnection?

    /// Pending connect completion and the queue it fires on. Queue-confined;
    /// fired exactly once via `fireConnectCompletion` — on ready/failure, or as
    /// "Cancelled" from `teardown` when `cancel()` races the connect.
    private var connectCompletion: ((Error?) -> Void)?
    private var connectCompletionQueue: DispatchQueue?

    // MARK: Receive

    private var receiveHandler: ((Data) -> Void)?
    private var receiveErrorHandler: ((Error) -> Void)?
    private var receiveHandlerQueue: DispatchQueue?

    /// Datagrams received before `startReceiving` arms the handler. Bounded so a
    /// pre-handler burst can't OOM us.
    private var pendingDatagrams: [Data] = []
    private var didWarnPendingOverflow = false

    // MARK: - Lifecycle

    init() {}

    // MARK: - Connect

    func connect(host: String, port: UInt16,
                 completionQueue: DispatchQueue,
                 completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else {
                completionQueue.async { completion(TransportError.connectionFailed("Deallocated")) }
                return
            }
            if case .cancelled = self.state {
                completionQueue.async { completion(TransportError.connectionFailed("Cancelled")) }
                return
            }

            guard let nwPort = NWEndpoint.Port(rawValue: port) else {
                completionQueue.async {
                    completion(TransportError.connectionFailed("Invalid port \(port)"))
                }
                return
            }

            self.connectCompletion = completion
            self.connectCompletionQueue = completionQueue

            // NWConnection resolves the name (or uses the IP literal directly),
            // adapting to network changes on its own.
            let endpointHost = nwHost(fromIPLiteral: host) ?? .name(host, nil)
            let connection = NWConnection(host: endpointHost, port: nwPort, using: .udp)
            self.connection = connection

            connection.stateUpdateHandler = { [weak self] newState in
                guard let self, self.connection === connection else { return }
                switch newState {
                case .ready:
                    // A racing cancel() wins: skip arming/reporting and let
                    // teardown fire the completion as "Cancelled".
                    let didBecomeReady: Bool = self.stateLock.withLock {
                        if case .setup = self._state { self._state = .ready; return true }
                        return false
                    }
                    guard didBecomeReady else { return }
                    self.armReceiveLoop(connection)
                    self.fireConnectCompletion(nil)
                case .failed(let error):
                    self.fireConnectCompletion(mapNWError(error, op: .connect))
                    connection.cancel()
                case .waiting(let error):
                    if isDefinitiveConnectError(error) {
                        self.fireConnectCompletion(mapNWError(error, op: .connect))
                        connection.cancel()
                    }
                default:
                    break
                }
            }
            // NWConnection drops viability before the receive loop would error;
            // surface a terminal error so the flow closes and re-dials on a live path.
            connection.viabilityUpdateHandler = { [weak self] viable in
                guard let self, self.connection === connection, !viable else { return }
                guard case .ready = self.state else { return }
                self.surfaceTerminalError(TransportError.connectionFailed("Network path no longer viable"))
            }
            connection.start(queue: self.queue)
        }
    }

    /// Fires the connect completion at most once, on its original completion
    /// queue. Must run on `queue`.
    private func fireConnectCompletion(_ error: Error?) {
        guard let completion = connectCompletion else { return }
        connectCompletion = nil
        let completionQueue = connectCompletionQueue
        connectCompletionQueue = nil
        if let completionQueue {
            completionQueue.async { completion(error) }
        } else {
            completion(error)
        }
    }

    // MARK: - Receive

    /// Handler fires on `handlerQueue`, or `queue` if nil. `errorHandler` fires
    /// once on a terminal receive failure; the loop then stops, so callers must
    /// treat it as terminal and close the flow.
    func startReceiving(queue handlerQueue: DispatchQueue? = nil,
                        handler: @escaping (Data) -> Void,
                        errorHandler: ((Error) -> Void)? = nil) {
        queue.async { [weak self] in
            guard let self else { return }
            self.receiveHandler = handler
            self.receiveErrorHandler = errorHandler
            self.receiveHandlerQueue = handlerQueue
            let drained = self.pendingDatagrams
            self.pendingDatagrams.removeAll()
            for data in drained {
                if let hq = handlerQueue {
                    hq.async { handler(data) }
                } else {
                    handler(data)
                }
            }
        }
    }

    /// Must run on `queue`.
    private func armReceiveLoop(_ connection: NWConnection) {
        receiveOne(connection)
    }

    /// Receives one datagram and re-arms. Must run on `queue`.
    private func receiveOne(_ connection: NWConnection) {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self, self.connection === connection else { return }
            if let data, !data.isEmpty {
                self.deliver(data)
            }
            if let error {
                self.handleReceiveError(error)
                return
            }
            if case .ready = self.state {
                self.receiveOne(connection)
            }
        }
    }

    /// Delivers a datagram, or buffers it if no handler is armed yet. Must run on
    /// `queue`.
    private func deliver(_ data: Data) {
        if let handler = receiveHandler {
            if let hq = receiveHandlerQueue {
                hq.async { handler(data) }
            } else {
                handler(data)
            }
        } else {
            if pendingDatagrams.count >= Self.maxPendingDatagrams {
                pendingDatagrams.removeFirst()
                if !didWarnPendingOverflow {
                    didWarnPendingOverflow = true
                    logger.warning("[UDP] Pre-handler buffer overflowed (cap \(Self.maxPendingDatagrams)); dropping oldest until startReceiving arms")
                }
            }
            pendingDatagrams.append(data)
        }
    }

    /// Surfaces a terminal receive error once, then stops the loop. Must run on
    /// `queue`.
    private func handleReceiveError(_ error: NWError) {
        surfaceTerminalError(mapNWError(error, op: .receive))
    }

    /// Delivers a terminal error to the receive-error handler at most once, then disarms
    /// it. Shared by the receive loop and the viability watchdog. Must run on `queue`.
    private func surfaceTerminalError(_ error: Error) {
        guard let handler = receiveErrorHandler else { return }
        receiveErrorHandler = nil
        let handlerQueue = receiveHandlerQueue
        if let handlerQueue {
            handlerQueue.async { handler(error) }
        } else {
            handler(error)
        }
    }

    // MARK: - Send

    func send(data: Data) {
        queue.async { [weak self] in
            guard let self, case .ready = self.state, let connection = self.connection else { return }
            connection.send(content: data, completion: .idempotent)
        }
    }

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else { completion(TransportError.notConnected); return }
            guard case .ready = self.state, let connection = self.connection else {
                completion(TransportError.notConnected)
                return
            }
            connection.send(content: data, completion: .contentProcessed { error in
                completion(error.map { mapNWError($0, op: .send) })
            })
        }
    }

    // MARK: - Cancel

    /// Latches cancelled state and tears down on `queue`. Safe from any thread;
    /// idempotent.
    func cancel() {
        guard latchCancelled() else { return }
        queue.async { [weak self] in
            self?.teardown()
        }
    }

    private func latchCancelled() -> Bool {
        stateLock.withLock {
            if case .cancelled = _state { return false }
            _state = .cancelled
            return true
        }
    }

    /// Must run on `queue`.
    private func teardown() {
        if let connection {
            self.connection = nil
            connection.stateUpdateHandler = nil
            connection.cancel()
        }
        // Fires only if connect hasn't already completed (ready/failure).
        fireConnectCompletion(TransportError.connectionFailed("Cancelled"))
        receiveHandler = nil
        receiveErrorHandler = nil
        receiveHandlerQueue = nil
        pendingDatagrams.removeAll()
        didWarnPendingOverflow = false
    }
}
