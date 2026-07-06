//
//  NWUDPTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 6/30/26.
//

import Foundation
import Network
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "NWUDPTransport")

// MARK: - NWUDPTransport

nonisolated final class NWUDPTransport: @unchecked Sendable {

    enum State {
        case setup
        case ready
        case failed(Error)
        case cancelled
    }

    // MARK: Constants

    /// Wall-clock backstop for the whole dial.
    private static let dialDeadlineSeconds: Int = 20
    private static let maxPendingDatagrams = 1024
    private static let receiveWindow = 16

    // MARK: State

    private let stateLock = Mutex(State.setup)

    /// The current state of the transport. Thread-safe.
    private var state: State {
        stateLock.withLock { $0 }
    }

    var isTransportReady: Bool {
        if case .ready = state { return true }
        return false
    }

    // MARK: Concurrency

    /// Serial queue for all connection callbacks and state transitions.
    private let queue = DispatchQueue(label: AWCore.Identifier.nwUDPTransportQueue, qos: .userInitiated)

    // MARK: Connection

    /// The live connection; `nil` after teardown. Mutated only on `queue`.
    private var connection: NWConnection?

    /// Whether this transport's `NWConnection` is counted in `FlowGauge`.
    /// `queue`-confined; balanced exactly once by `releaseFlowCount`.
    private var flowCounted = false

    // MARK: Connect pipeline

    /// Pending connect completion and the queue it fires on. `queue`-confined;
    /// fired exactly once via `fireConnectCompletion` — on ready/failure, or as
    /// "Cancelled" from `teardown` when `cancel()` races the connect.
    private var connectCompletion: ((Error?) -> Void)?
    private var connectCompletionQueue: DispatchQueue?

    /// Backstop that fails the dial if it never reaches `.ready`/`.failed`; armed in
    /// `connect`, cancelled the moment the dial resolves. Touched only on `queue`.
    private var dialDeadline: DispatchWorkItem?

    /// "host:port" for diagnostics. Set once in `connect`.
    private var endpointDescription = ""

    /// Whether the dial ever reached `.preparing`; disambiguates the
    /// dial-deadline diagnostic. `queue`-confined.
    private var sawPreparing = false

    // MARK: Receive pipeline

    private var receiveHandler: ((Data) -> Void)?
    private var receiveErrorHandler: ((Error) -> Void)?
    private var receiveHandlerQueue: DispatchQueue?

    /// Datagrams received before `startReceiving` arms the handler. Bounded so a
    /// pre-handler burst can't OOM us.
    private var pendingDatagrams: [Data] = []
    private var didWarnPendingOverflow = false

    // MARK: - Lifecycle

    init() {}

    deinit {
        guard flowCounted else { return }
        flowCounted = false
        FlowGauge.decrementUDP()
        connection?.cancel()
        logger.error("[UDP] Transport deallocated with its flow still counted — teardown never ran. Recovered the FlowGauge count and socket in deinit; a cancel path has regressed.")
    }

    // MARK: - Connect pipeline

    /// Connects asynchronously. `NWConnection` resolves `host` (or uses it
    /// directly when it's an IP literal), adapting to network changes on its
    /// own. `completion` fires on `completionQueue`.
    func connect(
        host: String, port: UInt16,
        completionQueue: DispatchQueue,
        completion: @escaping (Error?) -> Void
    ) {
        queue.async { [self] in
            switch state {
            case .setup:
                break
            case .cancelled:
                completionQueue.async { completion(TransportError.connectionFailed("Cancelled")) }
                return
            case .ready, .failed:
                completionQueue.async { completion(TransportError.connectionFailed("Transport already dialed")) }
                return
            }
            guard let nwPort = NWEndpoint.Port(rawValue: port) else {
                let error = TransportError.connectionFailed("Invalid port \(port)")
                stateLock.withLock {
                    if case .setup = $0 { $0 = .failed(error) }
                }
                completionQueue.async { completion(error) }
                return
            }

            connectCompletion = completion
            connectCompletionQueue = completionQueue
            endpointDescription = "\(host):\(port)"
            armDialDeadline()

            let endpointHost = NWEndpoint.Host(ipLiteral: host) ?? .name(host, nil)
            let connection = NWConnection(host: endpointHost, port: nwPort, using: .udp)
            self.connection = connection
            flowCounted = true
            FlowGauge.incrementUDP()

            connection.stateUpdateHandler = { [weak self] newState in
                guard let self, self.connection === connection else { return }
                self.handleConnectionState(newState, connection: connection)
            }
            // NWConnection drops viability before the receive loop would error;
            // fail the transport so the flow closes and re-dials on a live path.
            // The `.ready` guard keeps a pre-ready blip from killing the dial.
            connection.viabilityUpdateHandler = { [weak self] viable in
                guard let self, !viable else { return }
                guard case .ready = self.state else { return }
                self.fail(with: TransportError.connectionFailed("Network path no longer viable"), connection: connection)
            }
            connection.start(queue: queue)
        }
    }

    /// Balances `FlowGauge` exactly once per transport. Must run on `queue`.
    private func releaseFlowCount() {
        guard flowCounted else { return }
        flowCounted = false
        FlowGauge.decrementUDP()
    }

    /// Arms the wall-clock dial backstop on `queue`. Catches dials that hang
    /// without ever reporting `.waiting`/`.failed`.
    private func armDialDeadline() {
        let deadline = DispatchWorkItem { [weak self] in
            guard let self, case .setup = self.state, let connection = self.connection else { return }
            let lastState = self.sawPreparing ? "preparing, no error reported" : "no state updates"
            let message = "Dial deadline exceeded (\(Self.dialDeadlineSeconds)s; last state: \(lastState))"
            logger.debug("[UDP] \(message): \(self.endpointDescription)")
            self.fail(with: TransportError.posixError(.connect, errno: ETIMEDOUT), connection: connection)
        }
        dialDeadline = deadline
        queue.asyncAfter(deadline: .now() + .seconds(Self.dialDeadlineSeconds), execute: deadline)
    }

    /// Cancels the dial backstop once the dial resolves. Must run on `queue`.
    private func cancelDialDeadline() {
        dialDeadline?.cancel()
        dialDeadline = nil
    }

    /// Handles a state update from `connection`. Unlike TCP, one handler covers
    /// the connection's whole lifetime, so `.failed`/`.waiting` may arrive pre-
    /// or post-ready. Must run on `queue`.
    private func handleConnectionState(_ newState: NWConnection.State, connection: NWConnection) {
        switch newState {
        case .ready:
            handleConnectReady(connection)
        case .failed(let error):
            logger.debug("[UDP] connection \(endpointDescription) failed: \(error)")
            if error.isResourceExhaustion {
                FlowExhaustionBrake.shared.recordExhaustion()
            }
            // Pre-ready, the dial is what failed: resolve the pending connect
            // with the connect-flavored error before `fail` reports the
            // receive-flavored one. No-op once connect has resolved.
            fireConnectCompletion(error.transportError(op: .connect))
            fail(with: error.transportError(op: .receive), connection: connection)
        case .waiting(let error):
            if error.isResourceExhaustion {
                FlowExhaustionBrake.shared.recordExhaustion()
            }
            logger.debug("[UDP] connection \(endpointDescription) \(error.connectWaitingDescription); failing fast")
            fireConnectCompletion(error.transportError(op: .connect))
            fail(with: error.transportError(op: .receive), connection: connection)
        case .preparing:
            sawPreparing = true
        default:
            break  // .setup, .cancelled
        }
    }

    /// Promotes to `.ready`, arms the receive window, and fires the connect
    /// completion exactly once. A racing `cancel()` wins: skip arming and let
    /// teardown fire the completion as "Cancelled". Must run on `queue`.
    private func handleConnectReady(_ connection: NWConnection) {
        let didBecomeReady: Bool = stateLock.withLock { state in
            if case .setup = state { state = .ready; return true }
            return false
        }
        guard didBecomeReady else { return }
        cancelDialDeadline()
        FlowExhaustionBrake.shared.recordRecovery()
        armReceiveLoop(connection)
        fireConnectCompletion(nil)
    }

    /// Latches `.failed` (keeping `.cancelled` sticky), surfaces the error to
    /// the receive side, and discards the connection. Covers connect-phase and
    /// steady-state failures alike. Surfacing must happen here: `discard` nils
    /// `connection`, so in-flight receive callbacks bail on the identity guard
    /// and can't report it. Must run on `queue`.
    private func fail(with error: Error, connection: NWConnection) {
        let changed: Bool = stateLock.withLock { state in
            switch state {
            case .setup, .ready:
                state = .failed(error)
                return true
            case .failed, .cancelled:
                return false
            }
        }
        guard changed else { return }
        cancelDialDeadline()
        // No-op when connect already resolved; backstop for any pre-ready path
        // that reaches here without firing the completion explicitly.
        fireConnectCompletion(error)
        surfaceTerminalError(error)
        discard(connection)
    }

    /// Discards a failed connection (pre- or post-ready): releases its flow
    /// count and cancels it. Must run on `queue`.
    private func discard(_ connection: NWConnection) {
        if self.connection === connection {
            self.connection = nil
            releaseFlowCount()
        }
        connection.stateUpdateHandler = nil
        connection.viabilityUpdateHandler = nil
        connection.cancel()
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

    // MARK: - Receive pipeline

    /// Arms the datagram handler; buffered datagrams drain first. `handler`
    /// fires on `handlerQueue`, or the transport's internal queue if nil.
    /// `errorHandler` fires at most once, on a terminal failure; the receive
    /// loop then stops, so callers must treat it as terminal and close the flow.
    func startReceiving(
        queue handlerQueue: DispatchQueue? = nil,
        handler: @escaping (Data) -> Void,
        errorHandler: ((Error) -> Void)? = nil
    ) {
        queue.async { [self] in
            receiveHandler = handler
            receiveErrorHandler = errorHandler
            receiveHandlerQueue = handlerQueue
            let drained = pendingDatagrams
            pendingDatagrams.removeAll()
            for data in drained {
                if let hq = handlerQueue {
                    hq.async { handler(data) }
                } else {
                    handler(data)
                }
            }
        }
    }

    /// Fills the receive window with concurrent receives. Must run on `queue`.
    private func armReceiveLoop(_ connection: NWConnection) {
        for _ in 0..<Self.receiveWindow {
            receiveOne(connection)
        }
    }

    /// Receives one datagram and refills the window slot it occupied. Must run on `queue`.
    private func receiveOne(_ connection: NWConnection) {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self, self.connection === connection else { return }
            if let data, !data.isEmpty {
                self.deliver(data)
            }
            if let error {
                self.fail(with: error.transportError(op: .receive), connection: connection)
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

    /// Delivers a terminal error to the receive-error handler at most once,
    /// then disarms it. Must run on `queue`.
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

    /// Ordered send. `completion` fires on the transport's internal queue —
    /// unlike `connect`, which marshals to its caller's queue.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        queue.async { [self] in
            switch state {
            case .ready:
                guard let connection else {
                    completion(TransportError.notConnected)
                    return
                }
                connection.send(content: data, completion: .contentProcessed { error in
                    completion(error.map { $0.transportError(op: .send) })
                })
            case .failed(let error):
                completion(error)
            default:
                completion(TransportError.notConnected)
            }
        }
    }

    /// Fire-and-forget send.
    func send(data: Data) {
        queue.async { [self] in
            guard case .ready = state, let connection else { return }
            connection.send(content: data, completion: .idempotent)
        }
    }

    // MARK: - Teardown

    /// Latches cancelled state and tears down on `queue`. Safe from any thread;
    /// idempotent.
    func cancel() {
        guard latchCancelled() else { return }
        queue.async { [self] in
            teardown()
        }
    }

    private func latchCancelled() -> Bool {
        stateLock.withLock { state in
            if case .cancelled = state { return false }
            state = .cancelled
            return true
        }
    }

    /// Must run on `queue`.
    private func teardown() {
        cancelDialDeadline()
        if let connection {
            self.connection = nil
            releaseFlowCount()
            connection.stateUpdateHandler = nil
            connection.viabilityUpdateHandler = nil
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
