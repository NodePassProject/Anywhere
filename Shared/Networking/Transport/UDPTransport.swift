//
//  UDPTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 6/30/26.
//

import Foundation
import Network
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "UDPTransport")

// MARK: - UDPTransport

/// A connected-UDP transport backed by iOS 26's `NetworkConnection`.
///
/// The public surface is completion-handler / push based, while the underlying
/// connection uses `NetworkConnection`'s structured-concurrency API. A single
/// driver `Task` owns the connection inside `withNetworkConnection`; a serial
/// state queue bridges the callbacks. The connection is started by the driver's
/// receive loop (never by a stray empty datagram). Cancellation is task
/// cancellation.
nonisolated final class UDPTransport: @unchecked Sendable {

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

    // MARK: State

    /// Fields guarded by `stateLock`.
    private struct Protected {
        var state: State = .setup
        /// Set once teardown has finished.
        var teardownComplete = false
    }

    private let stateLock = Mutex(Protected())

    /// The current state of the transport. Thread-safe.
    private var state: State {
        stateLock.withLock { $0.state }
    }

    var isTransportReady: Bool {
        if case .ready = state { return true }
        return false
    }

    // MARK: Concurrency

    /// Serial queue for all state transitions and callbacks.
    private let queue = DispatchQueue(label: AWCore.Identifier.udpTransportQueue, qos: .userInitiated)

    // MARK: Connection

    /// Owns the `NetworkConnection` for its whole lifetime; cancelling it tears
    /// the connection down. `queue`-confined.
    private var driverTask: Task<Void, Never>?

    /// Whether this transport's connection is counted in `FlowGauge`.
    /// `queue`-confined; balanced exactly once by `releaseFlowCount`.
    private var flowCounted = false

    // MARK: Send pipeline

    /// Datagrams are sent in submission order by the driver's send loop.
    /// `queue`-confined.
    private var sendContinuation: AsyncStream<Data>.Continuation?
    /// FIFO of the completions for the datagrams buffered in `sendContinuation`.
    /// `queue`-confined.
    private var pendingSendCompletions: [((Error?) -> Void)?] = []

    // MARK: Connect pipeline

    /// Pending connect completion and the queue it fires on. `queue`-confined;
    /// fired exactly once via `fireConnectCompletion`.
    private var connectCompletion: ((Error?) -> Void)?
    private var connectCompletionQueue: DispatchQueue?

    /// Backstop that fails the dial if it never reaches `.ready`/`.failed`; armed
    /// in `connect`, cancelled the moment the dial resolves. Touched only on `queue`.
    private var dialDeadline: DispatchWorkItem?

    /// "host:port" for diagnostics. Set once in `connect`.
    private var endpointDescription = ""

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
        driverTask?.cancel()
        guard flowCounted else { return }
        flowCounted = false
        FlowGauge.decrementUDP()
        logger.error("[UDP] Transport deallocated with its flow still counted — teardown never ran. Recovered the FlowGauge count in deinit; a cancel path has regressed.")
    }

    // MARK: - Connect

    /// Connects asynchronously. `NetworkConnection` resolves `host` (or uses it
    /// directly when it's an IP literal), adapting to network changes on its own.
    /// `completion` fires on `completionQueue`.
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
                    if case .setup = $0.state { $0.state = .failed(error) }
                }
                completionQueue.async { completion(error) }
                return
            }

            connectCompletion = completion
            connectCompletionQueue = completionQueue
            endpointDescription = "\(host):\(port)"
            armDialDeadline()
            flowCounted = true
            FlowGauge.incrementUDP()

            let (sendStream, sendCont) = AsyncStream.makeStream(of: Data.self)
            sendContinuation = sendCont

            let endpointHost = NWEndpoint.Host(ipLiteral: host) ?? .name(host, nil)
            let endpoint = NWEndpoint.hostPort(host: endpointHost, port: nwPort)
            driverTask = Task { [self] in
                await self.runDriver(endpoint: endpoint, sendStream: sendStream)
            }
        }
    }

    // MARK: - Send

    /// Ordered send. `completion` fires on the transport's internal queue —
    /// unlike `connect`, which marshals to its caller's queue.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        queue.async { [self] in
            switch state {
            case .ready:
                guard let sendContinuation else {
                    completion(TransportError.notConnected)
                    return
                }
                pendingSendCompletions.append(completion)
                sendContinuation.yield(data)
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
            guard case .ready = state, let sendContinuation else { return }
            pendingSendCompletions.append(nil)
            sendContinuation.yield(data)
        }
    }

    // MARK: - Receive

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
                if let handlerQueue {
                    handlerQueue.async { handler(data) }
                } else {
                    handler(data)
                }
            }
        }
    }

    // MARK: - Teardown

    /// Latches cancelled state and tears down on `queue`. Safe from any thread;
    /// idempotent.
    func cancel() {
        guard latchCancelled() else { return }
        queue.async { [self] in beginTeardown() }
    }

    private func latchCancelled() -> Bool {
        stateLock.withLock {
            if $0.teardownComplete { return false }
            if case .cancelled = $0.state { return false }
            $0.state = .cancelled
            return true
        }
    }

    // MARK: - Driver

    /// Owns the `NetworkConnection` for the whole session. `withNetworkConnection`
    /// tears the connection down deterministically when this task is cancelled or
    /// returns. Runs off `queue`; all state mutation hops back onto `queue`.
    private func runDriver(endpoint: NWEndpoint, sendStream: AsyncStream<Data>) async {
        do {
            try await withNetworkConnection(to: endpoint, using: { UDP() }) { [self] conn in
                conn.onStateUpdate { [weak self] _, state in
                    guard let self else { return }
                    switch state {
                    case .ready:
                        self.queue.async { self.handleConnectReady() }
                    case .failed(let error), .waiting(let error):
                        self.queue.async { self.handleConnectionFailure(error) }
                    default:
                        break  // .setup, .preparing, .cancelled
                    }
                }
                // UDP drops viability before the receive loop would error; fail
                // the transport so the flow closes and re-dials on a live path.
                conn.onViabilityUpdate { [weak self] _, viable in
                    guard let self, !viable else { return }
                    self.queue.async { self.handleViabilityLost() }
                }
                // Covers the case where the connection is already established when
                // the handler runs; otherwise the receive loop's first read starts
                // it and `onStateUpdate` reports `.ready`.
                if case .ready = conn.state {
                    self.queue.async { self.handleConnectReady() }
                }

                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask { try await self.runSendLoop(conn, stream: sendStream) }
                    group.addTask { try await self.runReceiveLoop(conn) }
                    _ = try await group.next()
                    group.cancelAll()
                }
            }
        } catch {
            queue.async { [self] in handleDriverError(error) }
        }
        queue.async { [self] in finalizeTeardown() }
    }

    /// Drains ordered datagram sends. A send failure is surfaced to its
    /// completion but is not fatal — the receive loop / state handler tear the
    /// leg down. Runs off `queue`.
    private func runSendLoop(_ conn: NetworkConnection<UDP>, stream: AsyncStream<Data>) async throws {
        for await data in stream {
            do {
                try await conn.send(data)
                queue.async { [self] in completeSend(nil) }
            } catch {
                let mapped = TransportError.from(error, op: .send)
                queue.async { [self] in completeSend(mapped) }
            }
        }
    }

    /// Continuously receives datagrams and delivers (or buffers) them, starting
    /// the connection on the first read. A receive failure is terminal. Runs off
    /// `queue`.
    private func runReceiveLoop(_ conn: NetworkConnection<UDP>) async throws {
        do {
            while true {
                let message = try await conn.receive()
                let data = message.content
                if !data.isEmpty {
                    queue.async { [self] in deliver(data) }
                }
            }
        } catch {
            let mapped = TransportError.from(error, op: .receive)
            queue.async { [self] in fail(with: mapped) }
            throw error
        }
    }

    // MARK: - Connect resolution (on queue)

    /// Promotes to `.ready` and fires the connect completion exactly once.
    private func handleConnectReady() {
        guard transitionFromSetup(to: .ready) else { return }
        cancelDialDeadline()
        fireConnectCompletion(nil)
    }

    /// A `.failed`/`.waiting` state report. Pre-ready it resolves the connect
    /// with a connect-flavored error; either way it fails the transport.
    private func handleConnectionFailure(_ error: NWError) {
        logger.debug("[UDP] connection \(endpointDescription) \(error.connectWaitingDescription); failing")
        fireConnectCompletion(error.transportError(op: .connect))
        fail(with: error.transportError(op: .receive))
    }

    /// Egress under a ready connection went away. Must run on `queue`.
    private func handleViabilityLost() {
        guard case .ready = state else { return }
        fail(with: TransportError.connectionFailed("Network path no longer viable"))
    }

    /// Latches `.failed` (keeping `.cancelled` sticky), resolves the connect,
    /// surfaces the terminal error to the receive side, and tears the connection
    /// down. Must run on `queue`.
    private func fail(with error: Error) {
        let changed: Bool = stateLock.withLock {
            switch $0.state {
            case .setup, .ready:
                $0.state = .failed(error)
                return true
            case .failed, .cancelled:
                return false
            }
        }
        guard changed else { return }
        cancelDialDeadline()
        fireConnectCompletion(error)   // no-op if connect already resolved
        surfaceTerminalError(error)
        abortDriver()
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

    // MARK: - Receive delivery (on queue)

    /// Delivers a datagram, or buffers it if no handler is armed yet. Must run on
    /// `queue`.
    private func deliver(_ data: Data) {
        if let handler = receiveHandler {
            if let receiveHandlerQueue {
                receiveHandlerQueue.async { handler(data) }
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

    /// Delivers a terminal error to the receive-error handler at most once, then
    /// disarms it. Must run on `queue`.
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

    /// Fires the head send completion in submission order.
    private func completeSend(_ error: Error?) {
        guard !pendingSendCompletions.isEmpty else { return }
        let completion = pendingSendCompletions.removeFirst()
        completion?(error)
    }

    // MARK: - Teardown (on queue)

    /// Fails in-flight work with a cancellation error, then cancels the driver so
    /// the connection tears down. Full teardown completes in `finalizeTeardown`.
    private func beginTeardown() {
        cancelDialDeadline()
        fireConnectCompletion(TransportError.connectionFailed("Cancelled"))
        failAllPendingSends(TransportError.connectionFailed("Cancelled"))
        sendContinuation?.finish()
        sendContinuation = nil
        receiveHandler = nil
        receiveErrorHandler = nil
        receiveHandlerQueue = nil
        pendingDatagrams.removeAll()
        didWarnPendingOverflow = false

        if let task = driverTask {
            driverTask = nil
            task.cancel()  // `finalizeTeardown` runs when the driver unwinds
        } else {
            finalizeTeardown()
        }
    }

    /// Balances `FlowGauge` and marks teardown complete. Idempotent. Must run on
    /// `queue`.
    private func finalizeTeardown() {
        releaseFlowCount()
        stateLock.withLock { $0.teardownComplete = true }
    }

    /// A driver exit outside the cancel path: resolve the connect and fail the
    /// transport. No-ops once those have already fired.
    private func handleDriverError(_ error: Error) {
        fireConnectCompletion(TransportError.from(error, op: .connect))
        fail(with: TransportError.from(error, op: .receive))
    }

    /// Fires every buffered send completion with `error`, in order.
    private func failAllPendingSends(_ error: Error) {
        let pending = pendingSendCompletions
        pendingSendCompletions.removeAll()
        for completion in pending {
            completion?(error)
        }
    }

    /// Cancels the driver task, tearing the connection down. Must run on `queue`.
    private func abortDriver() {
        driverTask?.cancel()
    }

    /// Balances `FlowGauge` exactly once per transport. Must run on `queue`.
    private func releaseFlowCount() {
        guard flowCounted else { return }
        flowCounted = false
        FlowGauge.decrementUDP()
    }

    // MARK: - Dial deadline

    /// Arms the wall-clock dial backstop on `queue`. Catches dials that hang
    /// without ever reporting `.waiting`/`.failed`.
    private func armDialDeadline() {
        let deadline = DispatchWorkItem { [weak self] in
            guard let self, case .setup = self.state else { return }
            logger.debug("[UDP] Dial deadline exceeded (\(Self.dialDeadlineSeconds)s): \(self.endpointDescription)")
            self.fail(with: TransportError.posixError(.connect, errno: ETIMEDOUT))
        }
        dialDeadline = deadline
        queue.asyncAfter(deadline: .now() + .seconds(Self.dialDeadlineSeconds), execute: deadline)
    }

    /// Cancels the dial backstop once the dial resolves. Must run on `queue`.
    private func cancelDialDeadline() {
        dialDeadline?.cancel()
        dialDeadline = nil
    }

    // MARK: - State transitions

    /// Transitions only from `.setup`, keeping `.cancelled` sticky. Returns
    /// whether the transition occurred.
    @discardableResult
    private func transitionFromSetup(to new: State) -> Bool {
        stateLock.withLock {
            if case .setup = $0.state {
                $0.state = new
                return true
            }
            return false
        }
    }

}

// `UDPTransport` already provides the full `RawDatagramTransport` surface.
extension UDPTransport: RawDatagramTransport {}
