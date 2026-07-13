//
//  TCPTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 6/30/26.
//

import Foundation
import Network
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TCPTransport")

// MARK: - TCPTransport

/// A TCP byte-stream transport backed by iOS 26's `NetworkConnection`.
///
/// Stage 1 of the `NWConnection` → `NetworkConnection` migration: the public
/// surface stays completion-handler based, while the underlying connection uses
/// `NetworkConnection`'s structured-concurrency API. A single driver `Task` owns
/// the connection inside `withNetworkConnection`; the completion-handler API is
/// bridged to it through a serial state queue and two async pipelines (ordered
/// sends, one-at-a-time receives). Cancellation is task cancellation.
nonisolated final class TCPTransport: RawTransport, @unchecked Sendable {

    enum State {
        case setup
        case ready
        case failed(Error)
        case cancelled
    }

    // MARK: Constants

    /// Per-attempt connect timeout (seconds).
    private static let connectTimeout: Int = 16
    /// Wall-clock backstop for the whole dial.
    private static let dialDeadlineSeconds: Int = 20
    private static let maxReceiveLength = 65535

    // MARK: State

    /// Fields guarded by `stateLock`.
    private struct Protected {
        var state: State = .setup
        /// Completions awaiting full teardown.
        var teardownCompletions: [@Sendable () -> Void] = []
        /// Set once teardown has finished.
        var teardownComplete = false
    }

    private let stateLock = Mutex(Protected())

    /// The current state of the transport. Thread-safe.
    var state: State {
        stateLock.withLock { $0.state }
    }

    // MARK: Concurrency

    /// Serial queue for all state transitions and completion-handler callbacks.
    private let queue = DispatchQueue(label: AWCore.Identifier.tcpTransportQueue, qos: .userInitiated, autoreleaseFrequency: .workItem)

    // MARK: Connection

    /// Owns the `NetworkConnection` for its whole lifetime; cancelling it tears
    /// the connection down. `queue`-confined.
    private var driverTask: Task<Void, Never>?

    /// Whether this transport's connection is counted in `FlowGauge`.
    /// `queue`-confined; balanced exactly once by `releaseFlowCount`.
    private var flowCounted = false

    // MARK: Send pipeline

    /// One send at a time, in submission order, is awaited by the driver's send
    /// loop. `queue`-confined.
    private var sendContinuation: AsyncStream<SendJob>.Continuation?
    /// FIFO of the completions for the sends buffered in `sendContinuation`,
    /// aligned with the (non-establish) jobs. `queue`-confined.
    private var pendingSendCompletions: [((Error?) -> Void)?] = []

    /// A unit of ordered send work handed to the driver's send loop.
    private struct SendJob: Sendable {
        let data: Data
        let endOfStream: Bool
        /// The dial's first job: starts the connection and flushes `initialData`.
        let isEstablish: Bool
    }

    // MARK: Receive pipeline

    /// One token per caller `receive`; the driver's receive loop awaits one
    /// `NetworkConnection.receive` per token. `queue`-confined.
    private var receiveContinuation: AsyncStream<Void>.Continuation?
    /// At most one receive in flight; callers issue receives serially.
    private var pendingReceiveCompletion: ((Data?, Bool, Error?) -> Void)?
    /// Latched on remote half-close; later receives return EOF immediately.
    private var receivedEOF = false

    // MARK: Connect pipeline

    private var connectCompletion: ((Error?) -> Void)?

    /// Backstop that fails the dial if it never reaches `.ready`/`.failed`; armed
    /// in `connect`, cancelled the moment the dial resolves. Touched only on `queue`.
    private var dialDeadline: DispatchWorkItem?

    /// "host:port" for diagnostics. Set once in `connect`.
    private var endpointDescription = ""

    /// Times the dial for the live "Dial" stat; direct/bypass dials disable it
    /// so only proxied first-hop dials are counted.
    var dialTimer = MetricTimer(.dial)

    // MARK: - Lifecycle

    init() {}

    deinit {
        driverTask?.cancel()
        guard flowCounted else { return }
        flowCounted = false
        FlowGauge.decrementTCP()
        logger.error("[TCP] Transport deallocated with its flow still counted — teardown never ran. Recovered the FlowGauge count in deinit; a cancel path has regressed.")
    }

    // MARK: - RawTransport

    var isTransportReady: Bool {
        if case .ready = state { return true }
        return false
    }

    /// Connects asynchronously. `NetworkConnection` resolves `host` (or uses it
    /// directly when it's an IP literal) and races addresses (Happy Eyeballs);
    /// `initialData` is sent once ready. `completion` fires on `queue`.
    func connect(
        host: String, port: UInt16,
        initialData: Data? = nil,
        completion: @escaping (Error?) -> Void
    ) {
        queue.async { [self] in
            switch state {
            case .setup:
                break
            case .cancelled:
                completion(TransportError.connectionFailed("Cancelled"))
                return
            case .ready, .failed:
                completion(TransportError.connectionFailed("Transport already dialed"))
                return
            }
            guard let nwPort = NWEndpoint.Port(rawValue: port) else {
                let error = TransportError.connectionFailed("Invalid port \(port)")
                stateLock.withLock {
                    if case .setup = $0.state { $0.state = .failed(error) }
                }
                completion(error)
                return
            }

            connectCompletion = completion
            endpointDescription = "\(host):\(port)"
            dialTimer.start()
            armDialDeadline()
            flowCounted = true
            FlowGauge.incrementTCP()

            let (sendStream, sendCont) = AsyncStream.makeStream(of: SendJob.self)
            let (receiveStream, receiveCont) = AsyncStream.makeStream(of: Void.self)
            sendContinuation = sendCont
            receiveContinuation = receiveCont
            // The first job establishes the connection and flushes any initial
            // data ahead of every caller send.
            sendCont.yield(SendJob(data: initialData ?? Data(), endOfStream: false, isEstablish: true))

            let endpointHost = NWEndpoint.Host(ipLiteral: host) ?? .name(host, nil)
            let endpoint = NWEndpoint.hostPort(host: endpointHost, port: nwPort)
            driverTask = Task { [self] in
                await self.runDriver(endpoint: endpoint, sendStream: sendStream, receiveStream: receiveStream)
            }
        }
    }

    /// Ordered send; the driver's send loop preserves submission order and
    /// applies backpressure. `completion` fires on `queue`.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        queue.async { [self] in
            switch state {
            case .ready:
                guard let sendContinuation else {
                    completion(TransportError.notConnected)
                    return
                }
                pendingSendCompletions.append(completion)
                sendContinuation.yield(SendJob(data: data, endOfStream: false, isEstablish: false))
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
            sendContinuation.yield(SendJob(data: data, endOfStream: false, isEstablish: false))
        }
    }

    /// Half-closes the send direction: `endOfStream` emits a FIN ordered after
    /// every issued send; receive stays open. `completion` fires on `queue`.
    func closeWrite(completion: @escaping (Error?) -> Void) {
        queue.async { [self] in
            switch state {
            case .ready:
                guard let sendContinuation else {
                    completion(TransportError.notConnected)
                    return
                }
                pendingSendCompletions.append(completion)
                sendContinuation.yield(SendJob(data: Data(), endOfStream: true, isEstablish: false))
            case .failed(let error):
                completion(error)
            default:
                completion(TransportError.notConnected)
            }
        }
    }

    /// Receives once. Completion: `(data, false, nil)` on data,
    /// `(nil, true, nil)` on EOF, `(nil, true, error)` on failure; fires on `queue`.
    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        queue.async { [self] in
            if receivedEOF {
                completion(nil, true, nil)
                return
            }
            switch state {
            case .ready:
                break
            case .failed(let error):
                completion(nil, true, error)
                return
            case .cancelled, .setup:
                completion(nil, true, TransportError.notConnected)
                return
            }
            // Contract: receives are serial; don't clobber a pending completion.
            if pendingReceiveCompletion != nil {
                completion(nil, true, TransportError.receiveFailed("Concurrent receive"))
                return
            }
            guard let receiveContinuation else {
                completion(nil, true, TransportError.notConnected)
                return
            }
            pendingReceiveCompletion = completion
            receiveContinuation.yield(())
        }
    }

    /// Safe from any thread; latches `.cancelled` synchronously, then tears
    /// down on `queue`.
    func forceCancel() {
        forceCancel(completion: {})
    }

    /// Variant whose completion fires exactly once, after the connection is fully
    /// torn down; calls after teardown completes fire immediately.
    func forceCancel(completion: @escaping @Sendable () -> Void) {
        enum Action { case startTeardown, queue, fireImmediately }

        let action: Action = stateLock.withLock { (protected: inout Protected) -> Action in
            if protected.teardownComplete {
                return .fireImmediately
            }
            if case .cancelled = protected.state {
                protected.teardownCompletions.append(completion)
                return .queue
            }
            protected.state = .cancelled
            protected.teardownCompletions.append(completion)
            return .startTeardown
        }

        switch action {
        case .fireImmediately:
            completion()
        case .queue:
            return
        case .startTeardown:
            queue.async { [self] in beginTeardown() }
        }
    }

    // MARK: - Driver

    /// Owns the `NetworkConnection` for the whole session. `withNetworkConnection`
    /// tears the connection down deterministically when this task is cancelled or
    /// returns. Runs off `queue`; all state mutation hops back onto `queue`.
    private func runDriver(
        endpoint: NWEndpoint,
        sendStream: AsyncStream<SendJob>,
        receiveStream: AsyncStream<Void>
    ) async {
        do {
            try await withNetworkConnection(to: endpoint, using: { Self.makeProtocolStack() }) { [self] conn in
                conn.onStateUpdate { [weak self] _, state in
                    guard let self else { return }
                    switch state {
                    case .ready:
                        self.queue.async { self.handleConnectReady() }
                    case .failed(let error):
                        self.queue.async { self.handleConnectionFailure(error, waiting: false) }
                    case .waiting(let error):
                        self.queue.async { self.handleConnectionFailure(error, waiting: true) }
                    default:
                        break  // .setup, .preparing, .cancelled
                    }
                }
                // TCP can't migrate a 4-tuple: a viability drop means the leg is
                // dead, so fail it and let the next dial pick a live path.
                conn.onViabilityUpdate { [weak self] _, viable in
                    guard let self, !viable else { return }
                    self.queue.async { self.handleViabilityLost() }
                }

                try await withThrowingTaskGroup(of: Void.self) { group in
                    group.addTask { try await self.runSendLoop(conn, stream: sendStream) }
                    group.addTask { try await self.runReceiveLoop(conn, stream: receiveStream) }
                    // First loop to end (fatal error or cancellation) tears down
                    // the leg; propagate a throw so the connection is discarded.
                    _ = try await group.next()
                    group.cancelAll()
                }
            }
        } catch {
            queue.async { [self] in handleDriverError(error) }
        }
        queue.async { [self] in finalizeTeardown() }
    }

    /// Drains ordered send jobs. The establish job starts the connection and
    /// flushes initial data; readiness itself is reported via `onStateUpdate`.
    /// A steady-state send failure is surfaced to its completion but is not
    /// fatal — the receive loop / state handler tear the leg down. Runs off `queue`.
    private func runSendLoop(_ conn: NetworkConnection<TCP>, stream: AsyncStream<SendJob>) async throws {
        for await job in stream {
            do {
                try await conn.send(job.data, endOfStream: job.endOfStream)
                if job.isEstablish {
                    // The establish send returns once the connection is ready and
                    // the initial data is flushed — an authoritative readiness
                    // signal independent of `onStateUpdate` (idempotent with it).
                    queue.async { [self] in handleConnectReady() }
                } else {
                    queue.async { [self] in completeSend(nil) }
                }
            } catch {
                if job.isEstablish {
                    let mapped = Self.mapError(error, op: .connect)
                    queue.async { [self] in finishConnectFailure(mapped) }
                    throw error  // dial failed: tear the connection down
                }
                let mapped = Self.mapError(error, op: .send)
                queue.async { [self] in completeSend(mapped) }
            }
        }
    }

    /// Awaits one `NetworkConnection.receive` per caller token. A receive failure
    /// is fatal: it surfaces the error and tears the leg down. Runs off `queue`.
    private func runReceiveLoop(_ conn: NetworkConnection<TCP>, stream: AsyncStream<Void>) async throws {
        for await _ in stream {
            do {
                let message = try await conn.receive(atLeast: 1, atMost: Self.maxReceiveLength)
                let content = message.content
                let endOfStream = message.metadata.endOfStream
                queue.async { [self] in deliverReceive(content: content, endOfStream: endOfStream) }
            } catch {
                // Fail the leg atomically: transition to `.failed` and notify the
                // in-flight receive in one hop, then tear the connection down.
                let mapped = Self.mapError(error, op: .receive)
                queue.async { [self] in failActive(with: mapped) }
                throw error
            }
        }
    }

    // MARK: - Connect resolution (on queue)

    /// Promotes to `.ready` and fires the connect completion exactly once. A
    /// racing `.cancelled` wins; teardown fires the completion instead.
    private func handleConnectReady() {
        guard transitionFromSetup(to: .ready) else { return }
        cancelDialDeadline()
        dialTimer.stop()
        let completion = connectCompletion
        connectCompletion = nil
        completion?(nil)
    }

    /// A `.failed`/`.waiting` state report. Pre-ready it fails the dial fast;
    /// post-ready a hard `.failed` fails the active leg (a transient `.waiting`
    /// is left to `onViabilityUpdate`).
    private func handleConnectionFailure(_ error: NWError, waiting: Bool) {
        if case .setup = state {
            logger.debug("[TCP] connect \(endpointDescription) \(waiting ? error.connectWaitingDescription : "failed: \(error)"); failing fast")
            finishConnectFailure(error.transportError(op: .connect))
            abortDriver()
        } else if !waiting {
            failActive(with: error.transportError(op: .receive))
        }
    }

    /// Connect failed. Transitions to `.failed` and fires the completion once.
    /// If a racing `forceCancel()` already latched `.cancelled`, the completion
    /// is left for the teardown path to fire as "Cancelled".
    private func finishConnectFailure(_ error: Error) {
        cancelDialDeadline()
        guard transitionFromSetup(to: .failed(error)) else { return }
        let completion = connectCompletion
        connectCompletion = nil
        completion?(error)
    }

    /// Egress under a ready connection went away. Must run on `queue`.
    private func handleViabilityLost() {
        failActive(with: TransportError.connectionFailed("Network path no longer viable"))
    }

    /// Moves a ready leg to `.failed`, notifies an in-flight receive, and tears
    /// the connection down. Must run on `queue`.
    private func failActive(with error: Error) {
        let changed: Bool = stateLock.withLock {
            if case .ready = $0.state { $0.state = .failed(error); return true }
            return false
        }
        guard changed else { return }
        if let completion = pendingReceiveCompletion {
            pendingReceiveCompletion = nil
            completion(nil, true, error)
        }
        abortDriver()
    }

    // MARK: - Send/receive delivery (on queue)

    /// Fires the head send completion in submission order.
    private func completeSend(_ error: Error?) {
        guard !pendingSendCompletions.isEmpty else { return }
        let completion = pendingSendCompletions.removeFirst()
        completion?(error)
    }

    /// Delivers one successful receive result, mirroring the framed-EOF contract:
    /// a final segment carrying data is delivered as data now, with EOF latched
    /// for the next receive. Failures go through `failActive` instead.
    private func deliverReceive(content: Data?, endOfStream: Bool) {
        guard let completion = pendingReceiveCompletion else { return }

        if let data = content, !data.isEmpty {
            if endOfStream { receivedEOF = true }
            pendingReceiveCompletion = nil
            completion(data, false, nil)
            return
        }
        if endOfStream {
            receivedEOF = true
            pendingReceiveCompletion = nil
            completion(nil, true, nil)
            return
        }
        // No data, not complete (shouldn't happen with atLeast: 1): re-issue.
        receiveContinuation?.yield(())
    }

    // MARK: - Teardown (on queue)

    /// Fails in-flight work with a cancellation error, then cancels the driver so
    /// the connection tears down. Full teardown completes in `finalizeTeardown`.
    private func beginTeardown() {
        cancelDialDeadline()
        if let completion = connectCompletion {
            connectCompletion = nil
            completion(TransportError.connectionFailed("Cancelled"))
        }
        if let completion = pendingReceiveCompletion {
            pendingReceiveCompletion = nil
            completion(nil, true, TransportError.notConnected)
        }
        failAllPendingSends(TransportError.connectionFailed("Cancelled"))

        sendContinuation?.finish()
        sendContinuation = nil
        receiveContinuation?.finish()
        receiveContinuation = nil

        if let task = driverTask {
            driverTask = nil
            task.cancel()  // `finalizeTeardown` runs when the driver unwinds
        } else {
            finalizeTeardown()
        }
    }

    /// Balances `FlowGauge`, marks teardown complete, and fires the pending
    /// teardown completions. Idempotent. Must run on `queue`.
    private func finalizeTeardown() {
        releaseFlowCount()
        let completions: [@Sendable () -> Void] = stateLock.withLock { protected in
            guard !protected.teardownComplete else { return [] }
            protected.teardownComplete = true
            let pending = protected.teardownCompletions
            protected.teardownCompletions.removeAll()
            return pending
        }
        for completion in completions {
            completion()
        }
    }

    /// A driver exit outside the cancel path: report a connect-phase failure, or
    /// fail the active leg. No-ops once the relevant completion has already fired.
    private func handleDriverError(_ error: Error) {
        if connectCompletion != nil {
            finishConnectFailure(Self.mapError(error, op: .connect))
        } else {
            failActive(with: Self.mapError(error, op: .receive))
        }
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
        FlowGauge.decrementTCP()
    }

    // MARK: - Dial deadline

    /// Arms the wall-clock dial backstop on `queue`. Catches dials that hang
    /// without ever reporting `.waiting`/`.failed`.
    private func armDialDeadline() {
        let deadline = DispatchWorkItem { [weak self] in
            guard let self, case .setup = self.state else { return }
            logger.debug("[TCP] Dial deadline exceeded (\(Self.dialDeadlineSeconds)s): \(self.endpointDescription)")
            self.finishConnectFailure(TransportError.posixError(.connect, errno: ETIMEDOUT))
            self.abortDriver()
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

    // MARK: - Parameters

    /// The TCP protocol stack mirroring the old `NWParameters` tuning.
    private static func makeProtocolStack() -> TCP {
        TCP()
            .noDelay(true)
            .keepalive(idleTimeInSeconds: 30, count: 3, intervalInSeconds: 10)
            .connectionTimeout(UInt32(Self.connectTimeout))
    }

    /// Maps a `NetworkConnection` throw to a `TransportError` for operation `op`.
    private static func mapError(_ error: Error, op: TransportError.Operation) -> Error {
        if error is CancellationError { return TransportError.connectionFailed("Cancelled") }
        if let nwError = error as? NWError { return nwError.transportError(op: op) }
        return TransportError.connectionFailed(error.localizedDescription)
    }
}
