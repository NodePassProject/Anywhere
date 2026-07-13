//
//  NWTCPTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 6/30/26.
//

import Foundation
import Network
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "NWTCPTransport")

// MARK: - NWTCPTransport

nonisolated final class NWTCPTransport: RawTransport, @unchecked Sendable {

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
        /// Tear down with RST instead of a graceful close — set by `forceAbort()`,
        /// or when the connection never was cleanly `.ready`.
        var abortiveTeardown = false
    }

    private let stateLock = Mutex(Protected())

    /// The current state of the transport. Thread-safe.
    var state: State {
        stateLock.withLock { $0.state }
    }

    // MARK: Concurrency

    /// Serial queue for all connection callbacks and state transitions.
    private let queue = DispatchQueue(label: AWCore.Identifier.nwTCPTransportQueue, qos: .userInitiated, autoreleaseFrequency: .workItem)

    // MARK: Connection

    /// The live connection; `nil` after teardown. Mutated only on `queue`.
    private var connection: NWConnection?

    /// Whether this transport's `NWConnection` is counted in `FlowGauge`.
    /// `queue`-confined; balanced exactly once by `releaseFlowCount`.
    private var flowCounted = false

    // MARK: Connect pipeline

    private var connectCompletion: ((Error?) -> Void)?
    private var pendingInitialData: Data?

    /// Backstop that fails the dial if it never reaches `.ready`/`.failed`; armed in
    /// `connect`, cancelled the moment the dial resolves. Touched only on `queue`.
    private var dialDeadline: DispatchWorkItem?

    /// "host:port" for diagnostics. Set once in `connect`.
    private var endpointDescription = ""

    /// Whether the dial ever reached `.preparing`; disambiguates the
    /// dial-deadline diagnostic. `queue`-confined.
    private var sawPreparing = false

    /// Times the dial for the live "Dial" stat; direct/bypass dials disable it
    /// so only proxied first-hop dials are counted.
    var dialTimer = MetricTimer(.dial)

    // MARK: Receive pipeline

    /// At most one receive in flight; callers issue receives serially.
    private var pendingReceiveCompletion: ((Data?, Bool, Error?) -> Void)?
    /// Latched on remote half-close; later receives return EOF immediately.
    private var receivedEOF = false

    // MARK: - Lifecycle

    init() {}

    deinit {
        guard flowCounted else { return }
        flowCounted = false
        FlowGauge.decrementTCP()
        connection?.forceCancel()
        logger.error("[TCP] Transport deallocated with its flow still counted — teardown never ran. Recovered the FlowGauge count and socket in deinit; a cancel path has regressed.")
    }

    // MARK: - RawTransport

    var isTransportReady: Bool {
        if case .ready = state { return true }
        return false
    }

    /// Connects asynchronously. `NWConnection` resolves `host` (or uses it
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

            pendingInitialData = initialData
            connectCompletion = completion
            endpointDescription = "\(host):\(port)"
            dialTimer.start()
            armDialDeadline()

            let endpointHost = NWEndpoint.Host(ipLiteral: host) ?? .name(host, nil)
            let connection = NWConnection(to: .hostPort(host: endpointHost, port: nwPort),
                                          using: Self.makeParameters())
            self.connection = connection
            flowCounted = true
            FlowGauge.incrementTCP()
            connection.stateUpdateHandler = { [weak self] newState in
                self?.handleConnectionState(newState)
            }
            connection.start(queue: queue)
        }
    }

    /// Ordered send; `NWConnection` handles partial writes and backpressure.
    /// `completion` fires on `queue`.
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

    /// Half-closes the send direction: `.finalMessage` emits a FIN ordered after
    /// every issued send; receive stays open. `completion` fires on `queue`.
    func closeWrite(completion: @escaping (Error?) -> Void) {
        queue.async { [self] in
            switch state {
            case .ready:
                guard let connection else {
                    completion(TransportError.notConnected)
                    return
                }
                connection.send(content: nil,
                                contentContext: .finalMessage,
                                isComplete: true,
                                completion: .contentProcessed { error in
                    completion(error.map { $0.transportError(op: .send) })
                })
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
            guard let connection else {
                completion(nil, true, TransportError.notConnected)
                return
            }
            pendingReceiveCompletion = completion
            connection.receive(minimumIncompleteLength: 1,
                               maximumLength: Self.maxReceiveLength) { [weak self] data, _, isComplete, error in
                self?.handleReceive(data: data, isComplete: isComplete, error: error)
            }
        }
    }

    /// Safe from any thread; latches `.cancelled` synchronously, then tears
    /// down on `queue`.
    func forceCancel() {
        forceCancel(completion: {})
    }

    func forceAbort() {
        stateLock.withLock { $0.abortiveTeardown = true }
        forceCancel()
    }

    /// Variant whose completion fires exactly once, after the connection is fully
    /// cancelled; calls after teardown completes fire immediately.
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
            // Never cleanly `.ready`: nothing to flush, so close abortively.
            if case .ready = protected.state {} else {
                protected.abortiveTeardown = true
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
            queue.async { [self] in
                cancelDialDeadline()
                if let c = connectCompletion {
                    connectCompletion = nil
                    c(TransportError.connectionFailed("Cancelled"))
                }
                if let pendingComp = pendingReceiveCompletion {
                    pendingReceiveCompletion = nil
                    pendingComp(nil, true, TransportError.notConnected)
                }
                pendingInitialData = nil
                teardown { [self] in
                    notifyTeardownComplete()
                }
            }
        }
    }

    private func notifyTeardownComplete() {
        let completions: [@Sendable () -> Void] = stateLock.withLock { protected in
            protected.teardownComplete = true
            let pending = protected.teardownCompletions
            protected.teardownCompletions.removeAll()
            return pending
        }
        for completion in completions {
            completion()
        }
    }

    // MARK: - Connect pipeline

    /// Balances `FlowGauge` exactly once per transport. Must run on `queue`.
    private func releaseFlowCount() {
        guard flowCounted else { return }
        flowCounted = false
        FlowGauge.decrementTCP()
    }

    /// Arms the wall-clock dial backstop on `queue`. Catches dials that hang
    /// without ever reporting `.waiting`/`.failed`.
    private func armDialDeadline() {
        let deadline = DispatchWorkItem { [weak self] in
            guard let self, case .setup = self.state else { return }
            let lastState = self.sawPreparing ? "preparing, no error reported" : "no state updates"
            let message = "Dial deadline exceeded (\(Self.dialDeadlineSeconds)s; last state: \(lastState))"
            logger.debug("[TCP] \(message): \(self.endpointDescription)")
            self.finishConnectFailure(TransportError.posixError(.connect, errno: ETIMEDOUT))
        }
        dialDeadline = deadline
        queue.asyncAfter(deadline: .now() + .seconds(Self.dialDeadlineSeconds), execute: deadline)
    }

    /// Cancels the dial backstop once the dial resolves. Must run on `queue`.
    private func cancelDialDeadline() {
        dialDeadline?.cancel()
        dialDeadline = nil
    }

    private func handleConnectionState(_ newState: NWConnection.State) {
        switch newState {
        case .ready:
            handleConnectReady()
        case .failed(let error):
            logger.debug("[TCP] connect \(endpointDescription) failed: \(error)")
            finishConnectFailure(error.transportError(op: .connect))
        case .waiting(let error):
            logger.debug("[TCP] connect \(endpointDescription) \(error.connectWaitingDescription); failing fast")
            finishConnectFailure(error.transportError(op: .connect))
        case .preparing:
            sawPreparing = true
        default:
            break  // .setup, .cancelled
        }
    }

    /// Promotes to `.ready`, sends `initialData`, and fires the connect
    /// completion exactly once. Must run on `queue`.
    private func handleConnectReady() {
        // A racing .cancelled wins; teardown fires the completion.
        guard transitionFromSetup(to: .ready) else { return }
        cancelDialDeadline()

        dialTimer.stop()

        // Send initial data before the completion so it precedes any caller send
        // issued from the completion (NWConnection preserves send order).
        if let data = pendingInitialData, !data.isEmpty, let connection {
            connection.send(content: data, completion: .idempotent)
        }
        pendingInitialData = nil

        let completion = connectCompletion
        connectCompletion = nil
        completion?(nil)

        // Arm the connection's receive-side error path independent of pending reads.
        rearmReceiveHandler()
    }

    /// Connect failed. Transitions to `.failed` and fires the completion once.
    /// If a racing `forceCancel()` already latched `.cancelled`, the completion
    /// is left for the teardown path to fire as "Cancelled".
    private func finishConnectFailure(_ error: Error) {
        cancelDialDeadline()
        pendingInitialData = nil
        if let connection {
            self.connection = nil
            connection.stateUpdateHandler = nil
            releaseFlowCount()
            // An unestablished dial has nothing to flush; free the socket now.
            connection.forceCancel()
        }

        guard transitionFromSetup(to: .failed(error)) else { return }
        let c = connectCompletion
        connectCompletion = nil
        c?(error)
    }

    /// Replaces the connect-phase state handler with a steady-state one that
    /// surfaces a remote/path failure to any in-flight receive. `.cancelled`
    /// needs no handling: every cancel path nils or replaces this handler
    /// before cancelling the connection.
    private func rearmReceiveHandler() {
        guard let connection else { return }
        connection.stateUpdateHandler = { [weak self] newState in
            guard let self, case .failed(let error) = newState else { return }
            self.failActive(with: error.transportError(op: .receive))
        }
        // NWConnection drops viability before a send/receive would error. TCP can't
        // migrate a 4-tuple, so fail the leg promptly — the next dial picks the live
        // path. `failActive` only acts in `.ready`, so a teardown blip is a no-op.
        connection.viabilityUpdateHandler = { [weak self] viable in
            guard let self, !viable else { return }
            self.failActive(with: TransportError.connectionFailed("Network path no longer viable"))
        }
    }

    /// Moves to `.failed` and notifies an in-flight receive. Must run on `queue`.
    private func failActive(with error: Error) {
        let changed: Bool = stateLock.withLock {
            if case .ready = $0.state { $0.state = .failed(error); return true }
            return false
        }
        guard changed else { return }
        // Discard the dead connection now: waiting for the owner's teardown
        // (or its idle timer) would pin the kernel socket for nothing.
        if let connection {
            self.connection = nil
            connection.stateUpdateHandler = nil
            connection.viabilityUpdateHandler = nil
            releaseFlowCount()
            connection.forceCancel()
        }
        if let completion = pendingReceiveCompletion {
            pendingReceiveCompletion = nil
            completion(nil, true, error)
        }
    }

    // MARK: - Receive pipeline

    /// Handles one `NWConnection.receive` callback. Must run on `queue`.
    private func handleReceive(data: Data?, isComplete: Bool, error: NWError?) {
        guard let completion = pendingReceiveCompletion else { return }

        if let error {
            pendingReceiveCompletion = nil
            completion(nil, true, error.transportError(op: .receive))
            return
        }

        if let data, !data.isEmpty {
            // Final segment may arrive with data; deliver it now and latch EOF
            // so the next receive returns end-of-stream.
            if isComplete { receivedEOF = true }
            pendingReceiveCompletion = nil
            completion(data, false, nil)
            return
        }

        if isComplete {
            receivedEOF = true
            pendingReceiveCompletion = nil
            completion(nil, true, nil)
            return
        }

        // No data, not complete, no error: re-issue (NWConnection should not
        // deliver this given minimumIncompleteLength: 1, but stay safe).
        guard let connection else {
            pendingReceiveCompletion = nil
            completion(nil, true, TransportError.notConnected)
            return
        }
        connection.receive(minimumIncompleteLength: 1,
                           maximumLength: Self.maxReceiveLength) { [weak self] data, _, isComplete, error in
            self?.handleReceive(data: data, isComplete: isComplete, error: error)
        }
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

    // MARK: - Teardown

    /// Cancels the connection; `completion` fires once it reaches `.cancelled`,
    /// or immediately if there is nothing to cancel. Must run on `queue`.
    private func teardown(completion: @escaping () -> Void) {
        guard let connection else {
            completion()
            return
        }
        self.connection = nil
        releaseFlowCount()
        connection.stateUpdateHandler = { newState in
            if case .cancelled = newState { completion() }
        }
        if stateLock.withLock({ $0.abortiveTeardown }) {
            connection.forceCancel()
        } else {
            connection.cancel()
        }
    }

    // MARK: - Parameters

    private static func makeParameters() -> NWParameters {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.enableKeepalive = true
        tcp.keepaliveIdle = 30
        tcp.keepaliveInterval = 10
        tcp.keepaliveCount = 3
        tcp.connectionTimeout = Self.connectTimeout
        let parameters = NWParameters(tls: nil, tcp: tcp)
        return parameters
    }
}
