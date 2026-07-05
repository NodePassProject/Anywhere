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

// MARK: - NWError handling

nonisolated func mapNWError(_ error: NWError, op: TransportError.Operation) -> TransportError {
    switch error {
    case .posix(let code):
        return .posixError(op, errno: code.rawValue)
    case .dns:
        return .resolutionFailed(error.localizedDescription)
    default:
        // .tls and any SDK-newer cases (e.g. .wifiAware) fold to a generic failure.
        return .connectionFailed(error.localizedDescription)
    }
}

nonisolated func isDefinitiveConnectError(_ error: NWError) -> Bool {
    guard case .posix(let code) = error else { return false }
    switch code {
    case .ECONNREFUSED, .EHOSTUNREACH, .ENETUNREACH, .ECONNRESET,
         .ETIMEDOUT, .EHOSTDOWN, .ENETDOWN, .EADDRNOTAVAIL, .EPFNOSUPPORT, .EAFNOSUPPORT:
        return true
    default:
        return false
    }
}

nonisolated func isResourceExhaustionError(_ error: NWError) -> Bool {
    guard case .posix(let code) = error else { return false }
    switch code {
    case .ENOMEM, .ENOBUFS, .EMFILE, .ENFILE:
        return true
    default:
        return false
    }
}

nonisolated func nwHost(fromIPLiteral ip: String) -> NWEndpoint.Host? {
    if ip.contains(":") {
        return IPv6Address(ip).map { .ipv6($0) }
    }
    return IPv4Address(ip).map { .ipv4($0) }
}

// MARK: - DialGauge

/// Process-wide count of TCP dials in flight (connect issued, not yet resolved).
nonisolated enum DialGauge {
    private static let count = Atomic<Int>(0)

    static var inFlight: Int {
        count.load(ordering: .relaxed)
    }

    static func increment() {
        count.wrappingAdd(1, ordering: .relaxed)
    }

    static func decrement() {
        count.wrappingSubtract(1, ordering: .relaxed)
    }
}

// MARK: - DialGate

/// Global cap on concurrent TCP dial attempts.
nonisolated enum DialGate {
    /// Concurrent-dial ceiling; generous for interactive bursts, far below the
    /// observed ENOMEM collapse (~250 in-flight dials).
    static let maxConcurrentDials = 64

    private struct State {
        var active = 0
        var nextTicket: UInt64 = 0
        var waiters: [(ticket: UInt64, start: @Sendable () -> Void)] = []
    }

    private static let state = Mutex(State())

    /// (dialing now, queued) — sampled by failure diagnostics.
    static var stats: (active: Int, queued: Int) {
        state.withLock { ($0.active, $0.waiters.count) }
    }

    /// Claims a slot: returns nil when one is free (the caller proceeds
    /// immediately and owns the slot), otherwise queues `start` and returns its
    /// ticket. A queued `start` runs exactly once, when a slot frees, unless
    /// cancelled first — and then owns the slot the same way.
    static func acquire(_ start: @escaping @Sendable () -> Void) -> UInt64? {
        state.withLock { (state: inout State) -> UInt64? in
            if state.active < maxConcurrentDials {
                state.active += 1
                return nil
            }
            state.nextTicket += 1
            state.waiters.append((state.nextTicket, start))
            return state.nextTicket
        }
    }

    /// Removes a queued waiter. Returns false when it already started (or never
    /// existed) — its closure then owns the slot and must release it.
    static func cancelWaiter(_ ticket: UInt64) -> Bool {
        state.withLock { state in
            guard let index = state.waiters.firstIndex(where: { $0.ticket == ticket }) else { return false }
            state.waiters.remove(at: index)
            return true
        }
    }

    /// Releases a slot: hands it to the newest waiter, or lowers `active`.
    static func release() {
        let next = state.withLock { (state: inout State) -> (@Sendable () -> Void)? in
            if let waiter = state.waiters.popLast() { return waiter.start }
            state.active -= 1
            return nil
        }
        // Outside the lock; the closure hops to its transport's queue.
        next?()
    }
}

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

    /// Minimum time a connection must have actually been dialing before a
    /// deadline timeout counts as destination evidence.
    private static let minDialProbeSeconds: TimeInterval = 10

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

    /// Serial queue for all connection callbacks and state transitions.
    private let queue = DispatchQueue(label: AWCore.Identifier.nwTCPTransportQueue,
                                      qos: .userInitiated,
                                      autoreleaseFrequency: .workItem)

    // MARK: Connection

    /// The live connection; `nil` between attempts and after teardown. Mutated
    /// only on `queue`.
    private var connection: NWConnection?

    // MARK: Connect pipeline

    private var connectCompletion: ((Error?) -> Void)?
    private var pendingInitialData: Data?

    /// Backstop that fails the dial if it never reaches `.ready`/`.failed`; armed in
    /// `connect`, cancelled the moment the dial resolves. Touched only on `queue`.
    private var dialDeadline: DispatchWorkItem?

    /// "host:port" for connect-phase diagnostics. Set once in `connect`.
    private var dialEndpointDescription = ""

    /// Last non-definitive `.waiting` error seen during the dial, plus whether the
    /// dial ever reached `.preparing`. `queue`-confined.
    private var lastWaitingDescription: String?
    private var sawPreparing = false

    /// Whether this dial is counted in `DialGauge`. `queue`-confined.
    private var countedInFlightDial = false

    /// Dial-gate bookkeeping: `dialGateTicket` is non-nil while queued for a
    /// slot; `holdsDialGateSlot` is true from slot acquisition until
    /// `markDialResolved` releases it. Both `queue`-confined.
    private var dialGateTicket: UInt64?
    private var holdsDialGateSlot = false

    /// When `beginDial` started the `NWConnection`, on the `MonotonicClock`
    /// timeline; nil while still queued at the gate. `queue`-confined.
    private var dialStartedAt: TimeInterval?

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

    // MARK: - RawTransport

    var isTransportReady: Bool {
        if case .ready = state { return true }
        return false
    }

    /// Connects asynchronously. `NWConnection` resolves `host` (or uses it
    /// directly when it's an IP literal) and races addresses (Happy Eyeballs);
    /// `initialData` is sent once ready. `completion` fires on `queue`.
    func connect(host: String, port: UInt16,
                 initialData: Data? = nil,
                 completion: @escaping (Error?) -> Void) {
        queue.async { [self] in
            if case .cancelled = state {
                completion(TransportError.connectionFailed("Cancelled"))
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
            dialEndpointDescription = "\(host):\(port)"
            countedInFlightDial = true
            DialGauge.increment()
            dialTimer.start()
            armDialDeadline()

            let endpointHost = nwHost(fromIPLiteral: host) ?? .name(host, nil)
            let endpoint = NWEndpoint.hostPort(host: endpointHost, port: nwPort)
            if let ticket = DialGate.acquire({ [weak self] in
                // The popped waiter owns the slot; a transport torn down without
                // cancel must still hand it back.
                guard let self else {
                    DialGate.release()
                    return
                }
                self.queue.async { self.beginDial(to: endpoint) }
            }) {
                dialGateTicket = ticket
            } else {
                beginDial(to: endpoint)
            }
        }
    }

    /// Starts the `NWConnection` once a dial-gate slot is held. Must run on
    /// `queue`. A dial cancelled or timed out while queued releases the slot
    /// without dialing.
    private func beginDial(to endpoint: NWEndpoint) {
        dialGateTicket = nil
        holdsDialGateSlot = true
        guard case .setup = state else {
            holdsDialGateSlot = false
            DialGate.release()
            return
        }
        dialStartedAt = MonotonicClock.now
        let connection = NWConnection(to: endpoint, using: Self.makeParameters())
        self.connection = connection
        connection.stateUpdateHandler = { [weak self] newState in
            self?.handleConnectState(newState)
        }
        connection.start(queue: queue)
    }

    /// Ordered send; `NWConnection` handles partial writes and backpressure.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        queue.async { [self] in
            switch state {
            case .ready:
                guard let connection else {
                    completion(TransportError.notConnected)
                    return
                }
                connection.send(content: data, completion: .contentProcessed { error in
                    completion(error.map { mapNWError($0, op: .send) })
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

    /// Receives once. Completion: `(data, false, nil)` on data,
    /// `(nil, true, nil)` on EOF, `(nil, true, error)` on failure.
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
                markDialResolved()
                if let c = connectCompletion {
                    connectCompletion = nil
                    c(TransportError.connectionFailed("Cancelled"))
                }
                if let pendingComp = pendingReceiveCompletion {
                    pendingReceiveCompletion = nil
                    pendingComp(nil, true, TransportError.notConnected)
                }
                pendingInitialData = nil
                tearDownConnection { [self] in
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

    /// Balances `DialGauge` and `DialGate` exactly once per dial. Must run on `queue`.
    private func markDialResolved() {
        guard countedInFlightDial else { return }
        countedInFlightDial = false
        DialGauge.decrement()
        if let ticket = dialGateTicket {
            dialGateTicket = nil
            // A false return means the waiter was already popped; its closure
            // still runs, and `beginDial` releases the slot on seeing the
            // resolved state.
            _ = DialGate.cancelWaiter(ticket)
        } else if holdsDialGateSlot {
            holdsDialGateSlot = false
            DialGate.release()
        }
    }
    
    static let dialDeadlinePrefix = "Dial deadline exceeded"
    
    static let dialQueuedDeadlinePrefix = "Dial queue deadline exceeded"

    /// Arms the wall-clock dial backstop on `queue`. Bounds time spent queued at
    /// the gate or in `.waiting`, which `connectionTimeout` does not.
    private func armDialDeadline() {
        let deadline = DispatchWorkItem { [weak self] in
            guard let self, case .setup = self.state else { return }
            let message: String
            let probeSeconds = self.dialStartedAt.map { MonotonicClock.now - $0 }
            if self.dialGateTicket != nil {
                message = "\(Self.dialQueuedDeadlinePrefix) (\(Self.dialDeadlineSeconds)s; "
                    + "dial gate full, \(DialGate.stats.queued) waiting)"
            } else if let probeSeconds, probeSeconds < Self.minDialProbeSeconds {
                message = "\(Self.dialQueuedDeadlinePrefix) (\(Self.dialDeadlineSeconds)s; "
                    + "dialed only \(Int(probeSeconds))s after gate wait)"
            } else {
                let lastState = self.lastWaitingDescription
                    ?? (self.sawPreparing ? "preparing, no error reported" : "no state updates")
                message = "\(Self.dialDeadlinePrefix) (\(Self.dialDeadlineSeconds)s; last state: \(lastState))"
            }
            logger.debug("[TCP] \(message): \(self.dialEndpointDescription)")
            self.finishConnectFailure(TransportError.connectionFailed(message))
        }
        dialDeadline = deadline
        queue.asyncAfter(deadline: .now() + .seconds(Self.dialDeadlineSeconds), execute: deadline)
    }

    /// Cancels the dial backstop once the dial resolves. Must run on `queue`.
    private func cancelDialDeadline() {
        dialDeadline?.cancel()
        dialDeadline = nil
    }

    /// Handles connect-phase state changes. `NWConnection` resolves the name and
    /// races addresses; a definitive failure or the `connectionTimeout` drives
    /// `.failed`. Must run on `queue`.
    private func handleConnectState(_ newState: NWConnection.State) {
        switch newState {
        case .ready:
            handleConnectReady()
        case .failed(let error):
            logger.debug("[TCP] connect failed: \(error)")
            finishConnectFailure(mapNWError(error, op: .connect))
        case .waiting(let error):
            if isDefinitiveConnectError(error) {
                logger.debug("[TCP] connect unreachable: \(error)")
                finishConnectFailure(mapNWError(error, op: .connect))
            } else if isResourceExhaustionError(error) {
                logger.debug("[TCP] connect resource exhaustion: \(dialEndpointDescription): \(error)")
                finishConnectFailure(mapNWError(error, op: .connect))
            } else {
                let description = Self.describeConnectWaiting(error)
                if description != lastWaitingDescription {
                    logger.debug("[TCP] connect \(dialEndpointDescription) \(description)")
                    lastWaitingDescription = description
                }
            }
        case .preparing:
            sawPreparing = true
        default:
            break  // .setup, .cancelled
        }
    }
    
    private static func describeConnectWaiting(_ error: NWError) -> String {
        switch error {
        case .posix(let code):
            return "waiting(errno \(code.rawValue): \(String(cString: strerror(code.rawValue))))"
        case .dns(let code):
            return "waiting(dns \(code))"
        default:
            return "waiting(\(error.localizedDescription))"
        }
    }

    /// Promotes to `.ready`, sends `initialData`, and fires the connect
    /// completion exactly once. Must run on `queue`.
    private func handleConnectReady() {
        markDialResolved()
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
    private func finishConnectFailure(_ error: Error) {
        cancelDialDeadline()
        markDialResolved()
        pendingInitialData = nil
        if let connection {
            self.connection = nil
            connection.stateUpdateHandler = nil
            connection.cancel()
        }

        guard transitionFromSetup(to: .failed(error)) else { return }
        let c = connectCompletion
        connectCompletion = nil
        c?(error)
    }

    /// Replaces the connect-phase state handler with a steady-state one that
    /// surfaces a remote/path failure to any in-flight receive.
    private func rearmReceiveHandler() {
        guard let connection else { return }
        connection.stateUpdateHandler = { [weak self] newState in
            guard let self else { return }
            switch newState {
            case .failed(let error):
                self.failActive(with: mapNWError(error, op: .receive))
            case .cancelled:
                self.notifyTeardownComplete()
            default:
                break
            }
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
            completion(nil, true, mapNWError(error, op: .receive))
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
    private func tearDownConnection(completion: @escaping () -> Void) {
        guard let connection else {
            completion()
            return
        }
        self.connection = nil
        connection.stateUpdateHandler = { newState in
            if case .cancelled = newState { completion() }
        }
        connection.cancel()
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
