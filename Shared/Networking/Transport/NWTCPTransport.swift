//
//  NWTCPTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 6/30/26.
//

import Foundation
import Network

nonisolated private let logger = AnywhereLogger(category: "NWTCPTransport")

// MARK: - NWError mapping (shared with NWUDPTransport)

/// Translates an `NWError` into the project's `TransportError`, preserving the raw
/// `errno` so callers (e.g. `TransportErrorLogger`) can keep classifying by code.
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

/// `NWConnection` keeps retrying in `.waiting` on both transient and definitive
/// failures. Definitive per-address errors won't resolve on the current path, so
/// the caller fails them immediately rather than stalling until the attempt timeout.
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

/// Parses an IPv4/IPv6 literal into an `NWEndpoint.Host`; returns nil for a
/// hostname, which the caller passes to `NWConnection` as a `.name` to resolve.
nonisolated func nwHost(fromIPLiteral ip: String) -> NWEndpoint.Host? {
    if ip.contains(":") {
        return IPv6Address(ip).map { .ipv6($0) }
    }
    return IPv4Address(ip).map { .ipv4($0) }
}

// MARK: - NWTCPTransport

/// A TCP transport over `NWConnection`. All callbacks and state mutations run on
/// the serial `queue`; `state` is additionally lock-protected so `isTransportReady`
/// and `forceCancel()` are safe from any thread.
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

    private static let maxReceiveLength = 65535

    // MARK: State

    private let stateLock = UnfairLock()
    private var _state: State = .setup

    /// Completions awaiting full teardown. Protected by `stateLock`.
    private var teardownCompletions: [@Sendable () -> Void] = []
    /// Set once teardown has finished. Protected by `stateLock`.
    private var teardownComplete = false

    /// The current state of the transport. Thread-safe.
    var state: State {
        stateLock.withLock { _state }
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
                    if case .setup = _state { _state = .failed(error) }
                }
                completion(error)
                return
            }

            pendingInitialData = initialData
            connectCompletion = completion
            // Dial timing spans name resolution; NWConnection owns DNS.
            dialTimer.start()

            let endpointHost = nwHost(fromIPLiteral: host) ?? .name(host, nil)
            let connection = NWConnection(to: .hostPort(host: endpointHost, port: nwPort),
                                          using: Self.makeParameters())
            self.connection = connection
            connection.stateUpdateHandler = { [weak self] newState in
                self?.handleConnectState(newState)
            }
            connection.start(queue: queue)
        }
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

        let action: Action = stateLock.withLock { () -> Action in
            if teardownComplete {
                return .fireImmediately
            }
            if case .cancelled = _state {
                teardownCompletions.append(completion)
                return .queue
            }
            _state = .cancelled
            teardownCompletions.append(completion)
            return .startTeardown
        }

        switch action {
        case .fireImmediately:
            completion()
        case .queue:
            return
        case .startTeardown:
            queue.async { [self] in
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
        let completions: [@Sendable () -> Void] = stateLock.withLock {
            teardownComplete = true
            let pending = teardownCompletions
            teardownCompletions.removeAll()
            return pending
        }
        for completion in completions {
            completion()
        }
    }

    // MARK: - Connect pipeline

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
            // Definitive errors won't recover on this path; fail now instead of
            // stalling to the connect timeout. A DNS hiccup stays pending so
            // NWConnection can retry, bounded by `connectionTimeout`.
            if isDefinitiveConnectError(error) {
                logger.debug("[TCP] connect unreachable: \(error)")
                finishConnectFailure(mapNWError(error, op: .connect))
            }
        default:
            break  // .setup, .preparing, .cancelled
        }
    }

    /// Promotes to `.ready`, sends `initialData`, and fires the connect
    /// completion exactly once. Must run on `queue`.
    private func handleConnectReady() {
        // A racing .cancelled wins; teardown fires the completion.
        guard transitionFromSetup(to: .ready) else { return }

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
    /// If a racing `forceCancel()` already latched `.cancelled`, the completion is
    /// left intact for the teardown path to fire with "Cancelled"; consuming it
    /// here without reporting would drop the caller's completion entirely.
    private func finishConnectFailure(_ error: Error) {
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
            if case .ready = _state { _state = .failed(error); return true }
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
            if case .setup = _state {
                _state = new
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
