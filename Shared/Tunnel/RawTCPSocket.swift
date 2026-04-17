//
//  RawTCPSocket.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/24/26.
//

import Foundation
import Network

private let logger = AnywhereLogger(category: "RawTCPSocket")

// MARK: - RawTCPSocket

/// A TCP transport built on Apple's `Network` framework (``NWConnection``).
/// All callers reach this through the ``RawTransport`` protocol.
///
/// ### DNS
/// DNS resolution is performed via ``ProxyDNSCache`` to avoid tunnel routing
/// loops. The resolved IP literals are wrapped in `NWEndpoint.Host.ipv4` /
/// `.ipv6`, so the `Network` framework never issues its own DNS lookup at
/// connect time.
///
/// ### TCP Tuning (``NWProtocolTCP/Options``)
/// - `noDelay`            — disables Nagle's algorithm.
/// - `enableKeepalive`    — enables TCP keepalive.
/// - `keepaliveIdle` (30) — idle seconds before the first probe.
/// - `keepaliveInterval`(10) — interval between probes.
/// - `keepaliveCount` (3) — probes before the kernel drops the connection.
/// - `connectionTimeout`  — per-attempt connect timeout.
///
/// Matches the tuning of the previous `sockopt_darwin.go`-style POSIX
/// implementation. `SO_NOSIGPIPE` has no analogue because `NWConnection` does
/// not use `write(2)`; broken-pipe errors surface through the send completion
/// instead.
///
/// ### Threading
/// All I/O and state-machine transitions are serialized on an internal serial
/// dispatch queue (`ioQueue`). `NWConnection` state, send, and receive
/// callbacks are bound to that queue, so handlers run serially against each
/// other and against async operations dispatched from outside. The `state`
/// property is additionally protected by an unfair lock so that
/// `isTransportReady` and `forceCancel()` can be called safely from any
/// thread without deadlocking on `ioQueue`. `forceCancel()` synchronously
/// latches the cancelled state and then dispatches teardown to `ioQueue`;
/// any blocks already pending on the queue re-check state and bail out.
///
/// ### Loopback
/// Inside a `NEPacketTunnelProvider`, the provider's own outbound traffic is
/// kernel-excluded from the tunnel, so `NWConnection` does not loop back into
/// the tunnel it belongs to. Loopback targets (127.0.0.0/8, ::1) are always
/// routed via `lo0`. No explicit interface binding — we rely on the OS
/// routing table plus the kernel-level NE bypass.
///
/// ### `initialData`
/// When provided, `initialData` is sent as the very first outgoing payload as
/// soon as the connection transitions to `.ready`. No kernel TFO — we trade
/// one RTT in the best case for a simpler connect flow. Callers (TLS
/// ClientHello, Reality ClientHello) stay correct because the first `receive`
/// still waits on the server's response.
class RawTCPSocket: RawTransport {

    /// The current connection state.
    enum State {
        case setup
        case ready
        case failed(Error)
        case cancelled
    }

    // MARK: Constants

    /// Per-attempt connect timeout (seconds). Matches Xray-core `system_dialer.go`.
    private static let connectTimeout: Int = 16

    /// Maximum bytes returned by a single `receive` call.
    private static let receiveChunk: Int = 65536

    // MARK: State

    private let stateLock = UnfairLock()
    private var _state: State = .setup

    /// The current state of the transport. Thread-safe.
    var state: State {
        stateLock.withLock { _state }
    }

    // MARK: Concurrency

    /// Serial queue for all I/O and state transitions. All `NWConnection`
    /// callbacks are bound to this queue, so their handlers are naturally
    /// serialized against each other and against async operations dispatched
    /// from outside.
    private let ioQueue = DispatchQueue(label: "com.argsment.Anywhere.RawTCPSocket",
                                        qos: .userInitiated)

    // MARK: Connection

    /// The active `NWConnection`. Mutated only on `ioQueue`.
    private var connection: NWConnection?

    // MARK: Connect pipeline

    /// Pending connect completion, cleared once invoked.
    private var connectCompletion: ((Error?) -> Void)?

    /// Addresses still to try (consumed in order on fallthrough).
    private var remainingIPs: [String] = []
    private var remainingPort: UInt16 = 0
    private var pendingInitialData: Data?

    // MARK: Receive pipeline

    /// Outstanding receive completion. NWConnection serves at most one
    /// `receive` at a time; callers must issue receives serially.
    private var pendingReceive: ((Data?, Bool, Error?) -> Void)?

    /// Latched when the remote half-closes; subsequent `receive` calls return
    /// EOF immediately without touching the connection.
    private var receivedEOF = false

    // MARK: - Lifecycle

    init() {}

    deinit {
        // By the time deinit runs, all blocks on `ioQueue` have drained (they
        // retain self), so no further mutation is possible. Defensive cleanup
        // only for code paths that skipped `forceCancel()`.
        if let conn = connection {
            conn.stateUpdateHandler = nil
            conn.cancel()
            connection = nil
        }
    }

    // MARK: - RawTransport

    var isTransportReady: Bool {
        if case .ready = state { return true }
        return false
    }

    /// Connects to a remote host asynchronously.
    ///
    /// DNS resolution runs synchronously on the internal `ioQueue` via
    /// ``ProxyDNSCache``. Each resolved IP address is tried in order; on
    /// failure we fall through to the next address.
    ///
    /// When `initialData` is non-empty, it is sent as soon as the connection
    /// becomes ready.
    ///
    /// - Parameters:
    ///   - host: The remote hostname or IP address.
    ///   - port: The remote port number.
    ///   - initialData: Optional data to send immediately after connect.
    ///   - completion: Called with `nil` on success or an error on failure. Fires on the internal `ioQueue`.
    func connect(host: String, port: UInt16,
                 initialData: Data? = nil,
                 completion: @escaping (Error?) -> Void) {
        ioQueue.async { [self] in
            // If forceCancel() was called before we ran, bail immediately. No
            // teardown path involves `completion` here because we never
            // stored it.
            if case .cancelled = state {
                completion(SocketError.connectionFailed("Cancelled"))
                return
            }

            let ips = ProxyDNSCache.shared.resolveAll(host)
            guard !ips.isEmpty else {
                let err = SocketError.resolutionFailed("DNS resolution failed for \(host)")
                // Move to .failed if still in setup; keep .cancelled if already
                // latched.
                stateLock.withLock {
                    if case .setup = _state { _state = .failed(err) }
                }
                completion(err)
                return
            }

            remainingIPs = ips
            remainingPort = port
            pendingInitialData = initialData
            // Stash the completion before any further state transitions so
            // that forceCancel()'s teardown block can fire it if we get
            // pre-empted.
            connectCompletion = completion
            tryConnectNext()
        }
    }

    /// Sends data through the connection.
    ///
    /// The send is handed to `NWConnection`, which serializes it after any
    /// prior sends and invokes the completion on `ioQueue`.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        ioQueue.async { [self] in
            switch state {
            case .ready:
                guard let conn = connection else {
                    completion(SocketError.notConnected)
                    return
                }
                conn.send(content: data, completion: .contentProcessed { error in
                    if let error {
                        completion(SocketError.sendFailed(error.localizedDescription))
                    } else {
                        completion(nil)
                    }
                })
            case .failed(let err):
                completion(err)
            default:
                completion(SocketError.notConnected)
            }
        }
    }

    /// Fire-and-forget send.
    func send(data: Data) {
        ioQueue.async { [self] in
            guard case .ready = state, let conn = connection else { return }
            conn.send(content: data, completion: .contentProcessed { _ in })
        }
    }

    /// Receives up to ``receiveChunk`` bytes from the connection.
    ///
    /// Completion semantics match the prior implementation:
    /// - `(data, false, nil)` — data received successfully.
    /// - `(nil, true, nil)` — EOF (remote closed).
    /// - `(nil, true, error)` — a receive error occurred.
    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        ioQueue.async { [self] in
            if receivedEOF {
                completion(nil, true, nil)
                return
            }
            switch state {
            case .ready:
                break
            case .failed(let err):
                completion(nil, true, err)
                return
            case .cancelled, .setup:
                completion(nil, true, SocketError.notConnected)
                return
            }
            guard let conn = connection else {
                completion(nil, true, SocketError.notConnected)
                return
            }
            // Contract: callers issue receive serially.
            if pendingReceive != nil {
                // Unexpected — prior callback hasn't fired. Don't clobber it;
                // surface an error on this one.
                completion(nil, true, SocketError.receiveFailed("Concurrent receive"))
                return
            }
            pendingReceive = completion
            conn.receive(minimumIncompleteLength: 1,
                         maximumLength: Self.receiveChunk) { [weak self] content, _, isComplete, error in
                guard let self else {
                    completion(nil, true, SocketError.notConnected)
                    return
                }
                // forceCancel() may have already fired the pending completion
                // with `.notConnected`; drop this result in that case.
                guard let c = self.pendingReceive else { return }
                self.pendingReceive = nil
                if let error {
                    c(nil, true, SocketError.receiveFailed(error.localizedDescription))
                    return
                }
                if let data = content, !data.isEmpty {
                    c(data, false, nil)
                    return
                }
                // No data: connection is closed for receive.
                self.receivedEOF = true
                c(nil, true, nil)
                _ = isComplete
            }
        }
    }

    /// Closes the connection and cancels all pending operations.
    ///
    /// Safe to call from any thread. The cancelled state is set synchronously
    /// under the state lock so subsequent `isTransportReady` reads and queued
    /// blocks observe it immediately. Actual connection teardown and
    /// completion fan-out happen asynchronously on `ioQueue` to keep the data
    /// structures free of races.
    func forceCancel() {
        // Synchronously latch .cancelled. Sticky: `transitionFromSetup` will
        // refuse to move off of it.
        let alreadyCancelled: Bool = stateLock.withLock {
            if case .cancelled = _state { return true }
            _state = .cancelled
            return false
        }
        if alreadyCancelled { return }

        ioQueue.async { [self] in
            if let c = connectCompletion {
                connectCompletion = nil
                c(SocketError.connectionFailed("Cancelled"))
            }
            if let c = pendingReceive {
                pendingReceive = nil
                c(nil, true, SocketError.notConnected)
            }
            pendingInitialData = nil
            remainingIPs.removeAll()
            tearDownConnection()
        }
    }

    // MARK: - Connect pipeline

    /// Attempts the next resolved IP. Must run on `ioQueue`.
    private func tryConnectNext() {
        if case .cancelled = state {
            // Teardown handles the pending connect completion.
            return
        }

        guard !remainingIPs.isEmpty else {
            finishConnectFailure(SocketError.connectionFailed("All addresses failed"))
            return
        }

        let ip = remainingIPs.removeFirst()
        let port = remainingPort

        guard let host = Self.hostFromIP(ip), let nwPort = NWEndpoint.Port(rawValue: port) else {
            logger.debug("[TCP] invalid IP literal for \(ip):\(port)")
            tryConnectNext()
            return
        }

        let endpoint = NWEndpoint.hostPort(host: host, port: nwPort)
        let conn = NWConnection(to: endpoint, using: Self.buildParameters())
        connection = conn

        conn.stateUpdateHandler = { [weak self] newState in
            self?.handleConnectionStateUpdate(newState, for: conn)
        }
        conn.start(queue: ioQueue)
    }

    /// Parses an IPv4/IPv6 literal into an `NWEndpoint.Host`.
    private static func hostFromIP(_ ip: String) -> NWEndpoint.Host? {
        if ip.contains(":") {
            guard let addr = IPv6Address(ip) else { return nil }
            return .ipv6(addr)
        } else {
            guard let addr = IPv4Address(ip) else { return nil }
            return .ipv4(addr)
        }
    }

    /// Builds `NWParameters` with Darwin-equivalent TCP tuning.
    private static func buildParameters() -> NWParameters {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.enableKeepalive = true
        tcp.keepaliveIdle = 30
        tcp.keepaliveInterval = 10
        tcp.keepaliveCount = 3
        tcp.connectionTimeout = Self.connectTimeout
        let params = NWParameters(tls: nil, tcp: tcp)
        params.includePeerToPeer = false
        return params
    }

    /// Central handler for `NWConnection.stateUpdateHandler` events.
    private func handleConnectionStateUpdate(_ newState: NWConnection.State,
                                             for conn: NWConnection) {
        // Stale event from a connection that tearDown already replaced.
        guard conn === connection else { return }

        switch newState {
        case .ready:
            handleConnectReady()
        case .failed(let error):
            logger.debug("[TCP] connection failed: \(error.localizedDescription)")
            tearDownConnection()
            tryConnectNext()
        case .waiting(let error):
            // Path isn't satisfied — fall through to the next IP rather than
            // sitting idle. If all IPs end up waiting, we report failure.
            logger.debug("[TCP] connection waiting: \(error.localizedDescription)")
            tearDownConnection()
            tryConnectNext()
        case .cancelled, .preparing, .setup:
            break
        @unknown default:
            break
        }
    }

    /// Promotes to `.ready`, fires the connect completion, and enqueues
    /// `initialData` if present. Must run on `ioQueue`.
    private func handleConnectReady() {
        // Refuse to overwrite a concurrent .cancelled. Teardown will fire the
        // completion in that case.
        guard transitionFromSetup(to: .ready) else { return }

        let initial = pendingInitialData
        pendingInitialData = nil
        remainingIPs.removeAll()

        let c = connectCompletion
        connectCompletion = nil
        c?(nil)

        if let initial, !initial.isEmpty, let conn = connection {
            conn.send(content: initial, completion: .contentProcessed { _ in })
        }
    }

    /// No more addresses to try. Transitions to `.failed` and fires the completion.
    private func finishConnectFailure(_ error: Error) {
        tearDownConnection()
        pendingInitialData = nil

        let shouldReport = transitionFromSetup(to: .failed(error))
        let c = connectCompletion
        connectCompletion = nil
        if shouldReport {
            c?(error)
        }
    }

    // MARK: - State transitions

    /// Transitions only if the current state is `.setup`. Returns true if the
    /// transition occurred. Used to guarantee that `.cancelled` is sticky:
    /// once `forceCancel()` latches the cancelled state, no later code path
    /// can move us to `.ready` or `.failed`.
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

    /// Cancels the current `NWConnection` and clears the pointer. Must run
    /// on `ioQueue`.
    private func tearDownConnection() {
        guard let conn = connection else { return }
        connection = nil
        conn.stateUpdateHandler = nil
        conn.cancel()
    }
}
