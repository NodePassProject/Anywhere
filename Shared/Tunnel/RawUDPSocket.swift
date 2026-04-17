//
//  RawUDPSocket.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/14/26.
//

import Foundation
import Network

private let logger = AnywhereLogger(category: "RawUDPSocket")

// MARK: - RawUDPSocket

/// UDP transport built on Apple's `Network` framework.
///
/// DNS goes through ``ProxyDNSCache`` so resolution bypasses the VPN tunnel.
/// Each resolved IP is tried in order and wrapped in an `NWEndpoint.Host`
/// literal, so `Network` never issues its own DNS lookup. Reads are driven by
/// a self-re-arming `receiveMessage` chain — one datagram per callback — and
/// sends are non-blocking; if `NWConnection`'s internal queue is full the
/// error surfaces through the send completion.
///
/// All I/O runs on the internal `ioQueue`. The connect completion fires on
/// the caller-supplied queue; the receive handler fires on its own queue when
/// supplied (otherwise on `ioQueue`). `send`, `startReceiving`, and `cancel`
/// are safe to call from any thread.
///
/// ### Known limitation vs. BSD sockets
/// `NWConnection` does not expose `SO_SNDBUF` / `SO_RCVBUF`, so the kernel
/// socket buffer defaults apply. The previous POSIX implementation tuned
/// both to 4 MiB; there is no direct equivalent in the `Network` framework.
final class RawUDPSocket {

    enum State {
        case setup
        case ready
        case cancelled
    }

    // MARK: State

    private let stateLock = UnfairLock()
    private var _state: State = .setup

    /// The current state. Thread-safe.
    private var state: State {
        stateLock.withLock { _state }
    }

    /// Whether the socket is connected and ready for I/O. Thread-safe.
    var isReady: Bool {
        if case .ready = state { return true }
        return false
    }

    // MARK: Concurrency

    /// Serial queue for all I/O and state transitions.
    private let ioQueue = DispatchQueue(label: "com.argsment.Anywhere.RawUDPSocket",
                                        qos: .userInitiated)

    // MARK: Connection

    /// The active `NWConnection`. Mutated only on `ioQueue`.
    private var connection: NWConnection?

    // MARK: Receive

    private var receiveHandler: ((Data) -> Void)?
    private var receiveHandlerQueue: DispatchQueue?

    // MARK: - Lifecycle

    init() {}

    deinit {
        // Defensive: if `cancel()` wasn't called, still tear down so we don't
        // leak an NWConnection.
        if let conn = connection {
            conn.stateUpdateHandler = nil
            conn.cancel()
            connection = nil
        }
    }

    // MARK: - Connect

    /// Resolves `host` via ``ProxyDNSCache`` and creates a connected UDP
    /// `NWConnection` to `port`.
    ///
    /// - Parameters:
    ///   - host: Remote hostname or literal IP.
    ///   - port: Remote UDP port.
    ///   - completionQueue: Queue on which `completion` is invoked.
    ///   - completion: `nil` on success, a ``SocketError`` on failure.
    func connect(host: String, port: UInt16,
                 completionQueue: DispatchQueue,
                 completion: @escaping (Error?) -> Void) {
        ioQueue.async { [weak self] in
            guard let self else {
                completionQueue.async { completion(SocketError.connectionFailed("Deallocated")) }
                return
            }
            if case .cancelled = self.state {
                completionQueue.async { completion(SocketError.connectionFailed("Cancelled")) }
                return
            }

            let ips = ProxyDNSCache.shared.resolveAll(host)
            guard !ips.isEmpty else {
                completionQueue.async {
                    completion(SocketError.resolutionFailed("DNS resolution failed for \(host)"))
                }
                return
            }

            // Try each resolved IP in order, matching the prior POSIX
            // implementation's behavior on mixed v4/v6 records.
            self.attemptConnect(ips: ips, index: 0, port: port,
                                completionQueue: completionQueue, completion: completion)
        }
    }

    /// Tries `ips[index]`, then recurses on failure. Must run on `ioQueue`.
    private func attemptConnect(ips: [String], index: Int, port: UInt16,
                                completionQueue: DispatchQueue,
                                completion: @escaping (Error?) -> Void) {
        if case .cancelled = state {
            completionQueue.async { completion(SocketError.connectionFailed("Cancelled")) }
            return
        }
        guard index < ips.count else {
            completionQueue.async { completion(SocketError.connectionFailed("All addresses failed")) }
            return
        }

        let ip = ips[index]
        guard let nwHost = Self.hostFromIP(ip), let nwPort = NWEndpoint.Port(rawValue: port) else {
            logger.debug("[UDP] invalid IP literal for \(ip):\(port)")
            attemptConnect(ips: ips, index: index + 1, port: port,
                           completionQueue: completionQueue, completion: completion)
            return
        }

        let endpoint = NWEndpoint.hostPort(host: nwHost, port: nwPort)
        let params = NWParameters(dtls: nil, udp: NWProtocolUDP.Options())
        params.includePeerToPeer = false
        let conn = NWConnection(to: endpoint, using: params)
        connection = conn

        conn.stateUpdateHandler = { [weak self] newState in
            guard let self else { return }
            // Stale event from a replaced connection.
            guard conn === self.connection else { return }

            switch newState {
            case .ready:
                let promoted: Bool = self.stateLock.withLock {
                    if case .setup = self._state {
                        self._state = .ready
                        return true
                    }
                    return false
                }
                // Handler no longer needed; receive errors will surface via
                // `receiveMessage` completions instead.
                conn.stateUpdateHandler = nil
                if !promoted {
                    // We were cancelled between scheduling and .ready.
                    return
                }
                self.armReceive(for: conn)
                completionQueue.async { completion(nil) }
            case .failed(let error), .waiting(let error):
                logger.debug("[UDP] connection failed for \(ip): \(error.localizedDescription)")
                conn.stateUpdateHandler = nil
                self.connection = nil
                conn.cancel()
                self.attemptConnect(ips: ips, index: index + 1, port: port,
                                    completionQueue: completionQueue, completion: completion)
            case .cancelled, .preparing, .setup:
                break
            @unknown default:
                break
            }
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

    // MARK: - Receive

    /// Installs a receive handler. Fires on `handlerQueue` (or `ioQueue` if
    /// nil) once per datagram. Calling twice replaces the previous handler.
    func startReceiving(queue handlerQueue: DispatchQueue? = nil,
                        handler: @escaping (Data) -> Void) {
        ioQueue.async { [weak self] in
            guard let self else { return }
            self.receiveHandler = handler
            self.receiveHandlerQueue = handlerQueue
        }
    }

    /// Arms a self-re-arming `receiveMessage` loop. Must run on `ioQueue`.
    private func armReceive(for conn: NWConnection) {
        conn.receiveMessage { [weak self] content, _, _, error in
            guard let self else { return }
            // Another connection took over, or we were cancelled.
            guard conn === self.connection, case .ready = self.state else { return }
            if let error {
                logger.error("[RawUDP] receive error: \(error.localizedDescription)")
                return
            }
            if let data = content, !data.isEmpty, let handler = self.receiveHandler {
                if let hq = self.receiveHandlerQueue {
                    hq.async { handler(data) }
                } else {
                    handler(data)
                }
            }
            self.armReceive(for: conn)
        }
    }

    // MARK: - Send

    /// Fire-and-forget datagram send.
    func send(data: Data) {
        ioQueue.async { [weak self] in
            guard let self, case .ready = self.state, let conn = self.connection else { return }
            conn.send(content: data, completion: .contentProcessed { _ in })
        }
    }

    /// Datagram send with completion on the internal `ioQueue`.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        ioQueue.async { [weak self] in
            guard let self else {
                completion(SocketError.notConnected)
                return
            }
            guard case .ready = self.state, let conn = self.connection else {
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
        }
    }

    // MARK: - Cancel

    /// Latches cancelled state and tears down the connection on `ioQueue`.
    /// Safe to call from any thread; idempotent.
    func cancel() {
        let alreadyCancelled: Bool = stateLock.withLock {
            if case .cancelled = _state { return true }
            _state = .cancelled
            return false
        }
        if alreadyCancelled { return }

        ioQueue.async { [weak self] in
            guard let self else { return }
            if let conn = self.connection {
                conn.stateUpdateHandler = nil
                conn.cancel()
                self.connection = nil
            }
            self.receiveHandler = nil
            self.receiveHandlerQueue = nil
        }
    }
}
