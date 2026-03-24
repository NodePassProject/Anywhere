//
//  NWTransport.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/24/26.
//

import Foundation
import Network
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "NWTransport")

// MARK: - RawTransport

/// Protocol abstracting the raw I/O layer used by TLS/Reality handshakes and proxy chaining.
///
/// Both ``NWTransport`` (real TCP) and ``TunneledTransport`` (tunneled TCP via proxy chain) conform.
protocol RawTransport: AnyObject {
    /// Whether the transport is connected and ready for I/O.
    var isTransportReady: Bool { get }

    /// Sends data through the transport.
    func send(data: Data, completion: @escaping (Error?) -> Void)

    /// Sends data through the transport without tracking completion.
    func send(data: Data)

    /// Receives up to `maximumLength` bytes from the transport.
    func receive(maximumLength: Int, completion: @escaping (Data?, Bool, Error?) -> Void)

    /// Closes the transport and cancels all pending operations.
    func forceCancel()
}

// MARK: - Error

/// Errors that can occur during socket/transport operations.
enum SocketError: Error, LocalizedError {
    case resolutionFailed(String)
    case socketCreationFailed(String)
    case connectionFailed(String)
    case notConnected
    case sendFailed(String)
    case receiveFailed(String)

    var errorDescription: String? {
        switch self {
        case .resolutionFailed(let msg): return "DNS resolution failed: \(msg)"
        case .socketCreationFailed(let msg): return "Socket creation failed: \(msg)"
        case .connectionFailed(let msg): return "Connection failed: \(msg)"
        case .notConnected: return "Not connected"
        case .sendFailed(let msg): return "Send failed: \(msg)"
        case .receiveFailed(let msg): return "Receive failed: \(msg)"
        }
    }
}

// MARK: - NWTransport

/// A TCP transport using `NWConnection` with asynchronous I/O.
///
/// `NWTransport` uses Apple's Network framework for TCP connections.
/// DNS resolution is performed via ``ProxyDNSCache`` to avoid tunnel routing loops,
/// and the resolved IP addresses are passed directly to `NWConnection`.
///
/// TCP options are configured to match Xray-core's `sockopt_darwin.go`:
/// - `TCP_NODELAY` enabled (disables Nagle's algorithm).
/// - TCP Fast Open enabled (sends initial data in SYN packet when possible).
/// - TCP keepalive enabled (detects dead connections after idle periods).
///
/// Safe to call from any thread — `NWConnection` serializes operations internally.
class NWTransport: RawTransport {

    /// The current connection state.
    enum State {
        case setup
        case ready
        case failed(Error)
        case cancelled
    }

    // MARK: Properties

    /// The current state of the transport.
    private(set) var state: State = .setup

    private var nwConnection: NWConnection?

    /// Tracks whether the remote has signalled EOF so the next `receive` returns immediately.
    private var receivedEOF = false

    /// Called when `NWConnection` detects a better network path is available
    /// (e.g. WiFi restored after cellular fallback). The owner can cancel and
    /// reconnect on the new path to reduce latency or improve throughput.
    var betterPathAvailableHandler: (() -> Void)?

    /// Connect timeout in seconds (matches Xray-core system_dialer.go `net.Dialer{Timeout: 16s}`).
    /// Prevents indefinite waits when SYN packets are silently dropped (e.g. by a firewall).
    private static let connectTimeout: Int = 16

    // MARK: - Connect

    /// Connects to a remote host asynchronously.
    ///
    /// DNS resolution runs via ``ProxyDNSCache`` on a global concurrent queue.
    /// Each resolved IP address is tried in order; the connection falls through
    /// to the next address on failure.
    ///
    /// When `initialData` is provided and TCP Fast Open is supported, the data
    /// is sent as part of the TCP SYN packet, saving one round trip.
    ///
    /// - Parameters:
    ///   - host: The remote hostname or IP address.
    ///   - port: The remote port number.
    ///   - queue: Accepted for API compatibility but unused internally.
    ///   - initialData: Optional data to send via TCP Fast Open (included in SYN packet).
    ///   - completion: Called with `nil` on success or an error on failure.
    func connect(host: String, port: UInt16, queue: DispatchQueue, initialData: Data? = nil, completion: @escaping (Error?) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let ips = ProxyDNSCache.shared.resolveAll(host)
            guard !ips.isEmpty else {
                let err = SocketError.resolutionFailed("DNS resolution failed for \(host)")
                state = .failed(err)
                completion(err)
                return
            }
            tryConnect(ips: ips, port: port, index: 0, initialData: initialData, completion: completion)
        }
    }

    /// Attempts to connect to each resolved IP address in order.
    ///
    /// Falls through to the next address on failure. Each attempt is guarded
    /// by ``connectTimeout`` seconds via `NWProtocolTCP.Options.connectionTimeout`.
    private func tryConnect(ips: [String], port: UInt16, index: Int, initialData: Data?, completion: @escaping (Error?) -> Void) {
        guard index < ips.count else {
            let err = SocketError.connectionFailed("All addresses failed")
            state = .failed(err)
            completion(err)
            return
        }

        let ip = ips[index]

        // TCP options (reference: Xray-core sockopt_darwin.go)
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        tcpOptions.connectionTimeout = Self.connectTimeout
        tcpOptions.enableFastOpen = true
        tcpOptions.enableKeepalive = true
        tcpOptions.keepaliveIdle = 30
        tcpOptions.keepaliveInterval = 10
        tcpOptions.keepaliveCount = 3

        let params = NWParameters(tls: nil, tcp: tcpOptions)

        let nwHost = NWEndpoint.Host(ip)
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            tryConnect(ips: ips, port: port, index: index + 1, initialData: initialData, completion: completion)
            return
        }

        let connection = NWConnection(host: nwHost, port: nwPort, using: params)
        var completed = false

        connection.stateUpdateHandler = { [weak self] newState in
            guard let self, !completed else { return }

            switch newState {
            case .ready:
                completed = true
                connection.stateUpdateHandler = nil
                self.nwConnection = connection
                self.state = .ready
                connection.betterPathUpdateHandler = { [weak self] isBetter in
                    if isBetter { self?.betterPathAvailableHandler?() }
                }
                completion(nil)

            case .failed:
                completed = true
                connection.stateUpdateHandler = nil
                connection.cancel()
                self.tryConnect(ips: ips, port: port, index: index + 1, initialData: initialData, completion: completion)

            case .cancelled:
                guard !completed else { return }
                completed = true
                self.tryConnect(ips: ips, port: port, index: index + 1, initialData: initialData, completion: completion)

            default:
                break
            }
        }

        connection.start(queue: .global())

        // TCP Fast Open: send initial data before the handshake completes.
        // NWConnection includes this data in the SYN packet when TFO is available.
        if let initialData {
            connection.send(content: initialData, completion: .contentProcessed({ _ in }))
        }
    }

    // MARK: - RawTransport Conformance

    var isTransportReady: Bool {
        if case .ready = state { return true }
        return false
    }

    // MARK: - Send

    /// Sends data through the connection.
    ///
    /// `NWConnection` handles internal buffering and flow control.
    ///
    /// - Parameters:
    ///   - data: The data to send.
    ///   - completion: Called with `nil` on success or an error on failure.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        guard let connection = nwConnection else {
            completion(SocketError.notConnected)
            return
        }
        connection.send(content: data, completion: .contentProcessed({ error in
            if let error {
                completion(SocketError.sendFailed(error.localizedDescription))
            } else {
                completion(nil)
            }
        }))
    }

    /// Sends data through the connection without tracking completion.
    ///
    /// - Parameter data: The data to send.
    func send(data: Data) {
        guard let connection = nwConnection else { return }
        connection.send(content: data, completion: .contentProcessed({ _ in }))
    }

    // MARK: - Receive

    /// Receives up to `maximumLength` bytes from the connection.
    ///
    /// The completion handler is called with:
    /// - `(data, false, nil)` — data received successfully.
    /// - `(nil, true, nil)` — EOF (remote closed).
    /// - `(nil, true, error)` — a receive error occurred.
    ///
    /// - Parameters:
    ///   - maximumLength: The maximum number of bytes to receive.
    ///   - completion: Called with the received data, completion flag, and optional error.
    func receive(maximumLength: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        guard let connection = nwConnection else {
            completion(nil, true, SocketError.notConnected)
            return
        }
        if receivedEOF {
            completion(nil, true, nil)
            return
        }
        connection.receive(minimumIncompleteLength: 1, maximumLength: maximumLength) { [weak self] data, _, isComplete, error in
            if let error {
                completion(nil, true, SocketError.receiveFailed(error.localizedDescription))
            } else if let data, !data.isEmpty {
                if isComplete { self?.receivedEOF = true }
                completion(data, false, nil)
            } else if isComplete {
                completion(nil, true, nil)
            } else {
                completion(nil, true, nil)
            }
        }
    }

    // MARK: - Cancel

    /// Closes the connection and cancels all pending operations.
    ///
    /// Safe to call from any thread.
    func forceCancel() {
        state = .cancelled
        nwConnection?.forceCancel()
        nwConnection = nil
    }
}
