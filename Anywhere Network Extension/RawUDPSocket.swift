//
//  RawUDPSocket.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/14/26.
//

import Foundation
import Darwin

private let logger = AnywhereLogger(category: "RawUDPSocket")

// MARK: - RawUDPSocket

/// UDP transport over a connected non-blocking POSIX `SOCK_DGRAM`.
///
/// DNS goes through ``ProxyDNSCache``. Reads are driven by a
/// `DispatchSourceRead` that loops `recv(2)` until `EAGAIN`, so one
/// wake-up drains a burst of packets. Sends are non-blocking `send(2)`;
/// `EAGAIN` drops the datagram (the upper layer retransmits).
///
/// All I/O runs on the internal `ioQueue`. The connect completion and
/// receive handler fire on the caller's queue when supplied; `send`,
/// `startReceiving`, and `cancel` are safe to call from any thread.
final class RawUDPSocket {

    enum State {
        case setup
        case ready
        case cancelled
    }

    // MARK: Constants

    /// 65 KiB covers the largest possible UDP payload. Reused across
    /// `recv(2)` calls so the loop only allocates for the per-packet
    /// `Data` copy handed to the handler.
    private static let receiveBufferSize = 65536

    /// Kernel socket buffer size. macOS defaults (~9 KB) cap
    /// high-bandwidth relays at that per-RTT.
    private static let kernelSocketBufferSize: Int32 = 4 * 1024 * 1024

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

    /// Serial queue for all socket I/O and state transitions.
    private let ioQueue = DispatchQueue(label: "com.argsment.Anywhere.RawUDPSocket",
                                        qos: .userInitiated)

    // MARK: Socket

    /// Socket file descriptor. `-1` when no socket is open.
    private var socketFD: Int32 = -1

    /// Fires on socket readability; handler drains to `EAGAIN`.
    private var readSource: DispatchSourceRead?

    // MARK: Receive

    private var receiveHandler: ((Data) -> Void)?
    private var receiveErrorHandler: ((Error) -> Void)?
    private var receiveHandlerQueue: DispatchQueue?
    private var rxBuffer = [UInt8](repeating: 0, count: RawUDPSocket.receiveBufferSize)

    // MARK: - Lifecycle

    init() {}

    // MARK: - Connect

    /// Resolves `host` via ``ProxyDNSCache`` and creates a connected
    /// non-blocking UDP socket to `port`.
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

            // Try each resolved IP in order, matching RawTCPSocket's behavior on
            // mixed v4/v6 records.
            var lastError: SocketError?
            for ip in ips {
                switch self.attemptConnect(ip: ip, port: port) {
                case .success:
                    self.stateLock.withLock { self._state = .ready }
                    self.armReadSource()
                    completionQueue.async { completion(nil) }
                    return
                case .failure(let error):
                    lastError = error
                }
            }

            let err = lastError ?? SocketError.connectionFailed("All addresses failed")
            completionQueue.async { completion(err) }
        }
    }

    /// Builds a sockaddr from `ip`, creates the socket, applies options, and
    /// calls `connect(2)`. Must run on `ioQueue`.
    private func attemptConnect(ip: String, port: UInt16) -> Result<Void, SocketError> {
        guard let endpoint = IPEndpoint(ip: ip, port: port) else {
            return .failure(.connectionFailed("inet_pton failed for \(ip)"))
        }

        let fd = Darwin.socket(endpoint.family, SOCK_DGRAM, 0)
        guard fd >= 0 else {
            return .failure(.socketCreationFailed("socket() errno=\(errno)"))
        }

        guard SocketHelpers.makeNonBlocking(fd) else {
            let e = errno
            _ = Darwin.close(fd)
            return .failure(.socketCreationFailed("fcntl(O_NONBLOCK) errno=\(e)"))
        }

        applyUDPSocketOptions(fd: fd)

        let rc = endpoint.withSockAddr { sa, len in
            Darwin.connect(fd, sa, len)
        }
        if rc != 0 {
            let err = errno
            _ = Darwin.close(fd)
            return .failure(.connectionFailed("connect() errno=\(err)"))
        }

        socketFD = fd
        return .success(())
    }

    /// Applies Darwin-specific UDP socket options.
    private func applyUDPSocketOptions(fd: Int32) {
        SocketHelpers.setInt(fd, level: SOL_SOCKET, name: SO_NOSIGPIPE, value: 1)
        SocketHelpers.setInt(fd, level: SOL_SOCKET, name: SO_SNDBUF, value: Self.kernelSocketBufferSize)
        SocketHelpers.setInt(fd, level: SOL_SOCKET, name: SO_RCVBUF, value: Self.kernelSocketBufferSize)
    }

    // MARK: - Receive

    /// Installs a receive handler. Fires on `handlerQueue` (or `ioQueue` if
    /// nil) once per datagram. Calling twice replaces the previous handler.
    ///
    /// `errorHandler`, when supplied, fires once on the same queue when the
    /// recv loop encounters a non-transient `errno` (anything other than
    /// EAGAIN/EWOULDBLOCK/EINTR). After the error handler fires, the read
    /// source stops, so callers should treat this as a terminal event and
    /// close the flow — otherwise the socket sits dead until the next send
    /// surfaces ``SocketError/notConnected``.
    func startReceiving(queue handlerQueue: DispatchQueue? = nil,
                        handler: @escaping (Data) -> Void,
                        errorHandler: ((Error) -> Void)? = nil) {
        ioQueue.async { [weak self] in
            guard let self else { return }
            self.receiveHandler = handler
            self.receiveErrorHandler = errorHandler
            self.receiveHandlerQueue = handlerQueue
        }
    }

    /// Arms the read source. Runs on `ioQueue` via the connect path.
    private func armReadSource() {
        guard socketFD >= 0, readSource == nil else { return }
        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: ioQueue)
        source.setEventHandler { [weak self] in
            self?.drainReads()
        }
        readSource = source
        source.resume()
    }

    /// Loops `recv(2)` until `EAGAIN` so one wake-up drains a burst of
    /// packets. Must run on `ioQueue`.
    private func drainReads() {
        guard socketFD >= 0 else { return }
        while true {
            let n = rxBuffer.withUnsafeMutableBufferPointer { buf -> Int in
                Darwin.recv(socketFD, buf.baseAddress, buf.count, 0)
            }
            if n < 0 {
                let err = errno
                if err == EAGAIN || err == EWOULDBLOCK || err == EINTR { return }
                // Surface terminal recv failures so the flow can close; clear
                // the read source so the dispatch event handler stops firing
                // on the failed fd.
                let errorHandler = self.receiveErrorHandler
                let handlerQueue = self.receiveHandlerQueue
                self.receiveErrorHandler = nil
                self.readSource?.cancel()
                self.readSource = nil
                if let errorHandler {
                    let socketError = SocketError.posixError(.receive, errno: err)
                    if let handlerQueue {
                        handlerQueue.async { errorHandler(socketError) }
                    } else {
                        errorHandler(socketError)
                    }
                }
                return
            }
            if n == 0 { return }
            guard let handler = receiveHandler else {
                // No handler installed yet; drop but keep draining so the
                // dispatch source stops firing.
                continue
            }
            let data = rxBuffer.withUnsafeBufferPointer { buf -> Data in
                Data(bytes: buf.baseAddress!, count: n)
            }
            if let hq = receiveHandlerQueue {
                hq.async { handler(data) }
            } else {
                handler(data)
            }
        }
    }

    // MARK: - Send

    /// Fire-and-forget datagram send.
    func send(data: Data) {
        ioQueue.async { [weak self] in
            _ = self?.performSend(data)
        }
    }

    /// Datagram send with completion on the internal `ioQueue`.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        ioQueue.async { [weak self] in
            let err = self?.performSend(data)
            completion(err)
        }
    }

    /// Issues a single `send(2)`. Must run on `ioQueue`.
    private func performSend(_ data: Data) -> Error? {
        guard socketFD >= 0 else { return SocketError.notConnected }
        if case .cancelled = state {
            return SocketError.notConnected
        }
        let sent = data.withUnsafeBytes { buf -> Int in
            guard let base = buf.baseAddress else { return -1 }
            return Darwin.send(socketFD, base, data.count, 0)
        }
        if sent < 0 {
            let err = errno
            if err == EAGAIN || err == EWOULDBLOCK {
                // Kernel TX buffer full; drop and let the upper layer retransmit.
                return nil
            }
            return SocketError.posixError(.send, errno: err)
        }
        return nil
    }

    // MARK: - Cancel

    /// Latches cancelled state and tears down the socket on `ioQueue`.
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
            if let source = self.readSource {
                source.cancel()
                self.readSource = nil
            }
            if self.socketFD >= 0 {
                _ = Darwin.close(self.socketFD)
                self.socketFD = -1
            }
            self.receiveHandler = nil
            self.receiveErrorHandler = nil
            self.receiveHandlerQueue = nil
        }
    }
}
