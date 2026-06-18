//
//  RawUDPSocket.swift
//  Anywhere
//
//  Created by NodePassProject on 4/14/26.
//

import Foundation
import Darwin

nonisolated private let logger = AnywhereLogger(category: "RawUDPSocket")

// MARK: - RawUDPSocket

/// UDP transport over a connected non-blocking POSIX `SOCK_DGRAM`.
///
/// All I/O runs on the internal `ioQueue`; `send`, `startReceiving`, and
/// `cancel` are safe from any thread. Send-side `EAGAIN` drops the datagram
/// (the upper layer retransmits).
nonisolated final class RawUDPSocket {

    enum State {
        case setup
        case ready
        case cancelled
    }

    // MARK: Constants

    /// Covers the largest possible UDP payload.
    private static let receiveBufferSize = 65536

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
    private let ioQueue = DispatchQueue(label: AWCore.Identifier.rawUDPSocketQueue,
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

    /// Datagrams received before `startReceiving` arms the handler — real under
    /// chained QUIC, where the server's response races the lazy handler install.
    /// Bounded so a pre-handler burst can't OOM us.
    private var pendingDatagrams: [Data] = []
    private static let maxPendingDatagrams = 1024
    /// One-shot latch for the pre-handler overflow warning.
    private var didWarnPendingOverflow = false

    // MARK: - Lifecycle

    /// Kernel `SO_SNDBUF`/`SO_RCVBUF` applied on connect; direct-bypass flows
    /// pass a smaller size so per-peer fan-out can't exhaust the memory budget.
    private let socketBufferSize: Int32

    init(socketBufferSize: Int32 = SocketHelpers.kernelSocketBufferSize) {
        self.socketBufferSize = socketBufferSize
    }

    // MARK: - Connect

    /// Resolves `host` and connects a non-blocking UDP socket; `completion`
    /// fires on `completionQueue`.
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

            let ips = DNSResolver.shared.resolveAll(host)
            guard !ips.isEmpty else {
                completionQueue.async {
                    completion(SocketError.resolutionFailed("DNS resolution failed for \(host)"))
                }
                return
            }

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

    /// Creates, configures, and connects the socket. Must run on `ioQueue`.
    private func attemptConnect(ip: String, port: UInt16) -> Result<Void, SocketError> {
        guard let endpoint = IPEndpoint(ip: ip, port: port) else {
            return .failure(.connectionFailed("inet_pton failed for \(ip)"))
        }

        let fd = SocketHelpers.makeSocket(family: endpoint.family, type: SOCK_DGRAM,
                                          reliefPriority: .bestEffort)
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

    private func applyUDPSocketOptions(fd: Int32) {
        SocketHelpers.setInt(fd, level: SOL_SOCKET, name: SO_NOSIGPIPE, value: 1)
        SocketHelpers.setDatagramBuffers(fd, size: socketBufferSize)
    }

    // MARK: - Receive

    /// Installs the receive handler (fires on `handlerQueue`, or `ioQueue` if
    /// nil) and drains datagrams buffered since connect. `errorHandler` fires
    /// once on a non-transient recv errno; the read source then stops, so
    /// callers should treat it as terminal and close the flow.
    func startReceiving(queue handlerQueue: DispatchQueue? = nil,
                        handler: @escaping (Data) -> Void,
                        errorHandler: ((Error) -> Void)? = nil) {
        ioQueue.async { [weak self] in
            guard let self else { return }
            self.receiveHandler = handler
            self.receiveErrorHandler = errorHandler
            self.receiveHandlerQueue = handlerQueue
            let drained = self.pendingDatagrams
            self.pendingDatagrams.removeAll()
            for data in drained {
                if let hq = handlerQueue {
                    hq.async { handler(data) }
                } else {
                    handler(data)
                }
            }
        }
    }

    /// Arms the read source. Must run on `ioQueue`.
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
                PerformanceMonitor.measure(.socketReceiveUDP) {
                    Darwin.recv(socketFD, buf.baseAddress, buf.count, 0)
                }
            }
            if n < 0 {
                let err = errno
                if err == EAGAIN || err == EWOULDBLOCK || err == EINTR { return }
                // Terminal recv failure: stop the read source and surface the error once.
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
            let data = rxBuffer.withUnsafeBufferPointer { buf -> Data in
                Data(bytes: buf.baseAddress!, count: n)
            }
            if let handler = receiveHandler {
                if let hq = receiveHandlerQueue {
                    hq.async { handler(data) }
                } else {
                    handler(data)
                }
            } else {
                // No handler yet; buffer (bounded) until startReceiving arms.
                if pendingDatagrams.count >= Self.maxPendingDatagrams {
                    pendingDatagrams.removeFirst()
                    PerformanceMonitor.event(.udpBufferOverflow)
                    if !didWarnPendingOverflow {
                        didWarnPendingOverflow = true
                        logger.warning("[UDP] Pre-handler buffer overflowed (cap \(Self.maxPendingDatagrams)); dropping oldest until startReceiving arms")
                    }
                }
                pendingDatagrams.append(data)
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
            return PerformanceMonitor.measure(.socketSendUDP) {
                Darwin.send(socketFD, base, data.count, 0)
            }
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
        guard latchCancelled() else { return }
        // Strong self: a socket cancelled as it deallocates must still tear
        // down, or the fd and its buffers leak.
        ioQueue.async {
            self.performTeardownOnIOQueue()
        }
    }

    /// Synchronous ``cancel`` — the fd is closed on return, as the FD-pressure
    /// relief path requires. MUST NOT be called from this socket's `ioQueue`
    /// (deadlocks on the `ioQueue.sync`).
    func cancelSync() {
        guard latchCancelled() else { return }
        ioQueue.sync { [weak self] in
            self?.performTeardownOnIOQueue()
        }
    }

    /// Latches `.cancelled`; returns `true` if the caller owns teardown.
    private func latchCancelled() -> Bool {
        stateLock.withLock {
            if case .cancelled = _state { return false }
            _state = .cancelled
            return true
        }
    }

    /// Tears down the read source and closes the socket FD. Must run on
    /// `ioQueue`.
    private func performTeardownOnIOQueue() {
        if let source = readSource {
            source.cancel()
            readSource = nil
        }
        if socketFD >= 0 {
            _ = Darwin.close(socketFD)
            socketFD = -1
        }
        receiveHandler = nil
        receiveErrorHandler = nil
        receiveHandlerQueue = nil
        pendingDatagrams.removeAll()
        didWarnPendingOverflow = false
    }
}
