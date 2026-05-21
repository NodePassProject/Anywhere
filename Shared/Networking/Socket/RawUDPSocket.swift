//
//  RawUDPSocket.swift
//  Anywhere
//
//  Created by NodePassProject on 4/14/26.
//

import Foundation
import Darwin

private let logger = AnywhereLogger(category: "RawUDPSocket")

// MARK: - RawUDPSocket

/// UDP transport over a connected non-blocking POSIX `SOCK_DGRAM`.
///
/// DNS goes through ``DNSResolver``. Reads are driven by a
/// `DispatchSourceRead` that loops `recv(2)` until `EAGAIN`, so one
/// wake-up drains a burst of packets. Sends are non-blocking `send(2)`;
/// `EAGAIN` drops the datagram (the upper layer retransmits).
///
/// All I/O runs on the internal `ioQueue`. The connect completion and
/// receive handler fire on the caller's queue when supplied; `send`,
/// `startReceiving`, and `cancel` are safe to call from any thread.
nonisolated final class RawUDPSocket {

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

    /// Datagrams that arrived after the socket was connected but before
    /// the upper layer called `startReceiving`. Mostly empty for
    /// UDP-connected sockets (server only sends after we send first), but
    /// real when this socket is reused under chained QUIC: the QUIC client
    /// initial races with the wrapper's lazy `startReceiving` install, so
    /// without a tiny pre-handler buffer the server's response Initial can
    /// land on `drainReads` while `receiveHandler == nil` and get dropped.
    /// Bounded so a malformed peer that fires a burst before we arm the
    /// handler can't OOM us; matches `DirectUDPProxyConnection`'s cap.
    private var pendingDatagrams: [Data] = []
    private static let maxPendingDatagrams = 1024
    /// One-shot warn latch — when the pre-handler buffer fills before the
    /// upper layer arms `startReceiving`, we lose the head-of-queue. Stays
    /// silent in the common case (handler arms in tens of µs); only a
    /// chained-dial that stalls before arming will trip this.
    private var didWarnPendingOverflow = false

    // MARK: - Lifecycle

    init() {}

#if DEBUG
    /// Leak tripwire: a connected socket must be torn down via `cancel()`
    /// before the wrapper is freed. A live FD/read source here means it was
    /// dropped without cancelling — a leaked FD plus its 4 MB kernel buffers.
    /// (A never-connected socket has fd == -1 and trips nothing.) DEBUG-only.
    deinit {
        assert(socketFD < 0 && readSource == nil,
               "RawUDPSocket leaked: freed without cancel() (fd=\(socketFD))")
    }
#endif

    // MARK: - Connect

    /// Resolves `host` via ``DNSResolver`` and creates a connected
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

            let ips = DNSResolver.shared.resolveAll(host)
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

    /// Applies Darwin-specific UDP socket options.
    private func applyUDPSocketOptions(fd: Int32) {
        SocketHelpers.setInt(fd, level: SOL_SOCKET, name: SO_NOSIGPIPE, value: 1)
        SocketHelpers.setHighThroughputBuffers(fd)
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
    ///
    /// Drains any datagrams that arrived between `connect` and this call
    /// so they reach the new handler instead of being silently dropped.
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
                // Handler not yet installed (lazy `startReceiving` from
                // the wrapper). Buffer the datagram so it reaches the
                // handler when it eventually arms; cap so a burst before
                // install can't grow unbounded.
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
        guard latchCancelled() else { return }
        // Strong `self`, not `[weak self]`: a socket cancelled as it deallocates
        // must still tear down, or the FD + its 4 MB buffers + read source leak.
        ioQueue.async {
            self.performTeardownOnIOQueue()
        }
    }

    /// Synchronous variant of ``cancel``. Closes the socket FD before
    /// returning, so callers can rely on the FD being freed — used by the
    /// FD-pressure relief path so an evicted flow's FD is actually back in
    /// the table before the caller retries `socket(2)`.
    ///
    /// MUST NOT be called from this socket's `ioQueue` (would deadlock on
    /// the `ioQueue.sync` below). The relief path is invoked from other
    /// sockets' I/O queues and from `LWIPStack.lwipQueue`, never from this
    /// socket's own `ioQueue`.
    func cancelSync() {
        guard latchCancelled() else { return }
        ioQueue.sync { [weak self] in
            self?.performTeardownOnIOQueue()
        }
    }

    /// Atomically transitions the socket to `.cancelled`. Returns `true` if
    /// the caller was the one that transitioned it (and therefore owns the
    /// teardown), `false` if it was already cancelled.
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
