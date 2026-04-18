//
//  RawTCPSocket.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/24/26.
//

import Foundation
import Darwin

private let logger = AnywhereLogger(category: "RawTCPSocket")

// MARK: - RawTransport

/// Protocol abstracting the raw I/O layer used by TLS/Reality handshakes and
/// proxy chaining.
///
/// Both ``RawTCPSocket`` (real TCP) and ``TunneledTransport`` (tunneled TCP via a
/// proxy chain) conform.
protocol RawTransport: AnyObject {
    /// Whether the transport is connected and ready for I/O.
    var isTransportReady: Bool { get }

    /// Sends data through the transport.
    func send(data: Data, completion: @escaping (Error?) -> Void)

    /// Sends data without tracking completion.
    func send(data: Data)

    /// Receives up to `maximumLength` bytes from the transport.
    func receive(maximumLength: Int, completion: @escaping (Data?, Bool, Error?) -> Void)

    /// Closes the transport and cancels all pending operations.
    func forceCancel()
}

// MARK: - SocketError

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

// MARK: - IPEndpoint

/// A numeric IPv4/IPv6 address + port packed into a `sockaddr_storage`, ready
/// to hand to `connect(2)` or `sendto(2)`.
///
/// Shared between ``RawTCPSocket`` and ``RawUDPSocket`` so neither file needs to
/// duplicate the `inet_pton` / family-branch boilerplate.
struct IPEndpoint {
    /// Socket family — `AF_INET` or `AF_INET6`.
    let family: Int32

    /// Address length to pass to BSD socket APIs.
    let length: socklen_t

    private let storage: sockaddr_storage

    /// Parses `ip` as an IPv4 or IPv6 literal. Returns `nil` if the string
    /// isn't a valid literal for its inferred family.
    init?(ip: String, port: UInt16) {
        var storage = sockaddr_storage()
        let family: Int32
        let length: socklen_t

        if ip.contains(":") {
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = port.bigEndian
            guard ip.withCString({ inet_pton(AF_INET6, $0, &addr.sin6_addr) }) == 1 else {
                return nil
            }
            family = AF_INET6
            length = socklen_t(MemoryLayout<sockaddr_in6>.size)
            _ = memcpy(&storage, &addr, Int(length))
        } else {
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            guard ip.withCString({ inet_pton(AF_INET, $0, &addr.sin_addr) }) == 1 else {
                return nil
            }
            family = AF_INET
            length = socklen_t(MemoryLayout<sockaddr_in>.size)
            _ = memcpy(&storage, &addr, Int(length))
        }

        self.family = family
        self.length = length
        self.storage = storage
    }

    /// Invokes `body` with a `sockaddr *` suitable for `connect`/`sendto`/etc.
    func withSockAddr<T>(_ body: (UnsafePointer<sockaddr>, socklen_t) -> T) -> T {
        return withUnsafePointer(to: storage) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                body(sa, length)
            }
        }
    }
}

// MARK: - SocketHelpers

/// Low-level POSIX helpers shared between ``RawTCPSocket`` and ``RawUDPSocket``.
enum SocketHelpers {
    /// Sets a boolean-like `Int32` socket option. Failure is ignored — a
    /// missing option should never sink the connection.
    @inline(__always)
    static func setInt(_ fd: Int32, level: Int32, name: Int32, value: Int32) {
        var v = value
        _ = setsockopt(fd, level, name, &v, socklen_t(MemoryLayout<Int32>.size))
    }

    /// Puts `fd` into non-blocking mode. Returns `false` on failure.
    @inline(__always)
    static func makeNonBlocking(_ fd: Int32) -> Bool {
        let flags = fcntl(fd, F_GETFL, 0)
        guard flags >= 0 else { return false }
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0
    }
}

// MARK: - RawTCPSocket

/// A TCP transport using BSD (POSIX) sockets with asynchronous I/O.
/// All callers reach this through the ``RawTransport`` protocol.
///
/// ### DNS
/// DNS resolution is performed via ``ProxyDNSCache`` to avoid tunnel routing
/// loops, and the resolved IP address strings are fed directly into the socket
/// via `inet_pton`. This bypasses the system resolver at connect time.
///
/// ### Socket Options (match Xray-core `sockopt_darwin.go`)
/// - `O_NONBLOCK`     — non-blocking socket for async I/O via DispatchSource.
/// - `SO_NOSIGPIPE`   — prevents SIGPIPE on write to a broken pipe (Darwin-specific).
/// - `TCP_NODELAY`    — disables Nagle's algorithm.
/// - `SO_KEEPALIVE`   — enables TCP keepalive.
/// - `TCP_KEEPALIVE`  — idle seconds before the first probe (Darwin name; Linux is TCP_KEEPIDLE).
/// - `TCP_KEEPINTVL`  — interval between probes.
/// - `TCP_KEEPCNT`    — number of failed probes before the kernel drops the connection.
///
/// ### Threading
/// All socket I/O and state-machine transitions are serialized on an internal
/// serial dispatch queue (`ioQueue`). All DispatchSources (read/write/timer)
/// are bound to that queue, so their handlers are implicitly serialized
/// against each other. The `state` property is additionally protected by an
/// unfair lock so that `isTransportReady` and `forceCancel()` can be called
/// safely from any thread without deadlocking on `ioQueue`. `forceCancel()`
/// synchronously latches the cancelled state and then dispatches teardown to
/// `ioQueue`; any blocks already pending on the queue re-check state and bail
/// out.
///
/// ### Loopback
/// Inside a `NEPacketTunnelProvider`, the provider's own socket traffic is
/// kernel-excluded from the tunnel, so a direct `connect(2)` here does not
/// loop back. Loopback targets (127.0.0.0/8, ::1) are always routed via
/// `lo0`. No explicit interface binding — we rely on the OS routing table
/// plus the kernel-level NE bypass.
///
/// ### `initialData`
/// When provided, `initialData` is eagerly enqueued on the send buffer as
/// soon as connect completes. No kernel TFO (`connectx`) — we trade one
/// RTT in the best case for a simpler non-blocking connect flow. Callers
/// (TLS ClientHello, Reality ClientHello) stay correct because the first
/// `receive` still waits on the server's response.
class RawTCPSocket: RawTransport {

    /// The current connection state.
    enum State {
        case setup
        case ready
        case failed(Error)
        case cancelled
    }

    // MARK: Private types

    /// An entry in the partial-send FIFO. The head may have a non-zero
    /// `offset` representing bytes already written.
    private struct PendingSend {
        var data: Data
        var offset: Int
        let completion: ((Error?) -> Void)?
    }

    // MARK: Constants

    /// Per-attempt connect timeout (seconds). Matches Xray-core `system_dialer.go`.
    private static let connectTimeout: Int = 16

    // MARK: State

    private let stateLock = UnfairLock()
    private var _state: State = .setup

    /// The current state of the transport. Thread-safe.
    var state: State {
        stateLock.withLock { _state }
    }

    // MARK: Concurrency

    /// Serial queue for all socket I/O and state transitions.
    /// All DispatchSources are bound to this queue, so their event handlers
    /// run here and are naturally serialized against each other and against
    /// async operations dispatched from outside.
    private let ioQueue = DispatchQueue(label: "com.argsment.Anywhere.RawTCPSocket",
                                        qos: .userInitiated)

    // MARK: Socket & DispatchSources

    /// The socket file descriptor. `-1` when no socket is open.
    /// Mutated only on `ioQueue`; read cross-thread only via the sticky
    /// `.cancelled` state check.
    private var socketFD: Int32 = -1

    /// Monitors socket readability. Armed on demand while a receive is pending.
    private var readSource: DispatchSourceRead?

    /// Monitors socket writability. Armed during non-blocking connect and when
    /// a send has buffered a partial write.
    private var writeSource: DispatchSourceWrite?

    /// Per-attempt connect timer.
    private var connectTimer: DispatchSourceTimer?

    // MARK: Connect pipeline

    /// Pending connect completion, cleared once invoked.
    private var connectCompletion: ((Error?) -> Void)?

    /// Addresses still to try (consumed in order on fallthrough).
    private var remainingIPs: [String] = []
    private var remainingPort: UInt16 = 0
    private var pendingInitialData: Data?

    // MARK: Send pipeline

    /// Partial-send FIFO. Each entry is drained in order.
    private var sendQueue: [PendingSend] = []

    // MARK: Receive pipeline

    /// One receive may be in flight at a time; the contract is that callers
    /// call `receive` again only after the previous completion fires.
    private var pendingReceive: (max: Int, completion: (Data?, Bool, Error?) -> Void)?

    /// Latched when the remote half-closes; subsequent `receive` calls return
    /// EOF immediately without touching the socket.
    private var receivedEOF = false

    // MARK: - Lifecycle

    init() {}

    deinit {
        // By the time deinit runs, all blocks on `ioQueue` have drained (they
        // retain self), so no further mutation is possible. Defensive cleanup
        // only for code paths that skipped `forceCancel()`.
        if socketFD >= 0 {
            _ = Darwin.close(socketFD)
            socketFD = -1
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
    /// When `initialData` is non-empty, it is enqueued for send as soon as the
    /// socket becomes writable (after connect completes).
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

    /// Sends data through the socket.
    ///
    /// Data is enqueued on `ioQueue` and written non-blockingly. Partial
    /// writes are re-armed via a write-ready dispatch source.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        ioQueue.async { [self] in
            switch state {
            case .ready:
                sendQueue.append(PendingSend(data: data, offset: 0, completion: completion))
                drainSendQueue()
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
            guard case .ready = state else { return }
            sendQueue.append(PendingSend(data: data, offset: 0, completion: nil))
            drainSendQueue()
        }
    }

    /// Receives up to `maximumLength` bytes from the socket.
    ///
    /// Completion semantics match the prior implementation:
    /// - `(data, false, nil)` — data received successfully.
    /// - `(nil, true, nil)` — EOF (remote closed).
    /// - `(nil, true, error)` — a receive error occurred.
    func receive(maximumLength: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
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
            // Contract: callers issue receive serially.
            if pendingReceive != nil {
                // Unexpected — prior callback hasn't fired. Don't clobber it;
                // surface an error on this one.
                completion(nil, true, SocketError.receiveFailed("Concurrent receive"))
                return
            }
            pendingReceive = (maximumLength, completion)
            tryReceive()
        }
    }

    /// Closes the socket and cancels all pending operations.
    ///
    /// Safe to call from any thread. The cancelled state is set synchronously
    /// under the state lock so subsequent `isTransportReady` reads and queued
    /// blocks observe it immediately. Actual socket/source teardown and
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
            if let req = pendingReceive {
                pendingReceive = nil
                req.completion(nil, true, SocketError.notConnected)
            }
            if !sendQueue.isEmpty {
                failPendingSends(with: SocketError.sendFailed("Cancelled"))
            }
            pendingInitialData = nil
            remainingIPs.removeAll()
            connectTimer?.cancel()
            connectTimer = nil
            tearDownSocket()
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

        guard let endpoint = IPEndpoint(ip: ip, port: port) else {
            logger.debug("[TCP] inet_pton failed for \(ip)")
            tryConnectNext()
            return
        }

        let fd = Darwin.socket(endpoint.family, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else {
            logger.debug("[TCP] socket() failed: \(String(cString: strerror(errno)))")
            tryConnectNext()
            return
        }

        applyTCPSocketOptions(fd: fd)

        guard SocketHelpers.makeNonBlocking(fd) else {
            logger.debug("[TCP] fcntl(O_NONBLOCK) failed: \(String(cString: strerror(errno)))")
            _ = Darwin.close(fd)
            tryConnectNext()
            return
        }

        socketFD = fd
        armConnectTimer()

        let rc = endpoint.withSockAddr { sa, len in
            Darwin.connect(fd, sa, len)
        }

        if rc == 0 {
            // Unusual but legal on loopback: connect completes synchronously.
            handleConnectReady()
            return
        }

        let err = errno
        if err == EINPROGRESS {
            armWriteSourceForConnect()
            return
        }

        logger.debug("[TCP] connect(\(ip):\(port)) failed: \(String(cString: strerror(err)))")
        tearDownSocket()
        tryConnectNext()
    }

    /// Applies Darwin-specific TCP tuning. Errors are logged but not fatal —
    /// a missing option should not sink the connection.
    private func applyTCPSocketOptions(fd: Int32) {
        SocketHelpers.setInt(fd, level: SOL_SOCKET, name: SO_NOSIGPIPE, value: 1)
        SocketHelpers.setInt(fd, level: IPPROTO_TCP, name: TCP_NODELAY, value: 1)
        SocketHelpers.setInt(fd, level: SOL_SOCKET, name: SO_KEEPALIVE, value: 1)
        SocketHelpers.setInt(fd, level: IPPROTO_TCP, name: TCP_KEEPALIVE, value: 30)
        SocketHelpers.setInt(fd, level: IPPROTO_TCP, name: TCP_KEEPINTVL, value: 10)
        SocketHelpers.setInt(fd, level: IPPROTO_TCP, name: TCP_KEEPCNT, value: 3)
    }

    /// Arms the per-attempt connect timer, replacing any prior timer.
    private func armConnectTimer() {
        connectTimer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: ioQueue)
        t.schedule(deadline: .now() + .seconds(Self.connectTimeout))
        t.setEventHandler { [weak self] in
            self?.handleConnectTimeout()
        }
        connectTimer = t
        t.resume()
    }

    /// Timer fired: current attempt timed out. Try the next address.
    private func handleConnectTimeout() {
        // If we've already transitioned out of setup, the timer lost the race.
        guard case .setup = state else { return }
        logger.debug("[TCP] connect timed out, trying next address")
        tearDownSocket()
        tryConnectNext()
    }

    /// Arms the write source to signal non-blocking connect completion.
    private func armWriteSourceForConnect() {
        disarmWriteSource()
        guard socketFD >= 0 else { return }
        let ws = DispatchSource.makeWriteSource(fileDescriptor: socketFD, queue: ioQueue)
        ws.setEventHandler { [weak self] in
            self?.handleConnectWritable()
        }
        writeSource = ws
        ws.resume()
    }

    /// Write source fired during connect: check `SO_ERROR`.
    private func handleConnectWritable() {
        guard socketFD >= 0 else { return }
        var soerr: Int32 = 0
        var len = socklen_t(MemoryLayout<Int32>.size)
        let gsr = getsockopt(socketFD, SOL_SOCKET, SO_ERROR, &soerr, &len)
        if gsr != 0 {
            let e = errno
            logger.debug("[TCP] getsockopt(SO_ERROR) failed: \(String(cString: strerror(e)))")
            tearDownSocket()
            tryConnectNext()
            return
        }
        if soerr != 0 {
            logger.debug("[TCP] connect completed with error: \(String(cString: strerror(soerr)))")
            tearDownSocket()
            tryConnectNext()
            return
        }
        handleConnectReady()
    }

    /// Promotes to `.ready` and fires the connect completion exactly once.
    private func handleConnectReady() {
        disarmWriteSource()
        connectTimer?.cancel()
        connectTimer = nil

        // Refuse to overwrite a concurrent .cancelled. Teardown will fire the
        // completion in that case.
        guard transitionFromSetup(to: .ready) else { return }

        // Enqueue initialData for the first outgoing bytes (TFO-equivalent).
        if let data = pendingInitialData, !data.isEmpty {
            sendQueue.append(PendingSend(data: data, offset: 0, completion: nil))
        }
        pendingInitialData = nil
        remainingIPs.removeAll()

        let c = connectCompletion
        connectCompletion = nil
        c?(nil)

        if !sendQueue.isEmpty {
            drainSendQueue()
        }
    }

    /// No more addresses to try. Transitions to `.failed` and fires the completion.
    private func finishConnectFailure(_ error: Error) {
        tearDownSocket()
        connectTimer?.cancel()
        connectTimer = nil
        pendingInitialData = nil

        let shouldReport = transitionFromSetup(to: .failed(error))
        let c = connectCompletion
        connectCompletion = nil
        if shouldReport {
            c?(error)
        }
    }

    // MARK: - Send pipeline

    /// Drains the send queue. Must run on `ioQueue`.
    private func drainSendQueue() {
        while !sendQueue.isEmpty {
            guard socketFD >= 0 else {
                failPendingSends(with: SocketError.sendFailed("Socket closed"))
                return
            }

            var head = sendQueue[0]
            let remaining = head.data.count - head.offset
            if remaining <= 0 {
                let c = head.completion
                sendQueue.removeFirst()
                c?(nil)
                continue
            }

            let fd = socketFD
            let sent: Int = head.data.withUnsafeBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.send(fd, base.advanced(by: head.offset), remaining, 0)
            }

            if sent > 0 {
                head.offset += sent
                if head.offset >= head.data.count {
                    let c = head.completion
                    sendQueue.removeFirst()
                    c?(nil)
                    continue
                }
                // Partial — keep head, re-arm write source.
                sendQueue[0] = head
                armWriteSourceForSend()
                return
            }

            // sent <= 0
            let e = errno
            if sent == 0 || e == EAGAIN || e == EWOULDBLOCK || e == EINTR {
                // EAGAIN or spurious 0 — wait for writable.
                armWriteSourceForSend()
                return
            }

            let err = SocketError.sendFailed(String(cString: strerror(e)))
            failPendingSends(with: err)
            // Move state to failed so subsequent sends/receives fail fast.
            stateLock.withLock {
                if case .ready = _state { _state = .failed(err) }
            }
            // Also fail any pending receive.
            if let req = pendingReceive {
                pendingReceive = nil
                disarmReadSource()
                req.completion(nil, true, err)
            }
            return
        }
    }

    /// Fails every buffered send with `err`. Must run on `ioQueue`.
    private func failPendingSends(with err: Error) {
        let q = sendQueue
        sendQueue.removeAll()
        for p in q { p.completion?(err) }
    }

    /// Arms the write source for a partial-send wait. Idempotent.
    private func armWriteSourceForSend() {
        if writeSource != nil { return }
        guard socketFD >= 0 else { return }
        let ws = DispatchSource.makeWriteSource(fileDescriptor: socketFD, queue: ioQueue)
        ws.setEventHandler { [weak self] in
            guard let self else { return }
            // Tear down this write source; `drainSendQueue` will re-arm if needed.
            self.disarmWriteSource()
            self.drainSendQueue()
        }
        writeSource = ws
        ws.resume()
    }

    private func disarmWriteSource() {
        if let ws = writeSource {
            writeSource = nil
            ws.cancel()
        }
    }

    // MARK: - Receive pipeline

    /// Attempts one `recv(2)`. Arms the read source on `EAGAIN`. Must run on
    /// `ioQueue`.
    private func tryReceive() {
        guard let req = pendingReceive else { return }
        guard socketFD >= 0 else {
            pendingReceive = nil
            req.completion(nil, true, SocketError.notConnected)
            return
        }
        let cap = max(1, req.max)
        var buf = Data(count: cap)
        let fd = socketFD
        let n = buf.withUnsafeMutableBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return Darwin.recv(fd, base, cap, 0)
        }
        if n > 0 {
            buf.count = n
            pendingReceive = nil
            disarmReadSource()
            req.completion(buf, false, nil)
        } else if n == 0 {
            receivedEOF = true
            pendingReceive = nil
            disarmReadSource()
            req.completion(nil, true, nil)
        } else {
            let e = errno
            if e == EAGAIN || e == EWOULDBLOCK || e == EINTR {
                armReadSource()
            } else {
                pendingReceive = nil
                disarmReadSource()
                req.completion(nil, true, SocketError.receiveFailed(String(cString: strerror(e))))
            }
        }
    }

    private func armReadSource() {
        if readSource != nil { return }
        guard socketFD >= 0 else { return }
        let rs = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: ioQueue)
        rs.setEventHandler { [weak self] in
            self?.tryReceive()
        }
        readSource = rs
        rs.resume()
    }

    private func disarmReadSource() {
        if let rs = readSource {
            readSource = nil
            rs.cancel()
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

    /// Closes the current fd and tears down its DispatchSources.
    ///
    /// The close is deferred to the sources' cancel handler so that
    /// libdispatch is done monitoring the descriptor before we actually close
    /// it — this is required by the `DispatchSource` contract. Must run on
    /// `ioQueue`.
    private func tearDownSocket() {
        let fdToClose = socketFD
        socketFD = -1

        let rs = readSource
        let ws = writeSource
        readSource = nil
        writeSource = nil

        if fdToClose < 0 {
            rs?.cancel()
            ws?.cancel()
            return
        }

        // No sources to wait on — close immediately.
        if rs == nil && ws == nil {
            _ = Darwin.close(fdToClose)
            return
        }

        // Count cancel handlers; the last one to fire closes the fd. Cancel
        // handlers run on `ioQueue` (serial), so the counter needs no lock.
        var pending = (rs != nil ? 1 : 0) + (ws != nil ? 1 : 0)
        let closeHandler: () -> Void = {
            pending -= 1
            if pending == 0 {
                _ = Darwin.close(fdToClose)
            }
        }

        if let rs {
            rs.setCancelHandler(handler: closeHandler)
            rs.cancel()
        }
        if let ws {
            ws.setCancelHandler(handler: closeHandler)
            ws.cancel()
        }
    }
}
