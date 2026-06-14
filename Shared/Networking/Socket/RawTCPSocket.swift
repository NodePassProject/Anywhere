//
//  RawTCPSocket.swift
//  Anywhere
//
//  Created by NodePassProject on 3/24/26.
//

import Foundation
import Darwin

private let logger = AnywhereLogger(category: "RawTCPSocket")

// MARK: - RawTransport

/// Raw I/O transport abstraction used by TLS/Reality handshakes and proxy chaining.
protocol RawTransport: AnyObject {
    var isTransportReady: Bool { get }

    func send(data: Data, completion: @escaping (Error?) -> Void)

    func send(data: Data)

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void)

    func forceCancel()
}

// MARK: - SocketError

enum SocketError: Error, LocalizedError {
    case resolutionFailed(String)
    case socketCreationFailed(String)
    case connectionFailed(String)
    case notConnected
    case sendFailed(String)
    case receiveFailed(String)
    /// POSIX failure preserving the raw `errno` so callers can classify by code.
    case posixError(Operation, errno: Int32)

    enum Operation {
        case connect, send, receive

        var failurePrefix: String {
            switch self {
            case .connect: return "Connection failed"
            case .send:    return "Send failed"
            case .receive: return "Receive failed"
            }
        }
    }

    var errorDescription: String? {
        switch self {
        case .resolutionFailed(let msg): return "DNS resolution failed: \(msg)"
        case .socketCreationFailed(let msg): return "Socket creation failed: \(msg)"
        case .connectionFailed(let msg): return "Connection failed: \(msg)"
        case .notConnected: return "Not connected"
        case .sendFailed(let msg): return "Send failed: \(msg)"
        case .receiveFailed(let msg): return "Receive failed: \(msg)"
        case .posixError(let op, let errno):
            return "\(op.failurePrefix): \(String(cString: strerror(errno)))"
        }
    }

    var posixErrno: Int32? {
        if case .posixError(_, let errno) = self { return errno }
        return nil
    }
}

// MARK: - IPEndpoint

/// A numeric IPv4/IPv6 address + port packed into a `sockaddr_storage` for
/// `connect(2)`/`sendto(2)`.
struct IPEndpoint {
    /// Socket family — `AF_INET` or `AF_INET6`.
    let family: Int32

    let length: socklen_t

    private let storage: sockaddr_storage

    /// Parses `ip` as an IPv4 or IPv6 literal; fails if it isn't a valid literal.
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

// MARK: - RawTCPSocket

/// A TCP transport over non-blocking BSD sockets with DispatchSource-driven I/O.
///
/// All I/O and state transitions run on the serial `ioQueue`; `state` is
/// additionally lock-protected so `isTransportReady` and `forceCancel()` are
/// safe from any thread. The provider's own sockets are kernel-excluded from the
/// tunnel, so a direct `connect(2)` here does not loop back. `initialData` is enqueued once
/// connect completes (no kernel TFO — one extra RTT for a simpler flow).
nonisolated class RawTCPSocket: RawTransport {

    enum State {
        case setup
        case ready
        case failed(Error)
        case cancelled
    }

    // MARK: Private types

    /// Partial-send FIFO entry; `offset` counts bytes already written.
    private struct PendingSend {
        var data: Data
        var offset: Int
        let completion: ((Error?) -> Void)?
    }

    // MARK: Constants

    /// Per-attempt connect timeout (seconds).
    private static let connectTimeout: Int = 16

    // MARK: State

    private let stateLock = UnfairLock()
    private var _state: State = .setup

    /// Completions awaiting full teardown (fd closed). Protected by `stateLock`.
    private var teardownCompletions: [@Sendable () -> Void] = []
    /// Set once teardown has finished. Protected by `stateLock`.
    private var teardownComplete = false

    /// The current state of the transport. Thread-safe.
    var state: State {
        stateLock.withLock { _state }
    }

    // MARK: Concurrency

    /// Serial queue for all socket I/O; all DispatchSources are bound to it.
    private let ioQueue = DispatchQueue(label: AWCore.Identifier.rawTCPSocketQueue,
                                        qos: .userInitiated,
                                        autoreleaseFrequency: .workItem)

    // MARK: Socket & DispatchSources

    /// Socket file descriptor; `-1` when closed. Mutated only on `ioQueue`.
    private var socketFD: Int32 = -1

    /// Monitors socket readability. Armed on demand while a receive is pending.
    private var readSource: DispatchSourceRead?

    /// Monitors writability; armed during connect and partial-send waits.
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

    /// Times the dial for the live "Dial" stat; direct/bypass dials disable it
    /// so only proxied first-hop dials are counted.
    var dialTimer = MetricTimer(.dial)

    // MARK: Send pipeline

    /// Partial-send FIFO.
    private var sendQueue: [PendingSend] = []

    // MARK: Receive pipeline

    /// At most one receive in flight; callers issue receives serially.
    private var pendingReceiveCompletion: ((Data?, Bool, Error?) -> Void)?

    /// Latched on remote half-close; later receives return EOF immediately.
    private var receivedEOF = false

    /// Reusable `recv(2)` scratch, allocated lazily on first receive.
    private static let recvScratchSize = 65535
    private var recvScratch: UnsafeMutableRawPointer?

    // MARK: - Lifecycle

    init() {}

    // MARK: - RawTransport

    var isTransportReady: Bool {
        if case .ready = state { return true }
        return false
    }

    /// Connects asynchronously, trying each resolved IP in order; `initialData`
    /// is enqueued once connect completes. `completion` fires on `ioQueue`.
    func connect(host: String, port: UInt16,
                 initialData: Data? = nil,
                 completion: @escaping (Error?) -> Void) {
        ioQueue.async { [self] in
            // Cancelled before we ran; completion was never stored, so fire it here.
            if case .cancelled = state {
                completion(SocketError.connectionFailed("Cancelled"))
                return
            }

            let ips = DNSResolver.shared.resolveAll(host)
            guard !ips.isEmpty else {
                let err = SocketError.resolutionFailed("DNS resolution failed for \(host)")
                stateLock.withLock {
                    if case .setup = _state { _state = .failed(err) }
                }
                completion(err)
                return
            }

            remainingIPs = ips
            remainingPort = port
            pendingInitialData = initialData
            // Stash before further transitions so a racing forceCancel() can fire it.
            connectCompletion = completion
            // Start after DNS so the Dial stat excludes resolution.
            dialTimer.start()
            tryConnectNext()
        }
    }

    /// Enqueues data for non-blocking write; partial writes re-arm the write source.
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

    /// Receives once. Completion: `(data, false, nil)` on data,
    /// `(nil, true, nil)` on EOF, `(nil, true, error)` on failure.
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
            // Contract: receives are serial; don't clobber a pending completion.
            if pendingReceiveCompletion != nil {
                completion(nil, true, SocketError.receiveFailed("Concurrent receive"))
                return
            }
            pendingReceiveCompletion = completion
            tryReceive()
        }
    }

    /// Safe from any thread; latches `.cancelled` synchronously, then tears
    /// down on `ioQueue`.
    func forceCancel() {
        forceCancel(completion: {})
    }

    /// Variant whose completion fires exactly once, after the fd is fully
    /// closed; calls after teardown completes fire immediately.
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
            ioQueue.async { [self] in
                if let c = connectCompletion {
                    connectCompletion = nil
                    c(SocketError.connectionFailed("Cancelled"))
                }
                if let pendingComp = pendingReceiveCompletion {
                    pendingReceiveCompletion = nil
                    pendingComp(nil, true, SocketError.notConnected)
                }
                if !sendQueue.isEmpty {
                    failPendingSends(with: SocketError.sendFailed("Cancelled"))
                }
                pendingInitialData = nil
                remainingIPs.removeAll()
                connectTimer?.cancel()
                connectTimer = nil
                tearDownSocket { [self] in
                    notifyTeardownComplete()
                }
            }
        }
    }

    /// Drains queued teardown completions once the fd is closed.
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

        let fd = SocketHelpers.makeSocket(family: endpoint.family, type: SOCK_STREAM,
                                          proto: IPPROTO_TCP, reliefPriority: .userVisible)
        if fd < 0 {
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

    /// Applies Darwin-specific TCP tuning; a missing option is not fatal.
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

        // A racing .cancelled wins; teardown fires the completion.
        guard transitionFromSetup(to: .ready) else { return }

        dialTimer.stop()

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
                return PerformanceMonitor.measure(.socketSendTCP) {
                    Darwin.send(fd, base.advanced(by: head.offset), remaining, 0)
                }
            }

            if sent > 0 {
                head.offset += sent
                if head.offset >= head.data.count {
                    let c = head.completion
                    sendQueue.removeFirst()
                    c?(nil)
                    continue
                }
                sendQueue[0] = head
                armWriteSourceForSend()
                return
            }

            let e = errno
            if sent == 0 || e == EAGAIN || e == EWOULDBLOCK || e == EINTR {
                // EAGAIN or spurious 0 — wait for writable.
                armWriteSourceForSend()
                return
            }

            let err = SocketError.posixError(.send, errno: e)
            failPendingSends(with: err)
            // Move state to failed so subsequent sends/receives fail fast.
            stateLock.withLock {
                if case .ready = _state { _state = .failed(err) }
            }
            if let completion = pendingReceiveCompletion {
                pendingReceiveCompletion = nil
                disarmReadSource()
                completion(nil, true, err)
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
        guard let completion = pendingReceiveCompletion else { return }
        guard socketFD >= 0 else {
            pendingReceiveCompletion = nil
            completion(nil, true, SocketError.notConnected)
            return
        }
        let scratch: UnsafeMutableRawPointer
        if let existing = recvScratch {
            scratch = existing
        } else {
            scratch = UnsafeMutableRawPointer.allocate(byteCount: Self.recvScratchSize, alignment: 1)
            recvScratch = scratch
        }
        let fd = socketFD
        let n = PerformanceMonitor.measure(.socketReceiveTCP) {
            Darwin.recv(fd, scratch, Self.recvScratchSize, 0)
        }
        if n > 0 {
            // Scratch is reused, so the returned Data must own its bytes (no bytesNoCopy).
            let buf = Data(bytes: scratch, count: n)
            pendingReceiveCompletion = nil
            disarmReadSource()
            completion(buf, false, nil)
        } else if n == 0 {
            receivedEOF = true
            pendingReceiveCompletion = nil
            disarmReadSource()
            completion(nil, true, nil)
        } else {
            let e = errno
            if e == EAGAIN || e == EWOULDBLOCK || e == EINTR {
                armReadSource()
            } else {
                pendingReceiveCompletion = nil
                disarmReadSource()
                completion(nil, true, SocketError.posixError(.receive, errno: e))
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

    /// Closes the fd after its DispatchSources cancel — required by the
    /// DispatchSource contract. Must run on `ioQueue`.
    private func tearDownSocket() {
        tearDownSocket(completion: {})
    }

    /// Variant that fires `completion` once the fd is actually closed.
    private func tearDownSocket(completion: @escaping @Sendable () -> Void) {
        if let scratch = recvScratch {
            recvScratch = nil
            scratch.deallocate()
        }

        let fdToClose = socketFD
        socketFD = -1

        let rs = readSource
        let ws = writeSource
        readSource = nil
        writeSource = nil

        if fdToClose < 0 {
            rs?.cancel()
            ws?.cancel()
            completion()
            return
        }

        if rs == nil && ws == nil {
            _ = Darwin.close(fdToClose)
            completion()
            return
        }

        // Last cancel handler closes the fd; handlers run serially on `ioQueue`,
        // so the counter needs no lock.
        var pending = (rs != nil ? 1 : 0) + (ws != nil ? 1 : 0)
        let closeHandler: () -> Void = {
            pending -= 1
            if pending == 0 {
                _ = Darwin.close(fdToClose)
                completion()
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
