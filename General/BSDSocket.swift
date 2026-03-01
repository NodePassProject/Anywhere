//
//  BSDSocket.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "BSDSocket")

// MARK: - Error

/// Errors that can occur during BSD socket operations.
enum BSDSocketError: Error, LocalizedError {
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

// MARK: - BSDSocket

/// A non-blocking BSD socket with `DispatchSource`-driven asynchronous I/O.
///
/// `BSDSocket` replaces `NWConnection` for scenarios where direct control over
/// socket options is needed (e.g. `TCP_NODELAY`, `SO_NOSIGPIPE`).
///
/// All mutable state is serialized on an internal serial dispatch queue,
/// making it safe to call from any thread or concurrent queue. No threads
/// are blocked waiting for I/O.
///
/// Socket options are configured following Xray-core's `sockopt_darwin.go`.
class BSDSocket {

    /// The current connection state.
    enum State {
        case setup
        case ready
        case failed(Error)
        case cancelled
    }

    // MARK: Properties

    /// The current state of the socket.
    private(set) var state: State = .setup

    private var fd: Int32 = -1

    /// Internal serial queue that serializes all state access,
    /// preventing data races when callers use concurrent queues.
    private let socketQueue = DispatchQueue(label: "com.argsment.Anywhere.bsdsocket")

    // Read state
    private var readSource: DispatchSourceRead?
    private var readSourceResumed = false
    private var pendingReceive: ((Data?, Bool, Error?) -> Void)?
    private var receiveMaxLength: Int = 65536

    // Write state
    private var writeSource: DispatchSourceWrite?
    private var writeSourceResumed = false
    private var pendingSends: [PendingSend] = []

    private struct PendingSend {
        let data: Data
        var offset: Int
        let completion: ((Error?) -> Void)?
    }

    // MARK: Lifecycle

    deinit {
        if fd >= 0 {
            Darwin.shutdown(fd, SHUT_RDWR)
            Darwin.close(fd)
        }
        // DispatchSource must not be deallocated while suspended
        if let rs = readSource, !readSourceResumed { rs.resume() }
        if let ws = writeSource, !writeSourceResumed { ws.resume() }
    }

    // MARK: - Connect

    /// A resolved network address, copied from `addrinfo` so it outlives `freeaddrinfo`.
    private struct ResolvedAddress {
        let family: Int32
        let socktype: Int32
        let proto: Int32
        let addr: Data
        let addrlen: socklen_t
    }

    /// Connects to a remote host asynchronously.
    ///
    /// DNS resolution runs on a global concurrent queue. The non-blocking TCP
    /// connect and all subsequent I/O run on the internal serial queue.
    ///
    /// - Parameters:
    ///   - host: The remote hostname or IP address.
    ///   - port: The remote port number.
    ///   - queue: Accepted for API compatibility but unused internally.
    ///   - completion: Called with `nil` on success or an error on failure.
    func connect(host: String, port: UInt16, queue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            let addresses: [ResolvedAddress]
            do {
                addresses = try Self.resolveAddresses(host: host, port: port)
            } catch {
                socketQueue.async { self.state = .failed(error); completion(error) }
                return
            }
            socketQueue.async {
                self.tryConnect(addresses: addresses, index: 0, completion: completion)
            }
        }
    }

    /// Resolves a hostname to an array of socket addresses via `getaddrinfo`.
    private static func resolveAddresses(host: String, port: UInt16) throws -> [ResolvedAddress] {
        // Strip brackets from IPv6 addresses (e.g. "[::1]" → "::1")
        let bare = host.hasPrefix("[") && host.hasSuffix("]")
            ? String(host.dropFirst().dropLast())
            : host

        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP

        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(bare, String(port), &hints, &result)
        guard status == 0, let _ = result else {
            let msg = status != 0 ? String(cString: gai_strerror(status)) : "No addresses"
            throw BSDSocketError.resolutionFailed(msg)
        }
        defer { freeaddrinfo(result) }

        var addresses: [ResolvedAddress] = []
        var current = result
        while let info = current {
            let addrData = Data(bytes: info.pointee.ai_addr, count: Int(info.pointee.ai_addrlen))
            addresses.append(ResolvedAddress(
                family: info.pointee.ai_family,
                socktype: info.pointee.ai_socktype,
                proto: info.pointee.ai_protocol,
                addr: addrData,
                addrlen: info.pointee.ai_addrlen
            ))
            current = info.pointee.ai_next
        }

        guard !addresses.isEmpty else {
            throw BSDSocketError.resolutionFailed("No addresses returned")
        }
        return addresses
    }

    /// Connect timeout in seconds (matches Xray-core system_dialer.go `net.Dialer{Timeout: 16s}`).
    /// Prevents indefinite waits when SYN packets are silently dropped (e.g. by a firewall).
    private static let connectTimeout: Int = 16

    /// Attempts a non-blocking connect to each resolved address in order.
    ///
    /// Uses `O_NONBLOCK` + `DispatchSource` to avoid blocking any thread.
    /// Falls through to the next address on failure. Each attempt is guarded
    /// by ``connectTimeout`` seconds to avoid long waits on blocked networks.
    private func tryConnect(addresses: [ResolvedAddress], index: Int, completion: @escaping (Error?) -> Void) {
        guard index < addresses.count else {
            let err = BSDSocketError.connectionFailed("All addresses failed")
            state = .failed(err)
            completion(err)
            return
        }

        let addr = addresses[index]
        let sockFd = Darwin.socket(addr.family, addr.socktype, addr.proto)
        guard sockFd >= 0 else {
            tryConnect(addresses: addresses, index: index + 1, completion: completion)
            return
        }

        // Socket options (reference: Xray-core sockopt_darwin.go)
        var yes: Int32 = 1
        setsockopt(sockFd, IPPROTO_TCP, TCP_NODELAY, &yes, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(sockFd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))

        // Non-blocking mode
        let flags = fcntl(sockFd, F_GETFL)
        _ = fcntl(sockFd, F_SETFL, flags | O_NONBLOCK)

        // Non-blocking connect
        let result = addr.addr.withUnsafeBytes { buf -> Int32 in
            let ptr = buf.baseAddress!.assumingMemoryBound(to: sockaddr.self)
            return Darwin.connect(sockFd, ptr, addr.addrlen)
        }

        if result == 0 {
            fd = sockFd
            state = .ready
            setupSources()
            completion(nil)
        } else if errno == EINPROGRESS {
            // Normal TCP path — wait for writability with a timeout
            fd = sockFd
            var completed = false

            let source = DispatchSource.makeWriteSource(fileDescriptor: sockFd, queue: socketQueue)
            let timer = DispatchSource.makeTimerSource(queue: socketQueue)

            source.setEventHandler { [weak self] in
                guard let self, !completed else { return }
                completed = true
                source.cancel()
                timer.cancel()

                var error: Int32 = 0
                var errorLen = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(sockFd, SOL_SOCKET, SO_ERROR, &error, &errorLen)

                if error == 0 {
                    self.state = .ready
                    self.setupSources()
                    completion(nil)
                } else {
                    Darwin.close(sockFd)
                    self.fd = -1
                    self.tryConnect(addresses: addresses, index: index + 1, completion: completion)
                }
            }

            timer.schedule(deadline: .now() + .seconds(Self.connectTimeout))
            timer.setEventHandler { [weak self] in
                guard let self, !completed else { return }
                completed = true
                source.cancel()
                timer.cancel()
                Darwin.close(sockFd)
                self.fd = -1
                self.tryConnect(addresses: addresses, index: index + 1, completion: completion)
            }

            source.resume()
            timer.resume()
        } else {
            Darwin.close(sockFd)
            tryConnect(addresses: addresses, index: index + 1, completion: completion)
        }
    }

    // MARK: - DispatchSource Setup

    /// Creates read and write dispatch sources for the connected socket.
    ///
    /// Both sources start suspended and are only resumed when the corresponding
    /// operation encounters `EAGAIN` (kernel buffer empty/full).
    private func setupSources() {
        guard fd >= 0 else { return }

        let rs = DispatchSource.makeReadSource(fileDescriptor: fd, queue: socketQueue)
        rs.setEventHandler { [weak self] in self?.handleReadEvent() }
        rs.setCancelHandler { [weak self] in
            self?.readSource = nil
            self?.readSourceResumed = false
        }
        readSource = rs

        let ws = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: socketQueue)
        ws.setEventHandler { [weak self] in self?.handleWriteEvent() }
        ws.setCancelHandler { [weak self] in
            self?.writeSource = nil
            self?.writeSourceResumed = false
        }
        writeSource = ws
    }

    // MARK: - Receive

    /// Receives up to `maximumLength` bytes from the socket.
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
        socketQueue.async { [self] in
            guard fd >= 0 else {
                completion(nil, true, BSDSocketError.notConnected)
                return
            }

            let buffer = UnsafeMutableRawPointer.allocate(byteCount: maximumLength, alignment: 1)
            let n = Darwin.recv(fd, buffer, maximumLength, 0)

            if n > 0 {
                let data = Data(bytes: buffer, count: n)
                buffer.deallocate()
                completion(data, false, nil)
            } else if n == 0 {
                buffer.deallocate()
                completion(nil, true, nil)
            } else if errno == EAGAIN || errno == EWOULDBLOCK {
                buffer.deallocate()
                pendingReceive = completion
                receiveMaxLength = maximumLength
                if !readSourceResumed {
                    readSourceResumed = true
                    readSource?.resume()
                }
            } else {
                buffer.deallocate()
                completion(nil, true, BSDSocketError.receiveFailed(String(cString: strerror(errno))))
            }
        }
    }

    /// Handles a read-ready event from the read dispatch source.
    private func handleReadEvent() {
        guard let completion = pendingReceive else {
            if readSourceResumed {
                readSourceResumed = false
                readSource?.suspend()
            }
            return
        }

        guard fd >= 0 else {
            pendingReceive = nil
            if readSourceResumed { readSourceResumed = false; readSource?.suspend() }
            completion(nil, true, BSDSocketError.notConnected)
            return
        }

        let maxLen = receiveMaxLength
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: maxLen, alignment: 1)
        let n = Darwin.recv(fd, buffer, maxLen, 0)

        if n > 0 {
            pendingReceive = nil
            if readSourceResumed { readSourceResumed = false; readSource?.suspend() }
            let data = Data(bytes: buffer, count: n)
            buffer.deallocate()
            completion(data, false, nil)
        } else if n == 0 {
            pendingReceive = nil
            if readSourceResumed { readSourceResumed = false; readSource?.suspend() }
            buffer.deallocate()
            completion(nil, true, nil)
        } else if errno == EAGAIN || errno == EWOULDBLOCK {
            buffer.deallocate()
            // Spurious wakeup — leave callback and source active
        } else {
            pendingReceive = nil
            if readSourceResumed { readSourceResumed = false; readSource?.suspend() }
            buffer.deallocate()
            completion(nil, true, BSDSocketError.receiveFailed(String(cString: strerror(errno))))
        }
    }

    // MARK: - Send

    /// Sends data through the socket with a completion callback.
    ///
    /// Multiple sends are queued and drained in order. If the kernel send buffer
    /// is full, a write dispatch source resumes draining when space is available.
    ///
    /// - Parameters:
    ///   - data: The data to send.
    ///   - completion: Called with `nil` on success or an error on failure.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        socketQueue.async { [self] in
            guard fd >= 0 else {
                completion(BSDSocketError.notConnected)
                return
            }
            pendingSends.append(PendingSend(data: data, offset: 0, completion: completion))
            if pendingSends.count == 1 {
                drainSendQueue()
            }
        }
    }

    /// Sends data through the socket without tracking completion.
    ///
    /// - Parameter data: The data to send.
    func send(data: Data) {
        send(data: data) { _ in }
    }

    /// Drains the pending send queue without blocking.
    ///
    /// Writes as much data as the kernel will accept, then suspends if
    /// `EAGAIN` is returned. The write dispatch source will resume draining.
    private func drainSendQueue() {
        while !pendingSends.isEmpty && fd >= 0 {
            let data = pendingSends[0].data
            let offset = pendingSends[0].offset
            let remaining = data.count - offset

            let sent = data.withUnsafeBytes { buf -> Int in
                guard let base = buf.baseAddress else { return -1 }
                return Darwin.send(fd, base + offset, remaining, 0)
            }

            if sent > 0 {
                pendingSends[0].offset += sent
                if pendingSends[0].offset >= data.count {
                    let done = pendingSends.removeFirst()
                    done.completion?(nil)
                }
            } else if sent == 0 {
                let done = pendingSends.removeFirst()
                done.completion?(BSDSocketError.sendFailed("Connection closed"))
            } else if errno == EAGAIN || errno == EWOULDBLOCK {
                if !writeSourceResumed {
                    writeSourceResumed = true
                    writeSource?.resume()
                }
                return
            } else {
                let err = BSDSocketError.sendFailed(String(cString: strerror(errno)))
                let all = pendingSends
                pendingSends.removeAll()
                for p in all { p.completion?(err) }
                return
            }
        }

        if writeSourceResumed {
            writeSourceResumed = false
            writeSource?.suspend()
        }
    }

    /// Handles a write-ready event from the write dispatch source.
    private func handleWriteEvent() {
        drainSendQueue()
    }

    // MARK: - Cancel

    /// Closes the socket and cancels all pending operations.
    ///
    /// Safe to call from any thread. Cleanup is dispatched to the internal
    /// serial queue to avoid data races.
    func forceCancel() {
        socketQueue.async { [self] in
            let currentFd = fd
            fd = -1
            state = .cancelled

            if let rs = readSource {
                if !readSourceResumed { rs.resume() }
                rs.cancel()
                readSource = nil
                readSourceResumed = false
            }
            if let ws = writeSource {
                if !writeSourceResumed { ws.resume() }
                ws.cancel()
                writeSource = nil
                writeSourceResumed = false
            }

            pendingReceive = nil
            pendingSends.removeAll()

            if currentFd >= 0 {
                Darwin.shutdown(currentFd, SHUT_RDWR)
                Darwin.close(currentFd)
            }
        }
    }
}
