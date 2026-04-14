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

    // MARK: - Properties

    private let stateLock = UnfairLock()
    private var _state: State = .setup
    var isReady: Bool { stateLock.withLock { if case .ready = _state { return true } else { return false } } }

    private let ioQueue = DispatchQueue(label: "com.argsment.Anywhere.RawUDPSocket",
                                        qos: .userInitiated)

    /// Socket file descriptor. `-1` when no socket is open.
    private var socketFD: Int32 = -1

    /// Fires on socket readability; handler drains to `EAGAIN`.
    private var readSource: DispatchSourceRead?

    private var receiveHandler: ((Data) -> Void)?
    private var receiveHandlerQueue: DispatchQueue?

    /// 65 KiB covers the largest possible UDP payload; reused across
    /// `recv(2)` calls so the loop only allocates for the per-packet
    /// `Data` copy handed to the handler.
    private var rxBuffer = [UInt8](repeating: 0, count: 65536)

    // MARK: - Lifecycle

    init() {}

    deinit {
        if socketFD >= 0 {
            _ = Darwin.close(socketFD)
            socketFD = -1
        }
    }

    // MARK: - Connect

    /// Resolves `host` via ``ProxyDNSCache`` and creates a connected
    /// non-blocking UDP socket to `port`.
    ///
    /// - Parameters:
    ///   - host: Remote hostname or literal IP.
    ///   - port: Remote UDP port.
    ///   - completionQueue: Queue on which `completion` is invoked.
    ///   - completion: `nil` on success, a `SocketError` on failure.
    func connect(host: String, port: UInt16,
                 completionQueue: DispatchQueue,
                 completion: @escaping (Error?) -> Void) {
        ioQueue.async { [weak self] in
            guard let self else {
                completionQueue.async { completion(SocketError.connectionFailed("Deallocated")) }
                return
            }
            if case .cancelled = self.stateLock.withLock({ self._state }) {
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

            // Try each resolved IP in order, matching BSDSocket's
            // behavior on mixed v4/v6 records.
            var lastError: SocketError?
            for ip in ips {
                switch self.connectToIP(ip, port: port) {
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

    /// Runs on `ioQueue`. Builds a sockaddr from `ip`, creates the socket,
    /// applies options, and calls `connect(2)`.
    private func connectToIP(_ ip: String, port: UInt16) -> Result<Void, SocketError> {
        var storage = sockaddr_storage()
        let addrLen: socklen_t
        let family: Int32

        if ip.contains(":") {
            var a6 = sockaddr_in6()
            a6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            a6.sin6_family = sa_family_t(AF_INET6)
            a6.sin6_port = port.bigEndian
            let ok = ip.withCString { inet_pton(AF_INET6, $0, &a6.sin6_addr) }
            guard ok == 1 else {
                return .failure(.connectionFailed("inet_pton(v6) failed for \(ip)"))
            }
            family = AF_INET6
            addrLen = socklen_t(MemoryLayout<sockaddr_in6>.size)
            withUnsafeMutablePointer(to: &storage) { dst in
                withUnsafePointer(to: &a6) { src in
                    memcpy(UnsafeMutableRawPointer(dst), UnsafeRawPointer(src), Int(addrLen))
                }
            }
        } else {
            var a4 = sockaddr_in()
            a4.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            a4.sin_family = sa_family_t(AF_INET)
            a4.sin_port = port.bigEndian
            let ok = ip.withCString { inet_pton(AF_INET, $0, &a4.sin_addr) }
            guard ok == 1 else {
                return .failure(.connectionFailed("inet_pton(v4) failed for \(ip)"))
            }
            family = AF_INET
            addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            withUnsafeMutablePointer(to: &storage) { dst in
                withUnsafePointer(to: &a4) { src in
                    memcpy(UnsafeMutableRawPointer(dst), UnsafeRawPointer(src), Int(addrLen))
                }
            }
        }

        let fd = Darwin.socket(family, SOCK_DGRAM, 0)
        guard fd >= 0 else {
            return .failure(.socketCreationFailed("socket() errno=\(errno)"))
        }

        let flags = fcntl(fd, F_GETFL, 0)
        if flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            _ = Darwin.close(fd)
            return .failure(.socketCreationFailed("fcntl(O_NONBLOCK) errno=\(errno)"))
        }

        var on: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on,
                       socklen_t(MemoryLayout<Int32>.size))

        // Widen the kernel buffers. macOS defaults ~9 KB, which caps
        // high-bandwidth relays at that per-RTT.
        var bufSize: Int32 = 4 * 1024 * 1024
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufSize,
                       socklen_t(MemoryLayout<Int32>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufSize,
                       socklen_t(MemoryLayout<Int32>.size))

        let rc = withUnsafePointer(to: &storage) { p -> Int32 in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(fd, sa, addrLen)
            }
        }
        if rc != 0 {
            let err = errno
            _ = Darwin.close(fd)
            return .failure(.connectionFailed("connect() errno=\(err)"))
        }

        socketFD = fd
        return .success(())
    }

    // MARK: - Receive

    /// Installs a receive handler. Fires on `handlerQueue` (or `ioQueue`
    /// if nil) once per datagram. Calling twice replaces the previous
    /// handler.
    func startReceiving(queue handlerQueue: DispatchQueue? = nil,
                        handler: @escaping (Data) -> Void) {
        ioQueue.async { [weak self] in
            guard let self else { return }
            self.receiveHandler = handler
            self.receiveHandlerQueue = handlerQueue
        }
    }

    private func armReadSource() {
        // Runs on ioQueue via the connect path.
        guard socketFD >= 0, readSource == nil else { return }
        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: ioQueue)
        source.setEventHandler { [weak self] in
            self?.drainReads()
        }
        readSource = source
        source.resume()
    }

    private func drainReads() {
        guard socketFD >= 0 else { return }
        while true {
            let n = rxBuffer.withUnsafeMutableBufferPointer { buf -> Int in
                Darwin.recv(socketFD, buf.baseAddress, buf.count, 0)
            }
            if n < 0 {
                let err = errno
                if err == EAGAIN || err == EWOULDBLOCK || err == EINTR { return }
                logger.error("[RawUDP] recv errno=\(err)")
                return
            }
            if n == 0 { return }
            guard let handler = receiveHandler else {
                // No handler installed yet; drop but keep draining so
                // the dispatch source stops firing.
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
            _ = self?.sendOnQueue(data)
        }
    }

    /// Datagram send with completion on the internal `ioQueue`.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        ioQueue.async { [weak self] in
            let err = self?.sendOnQueue(data)
            completion(err)
        }
    }

    private func sendOnQueue(_ data: Data) -> Error? {
        guard socketFD >= 0 else { return SocketError.notConnected }
        if case .cancelled = stateLock.withLock({ _state }) {
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
            return SocketError.sendFailed("errno=\(err)")
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
            self.receiveHandlerQueue = nil
        }
    }
}
