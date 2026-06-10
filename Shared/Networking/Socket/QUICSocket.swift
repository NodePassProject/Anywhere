//
//  QUICSocket.swift
//  Anywhere
//
//  Created by NodePassProject on 5/21/26.
//

import Foundation
import Darwin
import Dispatch

// MARK: - QUICSocket

/// Connected non-blocking UDP socket for QUICConnection's direct-dial path. Kept separate
/// from RawUDPSocket: all I/O runs inline on the connection's queue (ngtcp2 is single-threaded
/// there), receive/send are zero-copy, and ECN reporting is enabled for ngtcp2.
nonisolated final class QUICSocket {

    private typealias QUICError = QUICConnection.QUICError

    private let queue: DispatchQueue
    private var rxBuf: [UInt8]

    /// Connected UDP socket. `-1` when not open.
    private var socketFD: Int32 = -1
    /// Fires when a datagram is queued; the handler drains to EAGAIN.
    private var readSource: DispatchSourceRead?

    /// Per-datagram handler. Receives a zero-copy view valid only for the call.
    private var packetHandler: ((Data) -> Void)?
    /// Fires once with the `errno` on a terminal (non-EAGAIN) recv failure.
    private var recvErrorHandler: ((Int32) -> Void)?

    var isOpen: Bool { socketFD >= 0 }

    init(queue: DispatchQueue, receiveBufferSize: Int) {
        self.queue = queue
        self.rxBuf = [UInt8](repeating: 0, count: receiveBufferSize)
    }

    // MARK: - Connect

    /// Creates a connected non-blocking UDP socket with QUIC socket options, then fills
    /// `localAddr` from the kernel-assigned 4-tuple. Must run on `queue`.
    func connect(remoteAddr: sockaddr_storage, localAddr: inout sockaddr_storage,
                 addrLen: Int) throws {
        var remote = remoteAddr
        let family = Int32(remote.ss_family)
        // Treated as a user-visible (TCP-class) transport: relief evicts idle
        // direct UDP flows on our behalf and retries once.
        let fd = SocketHelpers.makeSocket(family: family, type: SOCK_DGRAM,
                                          reliefPriority: .userVisible)
        guard fd >= 0 else {
            throw QUICError.connectionFailed("socket() failed errno=\(errno)")
        }

        // Non-blocking so recv/send return EAGAIN instead of stalling the QUIC queue.
        guard SocketHelpers.makeNonBlocking(fd) else {
            Darwin.close(fd)
            throw QUICError.connectionFailed("fcntl(O_NONBLOCK) failed errno=\(errno)")
        }

        // macOS default ~9 KB kernel buffers cap per-RTT throughput regardless of cwnd.
        SocketHelpers.setHighThroughputBuffers(fd)

        // Best-effort ECN reporting for ngtcp2; silently ignored on older kernels.
        if family == AF_INET {
            SocketHelpers.setInt(fd, level: IPPROTO_IP, name: IP_RECVTOS, value: 1)
        } else {
            SocketHelpers.setInt(fd, level: IPPROTO_IPV6, name: IPV6_RECVTCLASS, value: 1)
        }

        let connectRv = withUnsafePointer(to: &remote) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(fd, sa, socklen_t(addrLen))
            }
        }
        if connectRv != 0 {
            Darwin.close(fd)
            throw QUICError.connectionFailed("connect() failed errno=\(errno)")
        }

        // Fill localAddr so ngtcp2's path matches reality; cosmetic (migration is disabled).
        var localStorage = sockaddr_storage()
        var localLen = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let gotLocal = withUnsafeMutablePointer(to: &localStorage) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                getsockname(fd, sa, &localLen)
            }
        }
        if gotLocal == 0 {
            if localStorage.ss_family == sa_family_t(AF_INET) {
                withUnsafePointer(to: &localStorage) { src in
                    src.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                        withUnsafeMutablePointer(to: &localAddr) { dst in
                            dst.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { dsin in
                                dsin.pointee.sin_port = sin.pointee.sin_port
                                dsin.pointee.sin_addr = sin.pointee.sin_addr
                            }
                        }
                    }
                }
            } else if localStorage.ss_family == sa_family_t(AF_INET6) {
                withUnsafePointer(to: &localStorage) { src in
                    src.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                        withUnsafeMutablePointer(to: &localAddr) { dst in
                            dst.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { dsin6 in
                                dsin6.pointee.sin6_port = sin6.pointee.sin6_port
                                dsin6.pointee.sin6_addr = sin6.pointee.sin6_addr
                            }
                        }
                    }
                }
            }
        }

        socketFD = fd
    }

    /// Re-points the connected socket at a new peer, keeping the same FD (and thus the same
    /// local source port and armed read source). Used for Hysteria port hopping: only the
    /// destination port rotates, so the server's post-DNAT 4-tuple — and ngtcp2's fixed path —
    /// stay put. Best-effort; a failed re-connect leaves the prior peer in place and the next
    /// hop retries. Must run on `queue`.
    func reconnect(remoteAddr: sockaddr_storage, addrLen: Int) {
        guard socketFD >= 0 else { return }
        var remote = remoteAddr
        _ = withUnsafePointer(to: &remote) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(socketFD, sa, socklen_t(addrLen))
            }
        }
    }

    // MARK: - Receive

    /// Arms the read source. `onPacket` fires synchronously with a zero-copy view valid only
    /// for that call; `onError` fires once on terminal recv failure. Must run on `queue`.
    func startReceiving(onPacket: @escaping (Data) -> Void,
                        onError: @escaping (Int32) -> Void) {
        guard socketFD >= 0 else { return }
        packetHandler = onPacket
        recvErrorHandler = onError
        let source = DispatchSource.makeReadSource(fileDescriptor: socketFD, queue: queue)
        source.setEventHandler { [weak self] in
            self?.drainReads()
        }
        readSource = source
        source.resume()
    }

    /// Drains `recv(2)` to EAGAIN; one wake-up pulls every pending datagram.
    private func drainReads() {
        guard socketFD >= 0 else { return }
        while true {
            let n = rxBuf.withUnsafeMutableBufferPointer { buf -> Int in
                PerformanceMonitor.measure(.socketReceiveQUIC) {
                    Darwin.recv(socketFD, buf.baseAddress, buf.count, 0)
                }
            }
            if n < 0 {
                let err = errno
                if err == EAGAIN || err == EWOULDBLOCK || err == EINTR { return }
                recvErrorHandler?(err)
                return
            }
            if n == 0 { return }
            // Zero-copy view; the handler copies out before returning.
            rxBuf.withUnsafeBufferPointer { buf in
                let view = Data(
                    bytesNoCopy: UnsafeMutableRawPointer(mutating: buf.baseAddress!),
                    count: n, deallocator: .none
                )
                packetHandler?(view)
            }
            // The handler may synchronously close the socket; re-check so we
            // don't issue recv(-1) → EBADF.
            if socketFD < 0 { return }
        }
    }

    // MARK: - Send

    /// Sends `length` bytes; errors drop the packet (ngtcp2's loss recovery retransmits).
    /// Must run on `queue`.
    func send(_ bytes: UnsafePointer<UInt8>, length: Int) {
        guard socketFD >= 0, length > 0 else { return }
        while true {
            let n = PerformanceMonitor.measure(.socketSendQUIC) {
                Darwin.send(socketFD, bytes, length, 0)
            }
            if n >= 0 { return }
            if errno == EINTR { continue }
            return
        }
    }

    // MARK: - Close

    /// Cancels the read source and closes the FD. Idempotent; must run on `queue`.
    func close() {
        if let source = readSource {
            source.cancel()
            readSource = nil
        }
        if socketFD >= 0 {
            Darwin.close(socketFD)
            socketFD = -1
        }
        packetHandler = nil
        recvErrorHandler = nil
    }
}
