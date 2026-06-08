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

/// Connected non-blocking UDP socket for a ``QUICConnection``'s direct-dial
/// path.
///
/// Kept separate from ``RawUDPSocket`` because ngtcp2 imposes constraints a
/// generic UDP wrapper can't meet:
///
/// - **Queue coupling.** All I/O runs on the *connection's* `queue` (passed
///   in), not an internal one. ngtcp2 is single-threaded on that queue and the
///   read path drives it inline, so there is no hop that could reorder a
///   received packet against the connection's other ngtcp2 work.
/// - **Zero-copy receive.** Each datagram is handed to the handler as a
///   `bytesNoCopy` `Data` view over the reusable receive buffer, valid only for
///   that synchronous call; the handler feeds it straight into ngtcp2.
/// - **Raw send.** ``send(_:length:)`` takes a pointer into ngtcp2's tx buffer,
///   avoiding a `Data` copy on the hot path.
/// - **ngtcp2 options.** ECN reporting is enabled so ngtcp2 sees congestion
///   signals, and the kernel-assigned local 4-tuple is read back via
///   `getsockname` for ngtcp2's path.
///
/// DNS and the placeholder/real address decision stay in ``QUICConnection``
/// (ngtcp2 needs the path addresses in both the socket and chained-transport
/// modes). The connection owns the lifecycle: ``connect(remoteAddr:localAddr:addrLen:)``,
/// ``startReceiving(onPacket:onError:)``, ``send(_:length:)``, and ``close()``
/// must all run on `queue`.
nonisolated final class QUICSocket {

    private typealias QUICError = QUICConnection.QUICError

    private let queue: DispatchQueue
    private var rxBuf: [UInt8]

    /// Connected UDP socket. `-1` when not open.
    private var socketFD: Int32 = -1
    /// Fires when the socket has at least one datagram queued; the handler
    /// drains to EAGAIN.
    private var readSource: DispatchSourceRead?

    /// Per-datagram handler. Receives a zero-copy view valid only for the call.
    private var packetHandler: ((Data) -> Void)?
    /// Fires once with the `errno` on a terminal (non-EAGAIN) recv failure.
    private var recvErrorHandler: ((Int32) -> Void)?

    /// True while the socket FD is open.
    var isOpen: Bool { socketFD >= 0 }

    init(queue: DispatchQueue, receiveBufferSize: Int) {
        self.queue = queue
        self.rxBuf = [UInt8](repeating: 0, count: receiveBufferSize)
    }

    // MARK: - Connect

    /// Creates a connected non-blocking UDP socket to `remoteAddr` with the
    /// QUIC/ngtcp2 socket options (4 MB buffers, ECN reporting), then fills
    /// `localAddr` from the kernel-assigned 4-tuple via `getsockname`. Must run
    /// on `queue`.
    func connect(remoteAddr: sockaddr_storage, localAddr: inout sockaddr_storage,
                 addrLen: Int) throws {
        var remote = remoteAddr
        let family = Int32(remote.ss_family)
        // QUIC here carries Hysteria / HTTP3 to the proxy, so it's treated as a
        // user-visible (TCP-class) transport: relief evicts idle direct UDP
        // flows on our behalf and retries once.
        let fd = SocketHelpers.makeSocket(family: family, type: SOCK_DGRAM,
                                          reliefPriority: .userVisible)
        guard fd >= 0 else {
            throw QUICError.connectionFailed("socket() failed errno=\(errno)")
        }

        // Non-blocking so `recv(2)` / `send(2)` return EAGAIN instead of
        // stalling the QUIC queue when the kernel buffer is empty/full.
        guard SocketHelpers.makeNonBlocking(fd) else {
            Darwin.close(fd)
            throw QUICError.connectionFailed("fcntl(O_NONBLOCK) failed errno=\(errno)")
        }

        // Widen the kernel buffers. macOS defaults ~9 KB, which caps
        // throughput at that per-RTT regardless of cwnd.
        SocketHelpers.setHighThroughputBuffers(fd)

        // Best-effort ECN reporting for ngtcp2. Silently ignored on
        // older kernels.
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

        // Populate localAddr with the kernel-assigned 4-tuple so ngtcp2's
        // path matches reality. Cosmetic (migration is disabled).
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

    // MARK: - Receive

    /// Arms the read source on `queue`. `onPacket` fires synchronously per
    /// datagram with a zero-copy `Data` view valid only for that call;
    /// `onError` fires once with the `errno` of a terminal recv failure. Must
    /// run on `queue`.
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

    /// Drains the kernel queue via public `recv(2)` until EAGAIN. One
    /// wake-up of the dispatch source pulls every pending datagram, so
    /// the per-syscall overhead is amortised at burst level.
    private func drainReads() {
        guard socketFD >= 0 else { return }
        while true {
            let n = rxBuf.withUnsafeMutableBufferPointer { buf -> Int in
                Darwin.recv(socketFD, buf.baseAddress, buf.count, 0)
            }
            if n < 0 {
                let err = errno
                if err == EAGAIN || err == EWOULDBLOCK || err == EINTR { return }
                recvErrorHandler?(err)
                return
            }
            if n == 0 { return }
            // Wrap this packet without copying; the handler and its callbacks
            // copy out before returning, so the view stays valid only for this
            // call.
            rxBuf.withUnsafeBufferPointer { buf in
                let view = Data(
                    bytesNoCopy: UnsafeMutableRawPointer(mutating: buf.baseAddress!),
                    count: n, deallocator: .none
                )
                packetHandler?(view)
            }
            // The handler may synchronously close the socket (e.g. on
            // NGTCP2_ERR_DRAINING). Re-check before the next recv so we don't
            // issue recv(-1) → EBADF.
            if socketFD < 0 { return }
        }
    }

    // MARK: - Send

    /// Sends `length` bytes from `bytes`. EAGAIN / transport errors drop the
    /// packet; ngtcp2's loss recovery handles the retransmit. Must run on
    /// `queue`.
    func send(_ bytes: UnsafePointer<UInt8>, length: Int) {
        guard socketFD >= 0, length > 0 else { return }
        while true {
            let n = Darwin.send(socketFD, bytes, length, 0)
            if n >= 0 { return }
            if errno == EINTR { continue }
            // Non-EAGAIN errors are silently dropped; ngtcp2's loss recovery
            // handles the retransmit on the next tx loop.
            return
        }
    }

    // MARK: - Close

    /// Cancels the read source and closes the FD synchronously. Idempotent.
    /// Must run on `queue`.
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
