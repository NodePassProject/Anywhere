//
//  SocketHelpers.swift
//  Anywhere
//
//  Created by NodePassProject on 5/21/26.
//

import Foundation
import Darwin

// MARK: - SocketHelpers

/// Low-level POSIX socket bring-up helpers shared by the raw transports.
nonisolated enum SocketHelpers {

    /// Kernel buffer size for proxy-relay datagram sockets; the ~9 KB macOS
    /// default caps in-flight data per RTT, and one socket exists per proxy
    /// connection so 4 MB doesn't fan out per peer.
    static let kernelSocketBufferSize: Int32 = 4 * 1024 * 1024

    /// Kernel buffer size for direct-bypass per-peer UDP sockets, kept small
    /// because these fan out per peer.
    static let directDatagramSocketBufferSize: Int32 = 128 * 1024

    /// Sets an `Int32` socket option; failure is deliberately ignored.
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

    /// Sets the kernel send/receive buffers to `size` bytes. Best-effort.
    @inline(__always)
    static func setDatagramBuffers(_ fd: Int32, size: Int32) {
        setInt(fd, level: SOL_SOCKET, name: SO_SNDBUF, value: size)
        setInt(fd, level: SOL_SOCKET, name: SO_RCVBUF, value: size)
    }

    /// Widens the kernel buffers for the high-throughput relay transports.
    @inline(__always)
    static func setHighThroughputBuffers(_ fd: Int32) {
        setDatagramBuffers(fd, size: kernelSocketBufferSize)
    }

    /// Creates a socket, retrying once after FD-pressure relief on
    /// `EMFILE`/`ENFILE`. Returns the descriptor, or `-1` with `errno` set.
    @inline(__always)
    static func makeSocket(family: Int32, type: Int32, proto: Int32 = 0,
                           reliefPriority priority: FDReliefPriority) -> Int32 {
        var fd = socket(family, type, proto)
        if fd < 0 {
            let err = errno
            if FDPressureRelief.isFDExhaustion(err), FDPressureRelief.relieve(for: priority) {
                // Relief freed FDs; retry once.
                fd = socket(family, type, proto)
            }
        }
        return fd
    }
}
