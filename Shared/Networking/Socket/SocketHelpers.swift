//
//  SocketHelpers.swift
//  Anywhere
//
//  Created by NodePassProject on 5/21/26.
//

import Foundation
import Darwin

// MARK: - SocketHelpers

/// Low-level POSIX socket helpers shared by ``RawTCPSocket``, ``RawUDPSocket``,
/// and ``QUICSocket``. These cover the bring-up steps every transport repeats
/// (create + relief retry, non-blocking, buffer sizing); the protocol-specific
/// option sets (TCP keepalive, QUIC ECN, …) stay in their own classes.
nonisolated enum SocketHelpers {

    /// Kernel send/receive buffer size for the high-throughput datagram paths
    /// (``RawUDPSocket``, ``QUICSocket``). macOS defaults (~9 KB) cap a relay
    /// at that much in flight per RTT regardless of the congestion window;
    /// 4 MB lifts the ceiling. TCP leaves the kernel autotuner alone.
    static let kernelSocketBufferSize: Int32 = 4 * 1024 * 1024

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

    /// Widens the kernel send/receive buffers to ``kernelSocketBufferSize``.
    /// Best-effort: a kernel that clamps the request just keeps a smaller
    /// buffer, so the result is not checked.
    @inline(__always)
    static func setHighThroughputBuffers(_ fd: Int32) {
        setInt(fd, level: SOL_SOCKET, name: SO_SNDBUF, value: kernelSocketBufferSize)
        setInt(fd, level: SOL_SOCKET, name: SO_RCVBUF, value: kernelSocketBufferSize)
    }

    /// Creates a socket, retrying once through ``FDPressureRelief`` when the
    /// first attempt hits per-process / system FD exhaustion (`EMFILE` /
    /// `ENFILE`). `priority` selects how aggressively relief evicts idle direct
    /// flows to free an FD for this caller (see ``FDReliefPriority``).
    ///
    /// Returns the new descriptor, or `-1` with `errno` set from the final
    /// attempt — callers map that to their own error type.
    @inline(__always)
    static func makeSocket(family: Int32, type: Int32, proto: Int32 = 0,
                           reliefPriority priority: FDReliefPriority) -> Int32 {
        var fd = socket(family, type, proto)
        if fd < 0 {
            let err = errno
            if FDPressureRelief.isFDExhaustion(err), FDPressureRelief.relieve(for: priority) {
                // Relief evicted idle direct UDP flow(s); retry once. A failed
                // retry falls through with the latest errno.
                fd = socket(family, type, proto)
            }
        }
        return fd
    }
}
