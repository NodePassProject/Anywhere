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

    /// Kernel send/receive buffer size for the proxy-relay datagram transports
    /// (``QUICSocket`` and the ``RawUDPSocket`` dialing a SOCKS5/Shadowsocks
    /// server). macOS defaults (~9 KB) cap a relay at that much in flight per
    /// RTT regardless of the congestion window; 4 MB lifts the ceiling. One
    /// exists per proxy connection, so — unlike direct bypass
    /// (``directDatagramSocketBufferSize``) — the buffers don't fan out per
    /// peer. TCP leaves the kernel autotuner alone.
    static let kernelSocketBufferSize: Int32 = 4 * 1024 * 1024

    /// Kernel send/receive buffer size for *direct-bypass* per-peer UDP sockets
    /// (``UDPFlow``'s direct path, taken when a flow skips the proxy). One
    /// exists per peer 5-tuple, so an app doing UDP NAT-traversal on a lossy
    /// link can open many at once; at the relay size (``kernelSocketBufferSize``)
    /// those kernel buffers would blow the Network Extension's hard memory cap
    /// and get it jetsam-killed. 512 KB still sustains ~40 Mbit/s per flow at
    /// 100 ms RTT — ample for direct app traffic — while bounding the per-flow
    /// footprint 8×.
    static let directDatagramSocketBufferSize: Int32 = 512 * 1024

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

    /// Sets the kernel send/receive buffers to `size` bytes. Best-effort: a
    /// kernel that clamps the request just keeps a smaller buffer, so the
    /// result is not checked.
    @inline(__always)
    static func setDatagramBuffers(_ fd: Int32, size: Int32) {
        setInt(fd, level: SOL_SOCKET, name: SO_SNDBUF, value: size)
        setInt(fd, level: SOL_SOCKET, name: SO_RCVBUF, value: size)
    }

    /// Widens the kernel send/receive buffers to ``kernelSocketBufferSize`` for
    /// the high-throughput relay transports. Best-effort.
    @inline(__always)
    static func setHighThroughputBuffers(_ fd: Int32) {
        setDatagramBuffers(fd, size: kernelSocketBufferSize)
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
