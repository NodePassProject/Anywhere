//
//  TunnelConstants.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
//

import Foundation

enum TunnelConstants {

    // MARK: - Connection Timeouts

    /// Inactivity timeout for TCP connections (Xray-core `connIdle`, default 300s).
    static let connectionIdleTimeout: TimeInterval = 300
    /// Timeout after uplink (local → remote) finishes (Xray-core `downlinkOnly`, default 1s).
    static let downlinkOnlyTimeout: TimeInterval = 1
    /// Timeout after downlink (remote → local) finishes (Xray-core `uplinkOnly`, default 1s).
    static let uplinkOnlyTimeout: TimeInterval = 1
    /// Handshake timeout matching Xray-core's `Timeout.Handshake` (60 seconds).
    /// Bounds the entire connection setup phase (TCP + TLS + WS/HTTPUpgrade + VLESS header).
    static let handshakeTimeout: TimeInterval = 60
    /// Maximum time to wait for a TLS ClientHello on a real-IP TCP connection
    /// before falling back to IP-based routing. Covers server-speaks-first
    /// protocols (SSH, SMTP, FTP) so they don't stall inside the sniff phase.
    /// TLS clients typically send ClientHello within a few ms of TCP accept.
    static let sniffDeadline: TimeInterval = 0.5

    // MARK: - TCP Buffer Sizes

    /// Maximum bytes per tcp_write call (16 KB ≈ 12 TCP segments at TCP_MSS=1360).
    /// With MEMP_NUM_TCP_SEG=32768, this lets many connections make progress without
    /// exhausting the segment pool. Must stay in sync with lwipopts.h.
    static let tcpMaxWriteSize = 16 * 1024
    /// Maximum upload coalesce buffer size, capped at UInt16.max because downstream
    /// protocols (Vision padding) use 2-byte content length fields.
    static let tcpMaxCoalesceSize = Int(UInt16.max)
    /// Safety cap on per-connection `pendingData` (bytes accumulated while the
    /// sniff phase runs or the proxy is dialing). Bounded naturally by TCP_WND
    /// (~696 KB) since we defer `tcp_recved` until the route is committed;
    /// this cap defends against pathological states where the window bookkeeping
    /// drifts. Set to 2 × TCP_WND so it only fires on runaway growth.
    static let tcpMaxPendingDataSize = 2 * 1024 * 1360
    /// Maximum packets handed to a single ``NEPacketTunnelFlow/writePackets``
    /// call. Each call is forwarded to utun as a sequence of `write(2)` syscalls;
    /// when the batch outruns utun's input queue the kernel drops the tail with
    /// ENOSPC ("User Tunnel write error: No space left on device"). Capping the
    /// batch keeps each call inside the queue and lets the queue-hop between
    /// successive flushes give utun time to drain.
    static let tunnelMaxPacketsPerWrite = 64

    /// Low-water mark for the per-connection downlink backlog (`pendingWrite`).
    /// When the backlog drops below this we prefetch the next proxy receive in
    /// parallel with the ongoing drain — without this overlap, big chunks turn
    /// the downlink into stop-and-wait and throughput collapses. Sized at half
    /// TCP_SND_BUF (lwipopts.h) so a prefetched chunk still fits in lwIP's send
    /// buffer once space frees up, without letting the backlog balloon past a
    /// full send-buffer worth of bytes.
    static let drainLowWaterMark = 512 * 1360

    // MARK: - UDP Settings

    /// Maximum buffer size for queued UDP datagrams.
    static let udpMaxBufferSize = 256 * 1024
    /// Idle timeout for UDP flows (seconds).
    static let udpIdleTimeout: CFAbsoluteTime = 60

    // MARK: - Log Buffer

    /// Retention interval for log entries (seconds).
    static let logRetentionInterval: CFAbsoluteTime = 300
    /// Maximum number of log entries in the buffer.
    static let logMaxEntries = 50
    /// Time window (seconds) to attribute connection errors to a recent tunnel interruption.
    static let recentTunnelInterruptionWindow: CFAbsoluteTime = 8

    // MARK: - Timer Intervals

    /// lwIP periodic timeout interval (milliseconds).
    /// MUST equal `TCP_TMR_INTERVAL` in `port/lwipopts.h` — `sys_check_timeouts`
    /// only fires `tcp_tmr` every `TCP_TMR_INTERVAL` internally, so the dispatch
    /// source has to wake at least that often or RTO/persist/MSL granularity
    /// regresses to whichever is coarser.
    static let lwipTimeoutIntervalMs = 100
    /// UDP flow cleanup timer interval (seconds).
    static let udpCleanupIntervalSec = 1
    /// Retry delay when TCP overflow drain makes no progress (milliseconds).
    static let drainRetryDelayMs = 250

    // MARK: - Stack Lifecycle

    /// Minimum interval between stack restarts (seconds).
    /// 2s absorbs bursts where a path update and a settings/routing notification arrive
    /// back-to-back (e.g., user toggling a setting while Wi-Fi is handing off).
    static let restartThrottleInterval: CFAbsoluteTime = 2.0

    // MARK: - TLS Sniffer

    /// Maximum bytes buffered while parsing a TLS ClientHello for SNI.
    /// Typical ClientHellos fit in under 2 KB; post-quantum key shares push
    /// that to ~4 KB. 8 KB is a safe ceiling that still bounds memory.
    static let tlsSnifferBufferLimit = 8192

    // MARK: - Fake-IP Pool

    /// Base IPv4 address for the fake-IP pool (198.18.0.0 in 198.18.0.0/15).
    static let fakeIPPoolBaseIPv4: UInt32 = 0xC612_0000
    /// Usable offsets in the fake-IP pool. Bounds the three backing
    /// dictionaries (~200 B per entry × 3 maps) in a long-running tunnel.
    static let fakeIPPoolSize = 16_384

}
