//
//  TunnelConstants.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
//

import Foundation

enum TunnelConstants {

    // MARK: - Tunnel Network Settings

    /// Remote address for the TUN interface.
    static let tunnelRemoteAddress = "10.8.0.1"
    /// Local IPv4 address assigned to the TUN interface.
    static let tunnelLocalIPv4Address = "10.8.0.2"
    /// Subnet mask for the TUN IPv4 address.
    static let tunnelSubnetMask = "255.255.255.0"
    /// Local IPv6 address assigned to the TUN interface (when IPv6 is enabled).
    static let tunnelLocalIPv6Address = "fd00::2"
    /// Prefix length for the TUN IPv6 address.
    static let tunnelIPv6PrefixLength: NSNumber = 64
    /// Maximum transmission unit for the TUN interface.
    static let tunnelMTU: NSNumber = 1400

    // MARK: - DNS Servers

    /// IPv4 DNS servers (Cloudflare).
    static let dnsServersIPv4 = ["1.1.1.1", "1.0.0.1"]
    /// IPv6 DNS servers (Cloudflare).
    static let dnsServersIPv6 = ["2606:4700:4700::1111", "2606:4700:4700::1001"]

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
    static let tcpMaxPendingDataSize = 2 * 512 * 1360
    /// Low-water mark for the per-connection downlink backlog (`pendingWrite`).
    /// When the backlog drops below this we prefetch the next proxy receive in
    /// parallel with the ongoing drain — without this overlap, big chunks turn
    /// the downlink into stop-and-wait and throughput collapses. Sized to match
    /// TCP_SND_BUF in lwipopts.h so a prefetched chunk can be pushed into lwIP
    /// the moment space frees up.
    static let drainLowWaterMark = 512 * 1360

    // MARK: - UDP Settings

    /// Maximum buffer size for queued UDP datagrams.
    static let udpMaxBufferSize = 16 * 1024
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
    static let lwipTimeoutIntervalMs = 250
    /// UDP flow cleanup timer interval (seconds).
    static let udpCleanupIntervalSec = 1
    /// Retry delay when TCP overflow drain makes no progress (milliseconds).
    static let drainRetryDelayMs = 250

    // MARK: - Stack Lifecycle

    /// Minimum sleep duration (seconds) before proactively restarting the stack on wake.
    /// Short sleeps leave TCP connections intact — they likely survive.
    /// Long sleeps almost certainly leave dead proxy connections behind,
    /// so we restart immediately instead of waiting for keepalive timeouts.
    static let wakeRestartThreshold: CFAbsoluteTime = 60

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
