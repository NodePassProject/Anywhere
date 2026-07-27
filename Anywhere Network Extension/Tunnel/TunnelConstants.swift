//
//  TunnelConstants.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

nonisolated enum TunnelConstants {

    // MARK: - Tunnel Addresses

    /// The tunnel's IPv4 interface/peer address; also the in-tunnel DNS
    /// resolver apps are told to use. Shared by the provider's network
    /// settings and the UDP/53 interception table.
    static let tunnelAddressIPv4 = "10.8.0.1"
    /// The tunnel's IPv6 interface address and in-tunnel DNS resolver,
    /// advertised only when IPv6 is enabled.
    static let tunnelAddressIPv6 = "fd00::1"

    // MARK: - Connection Timeouts

    /// Inactivity timeout for TCP connections.
    static let connectionIdleTimeout: TimeInterval = 300
    /// Stall bound for TCPConnection's drain-before-close flush.
    static let drainBeforeCloseTimeout: TimeInterval = 5
    /// Timeout for the entire connection setup phase.
    static let handshakeTimeout: TimeInterval = 10
    /// Max wait for a TLS ClientHello before falling back to IP-based routing,
    /// so server-speaks-first protocols (SSH, SMTP, FTP) don't stall.
    static let sniffDeadline: TimeInterval = 0.5

    // MARK: - TCP Buffer Sizes

    /// One lwIP window: mirrors `TCP_WND`/`TCP_SND_BUF` in `port/lwipopts.h`.
    static let tcpWindowSize = 64 * 1460
    /// Max bytes per `tcp_write` call: lwIP's `len` is `u16_t`.
    static let tcpMaxWriteSize = Int(UInt16.max)
    /// Safety cap on per-connection pendingData.
    static let tcpMaxPendingDataSize = 2 * tcpWindowSize

    /// Downlink backlog watermark.
    static let drainLowWaterMark = 2 * tcpWindowSize

    // MARK: - UDP Settings

    static let udpMaxBufferSize = 256 * 1024
    static let udpPendingResolutionMaxBytes = 32 * 1024
    /// Idle timeout for unreplied UDP flows; mirrors Linux conntrack's `nf_conntrack_udp_timeout` (30s) so probe storms are reaped fast.
    static let udpIdleTimeoutUnreplied: TimeInterval = 30
    /// Idle timeout for established UDP flows; matches Linux conntrack's `nf_conntrack_udp_timeout_stream` (120s).
    static let udpIdleTimeoutStream: TimeInterval = 120
    /// Downlink datagrams before a flow earns the longer stream timeout; one
    /// reply is not enough since STUN and one-shot DNS get exactly one answer.
    static let udpStreamMinReplies = 4

    // MARK: - Log Buffer

    static let logRetentionInterval: CFAbsoluteTime = 300
    static let logMaxEntries = 50
    /// Time window (seconds) to attribute connection errors to a recent tunnel interruption.
    static let recentTunnelInterruptionWindow: CFAbsoluteTime = 8

    // MARK: - Request Log

    /// Matches the log buffer's retention window.
    static let requestLogRetentionInterval: CFAbsoluteTime = 300
    static let requestLogMaxEntries = 50

    // MARK: - Timer Intervals

    /// lwIP tick interval (ms); must equal `TCP_TMR_INTERVAL` in `port/lwipopts.h`.
    static let lwipTimeoutIntervalMs = 100
    /// Leeway for the lwIP tick (ms); lets libdispatch coalesce wakeups.
    static let lwipTimeoutLeewayMs = 10
    static let udpCleanupIntervalSec = 1
    /// Leeway for the UDP cleanup reaper (ms); reaping tolerates the slack.
    static let udpCleanupLeewayMs = 250
    /// Retry delay when TCP overflow drain makes no progress.
    static let drainRetryDelayMs = 250

    // MARK: - Stack Lifecycle

    /// Minimum interval between stack restarts; 2s absorbs back-to-back path and settings notifications.
    static let restartThrottleInterval: CFAbsoluteTime = 2.0

    // MARK: - TLS Sniffer

    /// Max bytes buffered while parsing a ClientHello for SNI; post-quantum key shares push ~4 KB.
    static let tlsSnifferBufferLimit = 8192

    // MARK: - HTTP Sniffer

    /// Max bytes buffered while parsing a cleartext HTTP request head.
    static let httpSnifferBufferLimit = 64 * 1024

    // MARK: - Fake-IP Pool

    /// Base IPv4 address for the fake-IP pool (198.18.0.0 in 198.18.0.0/15).
    static let fakeIPPoolBaseIPv4: UInt32 = 0xC612_0000
    /// Usable offsets in the fake-IP pool; bounds the backing maps in a long-running tunnel.
    static let fakeIPPoolSize = 16_384
}
