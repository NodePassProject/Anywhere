//
//  TunnelConstants.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

enum TunnelConstants {

    // MARK: - Connection Timeouts

    /// Inactivity timeout for TCP connections (default 300s).
    static let connectionIdleTimeout: TimeInterval = 300
    /// Timeout after uplink (local → remote) finishes (default 1s).
    static let downlinkOnlyTimeout: TimeInterval = 1
    /// Timeout after downlink (remote → local) finishes (default 1s).
    static let uplinkOnlyTimeout: TimeInterval = 1
    /// Timeout for the entire connection setup phase (60s).
    static let handshakeTimeout: TimeInterval = 60
    /// Max wait for a TLS ClientHello before falling back to IP-based routing,
    /// so server-speaks-first protocols (SSH, SMTP, FTP) don't stall.
    static let sniffDeadline: TimeInterval = 0.5

    // MARK: - TCP Buffer Sizes

    /// Max bytes per tcp_write call (16 KB ≈ 12 segments at TCP_MSS=1360); must stay in sync with lwipopts.h.
    static let tcpMaxWriteSize = 16 * 1024
    /// Max bytes per upload send; UInt16.max stays safe for protocols with 2-byte length framing (e.g. Vision padding).
    static let uploadChunkSize = Int(UInt16.max)
    /// Safety cap on per-connection pendingData; 2 × TCP_WND so it only fires on runaway bookkeeping drift.
    static let tcpMaxPendingDataSize = 2 * 1024 * 1360
    /// Max packets per writePackets call; 128 is the empirical utun ceiling (256 trips ENOSPC).
    static let tunnelMaxPacketsPerWrite = 128

    /// Downlink backlog low-water mark below which the next proxy receive is prefetched
    /// (otherwise downlink degrades to stop-and-wait); half TCP_SND_BUF (lwipopts.h).
    static let drainLowWaterMark = 512 * 1360

    // MARK: - UDP Settings

    /// Maximum buffer size for queued UDP datagrams.
    static let udpMaxBufferSize = 256 * 1024
    /// Idle timeout for unreplied UDP flows; mirrors Linux conntrack's `nf_conntrack_udp_timeout` (30s) so probe storms are reaped fast.
    static let udpIdleTimeoutUnreplied: TimeInterval = 30
    /// Idle timeout for established UDP flows; matches Linux conntrack's `nf_conntrack_udp_timeout_stream` (120s).
    static let udpIdleTimeoutStream: TimeInterval = 120
    /// Downlink datagrams before a flow earns the longer stream timeout; one
    /// reply is not enough since STUN and one-shot DNS get exactly one answer.
    static let udpStreamMinReplies = 4
    /// Hard ceiling on concurrent UDP flows; each pins a socket plus a 64 KB
    /// buffer, and an uncapped probe storm can get the extension jetsam-killed.
    static let udpMaxFlows = 256

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
    /// Retry delay when TCP overflow drain makes no progress (milliseconds).
    static let drainRetryDelayMs = 250

    // MARK: - Stack Lifecycle

    /// Minimum interval between stack restarts; 2s absorbs back-to-back path and settings notifications.
    static let restartThrottleInterval: CFAbsoluteTime = 2.0

    /// Debounce for path-change recovery; collapses the NWPath update burst from a Wi-Fi⇄cellular handoff.
    static let networkRecoveryDebounceInterval: CFAbsoluteTime = 0.4

    // MARK: - TLS Sniffer

    /// Max bytes buffered while parsing a ClientHello for SNI; post-quantum key shares push ~4 KB.
    static let tlsSnifferBufferLimit = 8192

    // MARK: - Fake-IP Pool

    /// Base IPv4 address for the fake-IP pool (198.18.0.0 in 198.18.0.0/15).
    static let fakeIPPoolBaseIPv4: UInt32 = 0xC612_0000
    /// Usable offsets in the fake-IP pool; bounds the backing maps in a long-running tunnel.
    static let fakeIPPoolSize = 16_384

    // MARK: - DNS

    /// Public upstream resolvers for queries Anywhere cannot answer locally; must be reachable public IPs.
    static func fallbackDNSServers(includeIPv6: Bool) -> [String] {
        includeIPv6
            ? ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
            : ["1.1.1.1", "1.0.0.1"]
    }
}
