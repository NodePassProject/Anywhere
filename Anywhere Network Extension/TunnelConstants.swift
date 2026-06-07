//
//  TunnelConstants.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
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
    /// Maximum bytes per upload `proxyConnection.send` call. Caps the slice
    /// size when the upload pipeline drains a backlog so the initial
    /// pendingData burst (commonly 1+ MB on TLS uploads) ships as a sequence
    /// of bounded chunks rather than as one giant send whose completion
    /// gates every subsequent ack. Sized at UInt16.max to stay safe for
    /// downstream protocols whose framing uses 2-byte content-length fields
    /// (e.g. Vision padding).
    static let uploadChunkSize = Int(UInt16.max)
    /// Safety cap on per-connection `pendingData` (bytes accumulated while the
    /// sniff phase runs or the proxy is dialing). Bounded naturally by TCP_WND
    /// (~696 KB) since we defer `tcp_recved` until the route is committed;
    /// this cap defends against pathological states where the window bookkeeping
    /// drifts. Set to 2 × TCP_WND so it only fires on runaway growth.
    static let tcpMaxPendingDataSize = 2 * 1024 * 1360
    /// Maximum packets handed to a single ``NEPacketTunnelFlow/writePackets``
    /// call. Each call is forwarded to utun as a sequence of `write(2)` syscalls;
    /// when the batch outruns utun's input queue the kernel drops the tail with
    /// ENOSPC ("User Tunnel write error: No space left on device"). 128 is the
    /// empirical safe ceiling on iOS — 256 trips ENOSPC and induces lwIP
    /// per-PCB queue saturation because the dropped ACKs never reach the peer.
    /// The drain loop issues back-to-back calls at this cap until the buffer
    /// is empty, so the cap controls per-call ENOSPC risk but not throughput.
    static let tunnelMaxPacketsPerWrite = 128

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
    /// Idle timeout for UDP flows that have **not** yet seen a reply from the
    /// destination — one-way/speculative flows (NAT-traversal probes, scans,
    /// abandoned sends). Mirrors Linux conntrack's `nf_conntrack_udp_timeout`
    /// (30s default): a flow that never gets a packet back is reaped fast so a
    /// probe storm can't pin sockets and receive buffers for the full
    /// established window. The reaper and the global-cap eviction both treat
    /// these as the first to go (see ``UDPFlow/idleDeadline``).
    static let udpIdleTimeoutUnreplied: CFAbsoluteTime = 30
    /// Idle timeout for UDP flows that have seen at least one reply — an
    /// established bidirectional flow. Matches Linux conntrack's
    /// `nf_conntrack_udp_timeout_stream` default (120s): long enough that a
    /// paused-but-live flow — a game session, a long-poll — isn't torn down
    /// prematurely, while still freeing a genuinely dead established flow far
    /// sooner than the old 300s window did.
    static let udpIdleTimeoutStream: CFAbsoluteTime = 120
    /// Hard ceiling on concurrent UDP flows in ``TunnelStack/udpFlows``.
    ///
    /// Each live flow pins a socket (kernel send/receive buffers) plus a 64 KB
    /// in-process receive buffer. Without a ceiling, an app spraying UDP
    /// NAT-traversal probes on a lossy link (common with P2P remote-desktop
    /// tools) could pile up flows faster than they idle out and push the
    /// Network Extension past its hard memory limit, getting it jetsam-killed.
    ///
    /// Two mechanisms keep that storm bounded without a per-destination cap.
    /// First, an unreplied probe idles out after only
    /// ``udpIdleTimeoutUnreplied`` (30s), so one-way flows self-shed an order of
    /// magnitude faster than established ones. Second, when the table is
    /// nonetheless full, the flow with the least time left before its own idle
    /// deadline is evicted to admit a new one (see
    /// ``TunnelStack/evictUDPFlowsToAdmit()``) — which preferentially sheds
    /// those same short-lived probes before any flow an app is actively using.
    /// 256 sits far above any legitimate app's working set while bounding the
    /// data plane's footprint.
    static let udpMaxFlows = 256

    // MARK: - Log Buffer

    /// Retention interval for log entries (seconds).
    static let logRetentionInterval: CFAbsoluteTime = 300
    /// Maximum number of log entries in the buffer.
    static let logMaxEntries = 50
    /// Time window (seconds) to attribute connection errors to a recent tunnel interruption.
    static let recentTunnelInterruptionWindow: CFAbsoluteTime = 8

    // MARK: - Request Log

    /// Retention interval for request log entries (seconds). Matches the
    /// log buffer's window so "recent" has the same meaning across both
    /// diagnostics views.
    static let requestLogRetentionInterval: CFAbsoluteTime = 300
    /// Maximum number of request log entries in the buffer.
    static let requestLogMaxEntries = 50

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

    /// Debounce window for network-path-change recovery (seconds).
    /// A real Wi-Fi⇄cellular handoff emits several NWPath updates within a
    /// second or two; this collapses the burst into a single recovery while
    /// still reacting to the leading edge immediately. Kept far shorter than
    /// ``restartThrottleInterval`` because path-change recovery is now a
    /// lightweight outbound-state invalidation (no netif/listener rebuild),
    /// so reacting promptly costs little and stale connections otherwise sit
    /// on a dead path until protocol idle timeouts (30–300s) fire.
    static let networkRecoveryDebounceInterval: CFAbsoluteTime = 0.4

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

    // MARK: - DNS

    /// Cloudflare public resolvers, used as the real upstream for queries
    /// Anywhere cannot answer locally. The OS (or the tunnel) opens a real
    /// connection to these IPs, so they must be reachable public resolvers —
    /// internal tunnel addresses would not work. Two callers share them:
    ///
    /// - Encrypted-DNS fallback when the user's DoH/DoT hostname fails to
    ///   resolve at tunnel start (``PacketTunnelProvider``).
    /// - Non-A/AAAA queries (SRV/MX/TXT/…) sent to the Anywhere resolver,
    ///   which has no upstream behind the tunnel peer address and so must
    ///   forward them here rather than answer NODATA locally.
    ///
    /// The IPv6 resolvers are appended only when IPv6 is advertised to apps.
    static func fallbackDNSServers(includeIPv6: Bool) -> [String] {
        includeIPv6
            ? ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
            : ["1.1.1.1", "1.0.0.1"]
    }

}
