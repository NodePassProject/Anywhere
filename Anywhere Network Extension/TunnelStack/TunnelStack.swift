//
//  TunnelStack.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation
import NetworkExtension

private let logger = AnywhereLogger(category: "TunnelStack")

// MARK: - Traffic Accounting

/// Per-route cumulative payload byte counts for one tunnel session, keyed by
/// ``RouteTarget`` — direct and each proxy/chain get their own bucket. Reject
/// carries no payload, so it never appears. The Upload/Download totals are the
/// sum across every route, so the UI's headline cards and the per-route
/// breakdown always reconcile.
struct TrafficByteCounts {
    struct ByteCounts: Sendable {
        var bytesIn: Int64 = 0
        var bytesOut: Int64 = 0
    }

    var routes: [RouteTarget: ByteCounts] = [:]

    var totalBytesIn: Int64 { routes.values.reduce(0) { $0 + $1.bytesIn } }
    var totalBytesOut: Int64 { routes.values.reduce(0) { $0 + $1.bytesOut } }

    mutating func add(bytesIn n: Int64, target: RouteTarget) {
        routes[target, default: ByteCounts()].bytesIn += n
    }

    mutating func add(bytesOut n: Int64, target: RouteTarget) {
        routes[target, default: ByteCounts()].bytesOut += n
    }
}

// MARK: - TunnelStack

/// Main coordinator for the tunnel's data plane.
///
/// One instance per Network Extension process, accessible via ``shared``.
/// Reads IP packets from the tunnel's `NEPacketTunnelFlow` and splits them
/// across two serial data planes:
///
/// - **TCP/ICMP** → ``lwipQueue``, fed into the vendored lwIP stack (which is
///   not thread-safe, hence the single serial queue).
/// - **UDP** → ``udpQueue``. lwIP is built TCP-only (`LWIP_UDP 0`), so UDP is
///   parsed, routed, NATed, and proxied entirely in Swift (``UDPPacket`` /
///   ``UDPFlow`` / `TunnelStack+UDP`) without ever entering lwIP — and so
///   without contending on ``lwipQueue``.
///
/// Both planes dispatch resulting connections through proxy clients and write
/// responses back to the packet flow via the shared, lock-guarded output buffer.
class TunnelStack {

    // MARK: Properties

    /// Serial queue for all lwIP operations (lwIP is not thread-safe).
    /// `.userInitiated` because lwIP is the TCP data-plane hub every proxied TCP
    /// flow traverses; left at the default QoS it floats below the proxy-protocol
    /// queues that feed and drain it (QUIC, the raw sockets, Sudoku — all
    /// `.userInitiated`), so under load the scheduler starves the consumer
    /// behind its own producers. Keeping the whole chain at one priority avoids
    /// that inversion. UDP runs on its own ``udpQueue`` (below).
    let lwipQueue = DispatchQueue(label: AWCore.Identifier.lwipQueue, qos: .userInitiated)

    /// Serial queue owning the entire UDP data plane — ``udpFlows``,
    /// ``ssUDPSessions``, ``muxManager``, and every per-flow send/receive.
    /// UDP is built TCP-free in lwIP (`LWIP_UDP 0`), so it has no reason to
    /// share ``lwipQueue``; giving it its own queue stops UDP datagrams (QUIC,
    /// DNS, games) from queueing head-of-line behind TCP/lwIP work and vice
    /// versa. `.userInitiated` matches ``lwipQueue`` so neither data plane is
    /// scheduled below the proxy-protocol queues that feed and drain it.
    ///
    /// The cold "new flow" path reads shared routing/config state that
    /// ``lwipQueue`` mutates at start/restart; that state is made safe for
    /// cross-queue reads via ``udpConfig()`` (snapshot) and the internal locks
    /// in ``DomainRouter`` / ``MITMRewritePolicy``. Output (``enqueueOutbound``)
    /// is already lock-guarded and callable from here.
    let udpQueue = DispatchQueue(label: AWCore.Identifier.udpQueue, qos: .userInitiated)

    /// Queue for writing packets back to the tunnel. `.userInitiated` to match
    /// `lwipQueue` — this is the final hop delivering received bytes to the OS.
    let outputQueue = DispatchQueue(label: AWCore.Identifier.outputQueue, qos: .userInitiated)

    var packetFlow: NEPacketTunnelFlow?
    var configuration: ProxyConfiguration?

    /// Identity of the default outbound (connections that match no routing rule)
    /// for the active configuration. Derived from the app's persisted selection
    /// so a selected chain resolves to its stable chain id rather than the
    /// composite's throwaway id. Recomputed in ``configureRuntime`` on every
    /// start/switch. Reset/overwritten before any connection is accepted.
    var defaultRouteTarget: RouteTarget = .direct

    static let ipv4Proto = NSNumber(value: AF_INET)
    static let ipv6Proto = NSNumber(value: AF_INET6)

    /// Guards ``outputPackets``, ``outputProtocols``, ``pendingReleases``,
    /// and ``outputDrainInFlight``. Held briefly during appends from lwIP
    /// output callbacks on ``lwipQueue`` and during batch pulls by the drain
    /// loop on ``outputQueue``. `UnfairLock` keeps the per-packet append
    /// cost in the tens of nanoseconds.
    let outputBufferLock = UnfairLock()
    /// Pending IP packets to ship to utun. Protected by ``outputBufferLock``.
    var outputPackets: [Data] = []
    /// Per-packet protocol family (AF_INET / AF_INET6). Protected by ``outputBufferLock``.
    var outputProtocols: [NSNumber] = []
    /// Owning references to the pbufs / heap buffers backing the queued
    /// output packets, kept in lockstep with ``outputPackets``. The per-packet
    /// ``Data`` uses a `.none` deallocator; this list is the actual owner.
    /// ``drainOutputLoop`` swaps it out together with the packet batch and
    /// fires every release in a single ``lwipQueue.async`` per iteration.
    /// Protected by ``outputBufferLock``.
    var pendingReleases: [PendingRelease] = []
    /// True while a drain loop is running on ``outputQueue``. lwIP callbacks
    /// only dispatch a new loop when this is false. Protected by ``outputBufferLock``.
    var outputDrainInFlight = false

    /// ``fn(ctx)`` must run on ``lwipQueue``: `pbuf_free` and `mem_free`
    /// mutate per-pool freelists with no locking under NO_SYS=1.
    struct PendingRelease {
        let ctx: UnsafeMutableRawPointer?
        let fn: @convention(c) (UnsafeMutableRawPointer?) -> Void
    }

    /// Release placeholder for Swift-owned output packets (UDP responses, ICMP
    /// unreachables) that have no lwIP pbuf/heap buffer behind them. Appended
    /// alongside such packets so ``pendingReleases`` stays index-aligned with
    /// ``outputPackets`` — ``drainOutputLoop``'s prefix/removeFirst pulls all
    /// three arrays in lockstep and would desync (or crash on `removeFirst`) if
    /// a release entry were ever omitted.
    static let noopRelease = PendingRelease(ctx: nil, fn: { _ in })

    // --- Settings (read from App Group UserDefaults) ---
    // These are loaded at start/restart and live-reloaded via Darwin notification.
    //
    // Setting                 │ Where it takes effect               │ On change
    // ────────────────────────┼─────────────────────────────────────┼──────────────────────────────
    // bypassCountryEnabled    │ DomainRouter bypass rules gate      │ Stack restart
    // advertiseIPv6ToApps     │ lwIP DNS interception (AAAA fake IP)│ Stack restart
    // encryptedDNSEnabled     │ lwIP DNS interception (DDR block),  │ Reapply tunnel settings +
    //                         │ tunnel DNS settings (DoH/DoT)       │ stack restart
    // routingRules            │ DomainRouter (connection-time)      │ Stack restart (closes connections
    //                         │                                     │ using outdated proxy configurations;
    //                         │                                     │ FakeIPPool preserved)
    var proxyMode: ProxyMode = .rule
    var hideVPNIcon: Bool = false
    var quicPolicy: QUICPolicy = .blocked
    var blockWebRTC: Bool = true
    var advertiseIPv6ToApps: Bool = false
    var encryptedDNSEnabled: Bool = false
    var encryptedDNSProtocol: String = "doh"
    var encryptedDNSServer: String = ""

    // Reflection: packets to these addresses are reflected back to their source
    // instead of routed/proxied (see ``TunnelStack+Reflection``). Read on
    // ``lwipQueue``, then published as the ``reflector()`` snapshot the read
    // callback consumes. Live-reloaded in place — no restart.
    var reflectionEnabled: Bool = false
    var reflectionAddresses: [String] = []

    // MARK: MITM
    //
    // MITM state lives beside routing state: routing selects the upstream
    // proxy, while MITM decides whether to intercept TLS in transit.
    // With the master toggle off or no compiled rules, the connection path
    // stays unchanged.
    var mitmEnabled: Bool = false
    let mitmPolicy = MITMRewritePolicy()
    /// Lazily-created leaf certificate cache. Defers keychain access until a
    /// MITM session needs a leaf certificate.
    var mitmLeafCache: MITMLeafCertCache?
    let mitmCertificateStore = MITMCertificateStore()
    /// Cross-session memory of HTTP/1.1-only upstreams, so the inner TLS leg
    /// stops offering `h2` to origins that can't bridge it. Cheap and
    /// keychain-free, so created eagerly (unlike ``mitmLeafCache``).
    let mitmOriginCapabilities = MITMOriginCapabilityCache()
    
    var running = false

    /// True while a deliberate full-stack TCP teardown is in progress (stack
    /// shutdown or restart). Set around the ``lwip_bridge_abort_all_tcp`` call
    /// in ``shutdownInternal`` so ``TCPConnection.handleError`` can demote
    /// the resulting ERR_ABRT flood to debug — while still surfacing lwIP's own
    /// internal aborts (e.g., `tcp_kill_prio` under PCB pool exhaustion) as
    /// warnings. Network-path-change and wake recovery close gracefully (no
    /// ERR_ABRT), so they don't set this.
    var isTearingDown = false

    /// Timestamp of the last completed stack restart (used for throttling).
    var lastRestartTime: CFAbsoluteTime = 0

    /// Pending deferred restart when throttled. Cancelled and replaced on each new request.
    var deferredRestart: DispatchWorkItem?

    /// Timestamp of the last network-path-change recovery (used for debouncing).
    var lastNetworkRecoveryTime: CFAbsoluteTime = 0

    /// Pending debounced network recovery. Cancelled and replaced on each new
    /// path update that lands inside the debounce window.
    var pendingNetworkRecovery: DispatchWorkItem?

    /// lwIP periodic timeout timer
    var timeoutTimer: DispatchSourceTimer?

    /// True while ``timeoutTimer`` is suspended because lwIP reported no pending
    /// timeouts (idle tunnel). The tick re-arms from the inbound-TCP path
    /// (``feedLwip``). Confined to ``lwipQueue`` — set only in the tick handler,
    /// ``feedLwip``, and ``shutdownInternal``, all of which run there — so it
    /// faithfully tracks the source's suspend count, keeping suspend/resume
    /// balanced (releasing a suspended `DispatchSource` traps).
    var lwipTickSuspended = false

    /// Active bypass country code (empty = disabled).
    /// Used to gate DomainRouter bypass flags and detect settings changes.
    var bypassCountryCode: String = ""

    /// Per-target traffic counters (payload bytes through the tunnel), split by
    /// routing target (per individual proxy, plus direct) so the UI can render a
    /// per-route breakdown and a pie chart. Tallied at the connection/flow
    /// layer, where the routing target is known — ``TCPConnection`` (``writeToLWIP`` /
    /// ``acknowledgeReceivedBytes``) and ``UDPFlow`` (``handleProxyData`` /
    /// ``handleReceivedData``) — rather than at the netif, which sees only
    /// target-agnostic IP packets. These are therefore payload bytes, not wire
    /// bytes: TCP/IP headers, ACKs, retransmits, and locally-synthesized DNS
    /// responses are excluded. Rejected connections carry no payload and are
    /// intentionally not recorded.
    ///
    /// Incremented from ``lwipQueue`` (TCP) and ``udpQueue`` (UDP) and read from
    /// the NE message handler — so every access goes through ``countersLock``.
    /// With both data-plane queues writing, an unlocked `+=` could drop
    /// increments; the critical section is a single add, so the per-chunk cost
    /// stays in the tens of nanoseconds (the lock is all but uncontended) while
    /// keeping the UI totals exact.
    private let countersLock = UnfairLock()
    private var _byteCounts = TrafficByteCounts()
    func addBytesIn(_ n: Int64, target: RouteTarget) {
        countersLock.withLock { _byteCounts.add(bytesIn: n, target: target) }
    }
    func addBytesOut(_ n: Int64, target: RouteTarget) {
        countersLock.withLock { _byteCounts.add(bytesOut: n, target: target) }
    }
    /// Snapshot of all per-target counters, read once per stats poll.
    var byteCounts: TrafficByteCounts { countersLock.withLock { _byteCounts } }

    // MARK: - Live Connection Counts
    //
    // Point-in-time snapshots for the 1 Hz stats poll. Each hops onto the queue
    // that owns the underlying state so the count is consistent with the data
    // plane instead of racing it. Both are read from the IPC message handler,
    // which runs on neither queue, so `.sync` can't deadlock.

    /// Active TCP connections: lwIP's ``tcp_active_pcbs`` list (established,
    /// connecting, and closing legs; LISTEN and TIME_WAIT excluded). Read on
    /// ``lwipQueue`` — the only queue allowed to touch lwIP state.
    var activeTCPConnections: Int {
        lwipQueue.sync { Int(lwip_bridge_active_tcp_count()) }
    }

    /// Active UDP flows. Read on ``udpQueue``, which owns ``udpFlows``.
    var activeUDPConnections: Int {
        udpQueue.sync { udpFlows.count }
    }

    // MARK: - Log Buffer
    //
    // Stores recent log messages for display in the main app's log viewer.
    // Entries older than 5 minutes or exceeding 50 items are pruned on
    // each append or fetch.
    // Thread-safe via NSLock — logs may be appended from I/O completion
    // handlers off lwipQueue, while fetches come from IPC.

    typealias LogLevel = TunnelLogLevel
    typealias LogEntry = TunnelLogEntry

    struct RecentTunnelInterruption {
        let timestamp: CFAbsoluteTime
        let level: LogLevel
        let summary: String
    }

    private let logLock = NSLock()
    private var logEntries: [LogEntry] = []

    /// Appends a log message to the buffer. Thread-safe.
    func appendLog(_ message: String, level: LogLevel) {
        let now = CFAbsoluteTimeGetCurrent()
        logLock.lock()
        logEntries.append(LogEntry(timestamp: now, level: level, message: message))
        compactLogs(now: now)
        logLock.unlock()
    }

    /// Returns all log entries within the retention window.
    func fetchLogs() -> [LogEntry] {
        let now = CFAbsoluteTimeGetCurrent()
        logLock.lock()
        compactLogs(now: now)
        let result = logEntries
        logLock.unlock()
        return result
    }

    /// Removes entries older than the retention window, then trims the oldest
    /// entries if the buffer still exceeds `logMaxEntries`. Caller must hold `logLock`.
    private func compactLogs(now: CFAbsoluteTime) {
        let cutoff = now - TunnelConstants.logRetentionInterval
        logEntries.removeAll { $0.timestamp < cutoff }
        if logEntries.count > TunnelConstants.logMaxEntries {
            logEntries.removeFirst(logEntries.count - TunnelConstants.logMaxEntries)
        }
    }

    /// Mux manager for multiplexing UDP flows (created when Vision flow is
    /// active). Owned by ``udpQueue`` — created, used, and torn down there —
    /// since mux carries UDP only. Lifecycle code mutates it via a hop onto
    /// ``udpQueue``.
    var muxManager: MuxManager?

    // MARK: - UDP Config Snapshot
    //
    // The UDP cold path (new-flow routing, DNS interception) runs on
    // ``udpQueue`` but needs config that ``lwipQueue`` owns and mutates at
    // start/restart (and, for ``quicPolicy``, on a live in-place reload). Rather
    // than read those stored properties cross-queue — an ARC data race on
    // ``configuration`` and torn reads on the scalars — ``lwipQueue`` publishes
    // an immutable value snapshot under ``udpConfigLock`` whenever any of them
    // changes, and the UDP path reads it once per datagram via ``udpConfig()``.
    // Routing tables (``domainRouter`` / ``mitmPolicy``) aren't snapshotted —
    // they're large and have their own internal reload-vs-read locks.

    /// Immutable view of the config the UDP path needs, published on change.
    struct UDPConfig {
        let configuration: ProxyConfiguration?
        /// `configuration?.id`, precomputed so the mux "is this the default
        /// configuration?" check needs no cross-queue read of ``configuration``.
        let configurationID: UUID?
        let quicPolicy: QUICPolicy
        /// Whether STUN datagrams are rejected to block WebRTC (default on).
        let blockWebRTC: Bool
        let advertiseIPv6ToApps: Bool
        let mitmEnabled: Bool
    }
    private let udpConfigLock = UnfairLock()
    private var _udpConfig = UDPConfig(configuration: nil, configurationID: nil,
                                       quicPolicy: .blocked, blockWebRTC: true,
                                       advertiseIPv6ToApps: false, mitmEnabled: false)

    /// Reads the current UDP config snapshot. Callable from any queue; the UDP
    /// path calls it once at the top of each inbound datagram.
    func udpConfig() -> UDPConfig { udpConfigLock.withLock { _udpConfig } }

    /// Single source of truth for "does this configuration dial the default
    /// outbound?" Keyed off the published snapshot's `configurationID`, so it is
    /// safe from any queue. The data plane uses it to keep default-proxy-only
    /// behavior pinned to the default proxy — mux (built only here, for the
    /// default) and the live Dial/Handshake stats (see ``ProxyClient/isDefaultProxy``).
    func isDefaultConfiguration(_ id: UUID) -> Bool {
        udpConfig().configurationID == id
    }

    /// Republishes the UDP config snapshot from the current ``lwipQueue``-owned
    /// state. Must be called on ``lwipQueue`` (reads ``configuration`` etc.);
    /// the snapshot it builds is then safe to read from ``udpQueue``.
    func publishUDPConfig() {
        let snapshot = UDPConfig(
            configuration: configuration,
            configurationID: configuration?.id,
            quicPolicy: quicPolicy,
            blockWebRTC: blockWebRTC,
            advertiseIPv6ToApps: advertiseIPv6ToApps,
            mitmEnabled: mitmEnabled
        )
        udpConfigLock.withLock { _udpConfig = snapshot }
    }

    // Reflector snapshot. The packet reader runs on the ``NEPacketTunnelFlow``
    // read-callback thread, while the addresses are (re)loaded on ``lwipQueue``;
    // publishing an immutable value under a lock — read once per inbound batch
    // via ``reflector()`` — avoids a cross-thread race without a per-packet
    // lock. Mirrors ``udpConfig``.
    private let reflectorLock = UnfairLock()
    private var _reflector = Reflector.inactive

    /// Reads the current reflector snapshot. Callable from any queue; the read
    /// loop calls it once at the top of each inbound batch.
    func reflector() -> Reflector { reflectorLock.withLock { _reflector } }

    /// Rebuilds and publishes the reflector from the current ``lwipQueue``-owned
    /// settings. Must be called on ``lwipQueue``.
    func publishReflector() {
        let snapshot = reflectionEnabled ? Reflector(addresses: reflectionAddresses) : .inactive
        reflectorLock.withLock { _reflector = snapshot }
    }

    /// Hashable 5-tuple key for UDP flows. Addresses are held inline as raw
    /// bytes (`SIMD16<UInt8>`, zero-padded; IPv4 in the first 4) so the
    /// per-packet fast-path lookup in ``handleInboundUDP`` allocates nothing —
    /// no `inet_ntop` string, no address `Data`. `isIPv6` disambiguates an IPv4
    /// address from an IPv6 address sharing the same leading bytes.
    struct UDPFlowKey: Hashable, CustomStringConvertible {
        let srcIP: SIMD16<UInt8>
        let srcPort: UInt16
        let dstIP: SIMD16<UInt8>
        let dstPort: UInt16
        let isIPv6: Bool

        var description: String {
            "\(TunnelStack.ipAddrToString(srcIP, isIPv6: isIPv6)):\(srcPort)-\(TunnelStack.ipAddrToString(dstIP, isIPv6: isIPv6)):\(dstPort)"
        }
    }

    /// Active UDP flows keyed by 5-tuple. Owned by ``udpQueue``: every read,
    /// insert, and removal happens there (the inbound fast path, new-flow
    /// creation, cleanup timer, FD-pressure relief, and lifecycle teardown all
    /// run on or sync onto ``udpQueue``).
    var udpFlows: [UDPFlowKey: UDPFlow] = [:]
    var udpCleanupTimer: DispatchSourceTimer?

    /// Rising-edge latch for the flow-cap warning: set when ``udpFlows`` first
    /// reaches ``TunnelConstants/udpMaxFlows`` and eviction begins, cleared by
    /// the cleanup timer once the table drains back below the cap. Keeps a
    /// sustained flow storm from emitting one warning per evicted flow — which
    /// would both flood the bounded log ring and burn CPU. Owned by ``udpQueue``.
    var udpFlowCapWarned = false

    /// Shared Shadowsocks UDP sessions keyed by configuration id. One session
    /// services every UDP flow for a given SS configuration, so all
    /// destinations share a sessionID + upstream socket. Owned by ``udpQueue``.
    var ssUDPSessions: [UUID: ShadowsocksUDPSession] = [:]

    /// Domain-based DNS routing (loaded from App Group routing.json).
    let domainRouter = DomainRouter()

    /// Recent per-connection routing decisions, surfaced in the main
    /// app under Advanced Settings → Requests.
    let requestLog = RequestLog()

    /// Fake-IP pool for mapping domains to synthetic IPs.
    let fakeIPPool = FakeIPPool()

    /// Called when tunnel network settings need to be re-applied via `setTunnelNetworkSettings`.
    /// This resets the virtual interface and flushes the OS DNS cache, forcing apps to re-resolve.
    /// Triggered by: IPv6 toggle (route/DNS changes), routing rule changes (DNS cache flush).
    var onTunnelSettingsNeedReapply: (() -> Void)?

    /// Singleton for C callback access (one NE process = one stack).
    static var shared: TunnelStack?

    // MARK: - Shadowsocks UDP Sessions

    /// Returns the shared SS UDP session for `configuration`, creating one on
    /// first use. Must be called on `udpQueue`.
    ///
    /// The session lives across individual UDP flows so that one sessionID
    /// and one upstream socket serve every destination — which is what
    /// restores full-cone NAT and avoids per-flow session churn. A session
    /// that has reached a terminal (failed/cancelled) state is evicted and
    /// replaced transparently.
    func shadowsocksUDPSession(for configuration: ProxyConfiguration) -> Result<ShadowsocksUDPSession, Error> {
        if let existing = ssUDPSessions[configuration.id], existing.isUsable {
            return .success(existing)
        }
        ssUDPSessions.removeValue(forKey: configuration.id)

        guard case .shadowsocks(let password, let method) = configuration.outbound else {
            return .failure(ProxyError.protocolError("Shadowsocks password not set"))
        }
        guard let cipher = ShadowsocksCipher(method: method) else {
            return .failure(ShadowsocksError.invalidMethod(method))
        }

        let mode: ShadowsocksUDPSession.Mode
        if cipher.isSS2022 {
            guard let pskList = ShadowsocksKeyDerivation.decodePSKList(password: password, keySize: cipher.keySize) else {
                return .failure(ShadowsocksError.invalidPSK)
            }
            if cipher == .blake3chacha20poly1305 {
                mode = .ss2022ChaCha(psk: pskList.last!)
            } else {
                mode = .ss2022AES(cipher: cipher, pskList: pskList)
            }
        } else {
            let masterKey = ShadowsocksKeyDerivation.deriveKey(password: password, keySize: cipher.keySize)
            mode = .legacy(cipher: cipher, masterKey: masterKey)
        }

        let session = ShadowsocksUDPSession(
            mode: mode,
            serverHost: configuration.serverAddress,
            serverPort: configuration.serverPort,
            delegateQueue: udpQueue
        )
        ssUDPSessions[configuration.id] = session
        return .success(session)
    }

    /// Cancels and forgets every SS UDP session. Must be called on `udpQueue`.
    /// Called on stack shutdown, configuration switch, and device wake (the
    /// kernel tears down our UDP sockets during sleep).
    func purgeShadowsocksUDPSessions() {
        for (_, session) in ssUDPSessions {
            session.cancel()
        }
        ssUDPSessions.removeAll()
    }

    // MARK: - Runtime Configuration

    func configureRuntime(for configuration: ProxyConfiguration) {
        // Default-route identity: prefer the app's persisted selection (a chain
        // keeps its stable chain id; a plain config keeps its config id), falling
        // back to the dialing config's id. Never derived from a composited
        // chain's throwaway id, so the app can always resolve the name.
        defaultRouteTarget = AWCore.getSelectedChainId().map(RouteTarget.proxy)
            ?? AWCore.getSelectedConfigurationId().map(RouteTarget.proxy)
            ?? .proxy(configuration.id)

        loadIPv6Settings()
        loadBypassCountry()
        loadEncryptedDNSSetting()
        loadProxyModeSetting()
        loadHideVPNIconSetting()
        loadQUICPolicySetting()
        loadBlockWebRTCSetting()
        loadReflectionSetting()
        loadMITMSetting()

        // Publish the snapshot the UDP data plane reads. `configuration` is set
        // by the caller (start/restart) before configureRuntime; the scalars
        // were just loaded above.
        publishUDPConfig()

        // Publish the reflector the read callback consumes (same
        // lwipQueue-publishes / data-plane-reads contract as publishUDPConfig).
        publishReflector()

        // muxManager is udpQueue-owned (mux carries UDP only), so build it
        // there. Build and flow processing share that serial queue, so any flow
        // handled afterward finds the mux ready — at cold start that's every
        // flow (the read loop hasn't begun); on restart a datagram already in
        // flight may briefly miss it, which is fine since restart resets flows.
        let useMux = Self.shouldUseVisionMux(configuration)
        udpQueue.async { [self] in
            if useMux {
                muxManager = MuxManager(configuration: configuration, flowQueue: udpQueue)
            } else {
                muxManager = nil
            }
        }

        if proxyMode != .global {
            domainRouter.loadRoutingConfiguration()
        } else {
            domainRouter.reset()
        }
    }

    static func shouldUseVisionMux(_ configuration: ProxyConfiguration) -> Bool {
        guard case .vless(_, _, let flow, _, _, let muxEnabled, _) = configuration.outbound else { return false }
        return muxEnabled && flow == "xtls-rprx-vision"
    }

    /// Reads IPv6 settings from app group UserDefaults.
    private func loadIPv6Settings() {
        advertiseIPv6ToApps = AWCore.getAdvertiseIPv6ToApps()
    }

    /// Reads the bypass country code from app group UserDefaults.
    private func loadBypassCountry() {
        bypassCountryCode = AWCore.getBypassCountryCode()
    }

    /// Reads encrypted DNS settings from app group UserDefaults.
    private func loadEncryptedDNSSetting() {
        encryptedDNSEnabled = AWCore.getEncryptedDNSEnabled()
        encryptedDNSProtocol = AWCore.getEncryptedDNSProtocol()
        encryptedDNSServer = AWCore.getEncryptedDNSServer()
    }

    private func loadProxyModeSetting() {
        proxyMode = AWCore.getProxyMode()
    }

    private func loadHideVPNIconSetting() {
        hideVPNIcon = AWCore.getHideVPNIcon()
    }

    private func loadQUICPolicySetting() {
        quicPolicy = AWCore.getQUICPolicy()
    }

    private func loadBlockWebRTCSetting() {
        blockWebRTC = AWCore.getBlockWebRTC()
    }

    /// Reads the reflection toggle and address list from app group
    /// UserDefaults. ``publishReflector`` turns these into the read-path snapshot.
    private func loadReflectionSetting() {
        reflectionEnabled = AWCore.getReflectionEnabled()
        reflectionAddresses = AWCore.getReflectionAddresses()
    }

    /// Loads the MITM master toggle and rebuilds the in-memory rewrite
    /// policy. Called from ``configureRuntime`` and from the
    /// ``mitmChanged`` Darwin notification observer.
    func loadMITMSetting() {
        let snapshot = MITMSnapshot.load()
        mitmEnabled = snapshot.enabled
        if snapshot.enabled {
            mitmPolicy.load(ruleSets: snapshot.ruleSets)
        } else {
            mitmPolicy.reset()
        }
    }

    // MARK: - IP Address Helpers

    /// Converts a raw IP address pointer to a human-readable string.
    ///
    /// - Parameters:
    ///   - addr: Pointer to the raw IP address bytes (4 bytes for IPv4, 16 bytes for IPv6).
    ///   - isIPv6: Whether the address is IPv6.
    /// - Returns: A string representation (e.g. "192.168.1.1" or "2001:db8::1").
    static func ipAddrToString(_ addr: UnsafeRawPointer, isIPv6: Bool) -> String {
        var buf = (
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0)
        ) // 46 bytes = INET6_ADDRSTRLEN
        return withUnsafeMutablePointer(to: &buf) { ptr in
            let cStr = ptr.withMemoryRebound(to: CChar.self, capacity: 46) { charPtr in
                lwip_ip_to_string(addr, isIPv6 ? 1 : 0, charPtr, 46)
            }
            if let cStr {
                return String(cString: cStr)
            }
            return "?"
        }
    }

    /// Converts raw IP address bytes (4 for IPv4, 16 for IPv6) to a
    /// human-readable string. Convenience over the pointer-based overload for
    /// the Swift UDP path, which already holds addresses as `Data`.
    static func ipAddrToString(_ data: Data, isIPv6: Bool) -> String {
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return "?" }
            return ipAddrToString(base, isIPv6: isIPv6)
        }
    }

    /// Converts inline SIMD address storage (``UDPFlowKey`` / the UDP fast path)
    /// to a human-readable string, reading the leading 4 or 16 bytes per family.
    static func ipAddrToString(_ addr: SIMD16<UInt8>, isIPv6: Bool) -> String {
        withUnsafeBytes(of: addr) { raw in
            guard let base = raw.baseAddress else { return "?" }
            return ipAddrToString(base, isIPv6: isIPv6)
        }
    }
}
