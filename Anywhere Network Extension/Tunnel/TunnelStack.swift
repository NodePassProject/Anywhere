//
//  TunnelStack.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation
import NetworkExtension
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TunnelStack")

// MARK: - Traffic Accounting

nonisolated struct TrafficByteCounts {
    struct ByteCounts: Sendable {
        var bytesIn: Int64 = 0
        var bytesOut: Int64 = 0
    }

    var routes: [RouteTarget: ByteCounts] = [:]

    var totalBytesIn: Int64 { routes.values.reduce(0) { $0 + $1.bytesIn } }
    var totalBytesOut: Int64 { routes.values.reduce(0) { $0 + $1.bytesOut } }

    mutating func add(bytesIn byteCount: Int64, target: RouteTarget) {
        routes[target, default: ByteCounts()].bytesIn += byteCount
    }

    mutating func add(bytesOut byteCount: Int64, target: RouteTarget) {
        routes[target, default: ByteCounts()].bytesOut += byteCount
    }
}

// MARK: - TunnelStack

actor TunnelStack {

    /// Pins this actor to the lwIP serial queue, so C callbacks entering via `assumeIsolated`
    /// validate against — and run on — the same executor as the actor's isolated methods.
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        lwipBridge.executor.asUnownedSerialExecutor()
    }

    nonisolated let lwipBridge = LWIPConcurrencyBridge(label: AWCore.Identifier.lwipQueue)

    /// The UDP data plane; holds the stack `unowned`. Created in ``start(packetFlow:configuration:)``
    /// (not ``init``) so the back-reference sees a fully-formed actor. Actor-isolated: the off-actor
    /// read loop captures its value at spawn rather than reading it live.
    var udpPlane: UDPPlane!

    /// Wakes ``drainOutputLoop`` when a producer buffers packets while no drain is in flight.
    /// `.bufferingNewest(1)` coalesces a burst of kicks into a single pending wake — the drain
    /// loop empties the whole buffer each pass, so one wake suffices. Replaces the former
    /// `outputQueue.async` hop with an async-native single-consumer signal.
    let outputKick: AsyncStream<Void>
    private let outputKickContinuation: AsyncStream<Void>.Continuation

    /// The single output-drain consumer: awaits ``outputKick`` and drains the buffer to utun off
    /// the lwIP/UDP queues so producers never block on `writePackets`. Owned by the stack:
    /// ``start(packetFlow:configuration:)`` spawns it, ``stop()`` cancels it. One consumer means
    /// the drain stays serial without a queue.
    var outputDrainTask: Task<Void, Never>?

    /// The TUN read loop: awaits each inbound batch, partitions it, and feeds lwIP + the UDP plane.
    /// A single task, so the next read waits on both sub-batches (utun paces us). Owned by the
    /// stack; ``stop()`` cancels it.
    var readTask: Task<Void, Never>?

    /// Ordered command channel to ``udpPlane`` for mux/reclaim. lwipQueue producers `yield` (which
    /// preserves order), and a single driver applies them to the actor in that order — so a
    /// restart's reclaim-then-set never races. `.bufferingOldest` (unbounded) keeps every command.
    let planeCommands: AsyncStream<UDPPlaneCommand>
    private let planeCommandContinuation: AsyncStream<UDPPlaneCommand>.Continuation
    /// The single plane-command driver; owned by the stack, cancelled in ``stop()``.
    var planeCommandTask: Task<Void, Never>?

    /// Consumes the Darwin settings/routing/MITM notification stream; owned by the stack, cancelled
    /// in ``stop()`` (which tears down the underlying `CFNotificationCenter` observers).
    var settingsObserverTask: Task<Void, Never>?

    var packetFlow: NEPacketTunnelFlow?
    var configuration: ProxyConfiguration?
    
    var defaultRouteTarget: RouteTarget = .direct

    static let ipv4Proto = NSNumber(value: AF_INET)
    static let ipv6Proto = NSNumber(value: AF_INET6)

    /// Output batching state, guarded as one unit so ``packets``/``protocols``/
    /// ``releases`` stay index-aligned and the drain flag flips atomically with
    /// the empty check.
    struct OutputBufferState {
        /// Pending IP packets to ship to utun.
        var packets: [Data] = []
        /// Per-packet protocol family (AF_INET / AF_INET6).
        var protocols: [NSNumber] = []
        /// Sole owners of the buffers backing ``packets`` (their ``Data``
        /// uses a `.none` deallocator). Index-aligned with ``packets``;
        /// releases fire on ``lwipQueue``.
        var releases: [PendingRelease] = []
        /// True while ``outputDrainTask`` is draining; appenders only wake it when false.
        var drainInFlight = false
    }
    let outputBuffer = Mutex(OutputBufferState())

    /// ``fn(ctx)`` must run on ``lwipQueue``: `pbuf_free` and `mem_free`
    /// mutate per-pool freelists with no locking under NO_SYS=1.
    struct PendingRelease {
        let ctx: UnsafeMutableRawPointer?
        let fn: @convention(c) (UnsafeMutableRawPointer?) -> Void
    }

    /// Release placeholder for Swift-owned output packets; required so
    /// ``OutputBufferState/releases`` stays index-aligned with ``OutputBufferState/packets``.
    static let noopRelease = PendingRelease(ctx: nil, fn: { _ in })

    /// Settings snapshot read from App Group UserDefaults at start/restart
    /// and live-reloaded via Darwin notification. Owned by ``lwipQueue``;
    /// the UDP path reads the flags it needs via ``UDPConfig``.
    var settings = TunnelSettings()

    /// Effective mode applied by the data plane; equals
    /// ``TunnelSettings/baseProxyMode`` unless the trusted-network policy
    /// overrides it for the current egress. Owned by ``lwipQueue``.
    var proxyMode: ProxyMode = .rule

    /// Egress identity feeding the trusted-network policy. Owned by ``lwipQueue``.
    var networkContext = NetworkContext()

    // MARK: MITM
    //
    // `mitmEnabled` is an `Atomic` (not actor-isolated) so the lwIP accept callback and
    // ``TCPConnection`` — both off the actor's method-call graph — read it without a hop; the
    // actor publishes it in ``loadMITMSetting``. The leaf cache is lazily created by whichever
    // ``TCPConnection`` first needs it, so it lives behind a `Mutex`, not in actor state.
    private let _mitmEnabled = Atomic<Bool>(false)
    nonisolated var mitmEnabled: Bool { _mitmEnabled.load(ordering: .relaxed) }
    nonisolated let mitmPolicy = MITMRewritePolicy()
    private let _mitmLeafCache = Mutex<MITMLeafCertCache?>(nil)
    nonisolated let mitmCertificateStore = MITMCertificateStore()

    /// Returns the shared MITM leaf-cert cache, creating it on first use. Called by
    /// ``TCPConnection`` on the lwIP queue; the `Mutex` keeps the lazy init single-flighted.
    nonisolated func mitmLeafCacheCreatingIfNeeded() throws -> MITMLeafCertCache {
        try _mitmLeafCache.withLock { cache in
            if let cache { return cache }
            let made = try MITMLeafCertCache(store: mitmCertificateStore)
            cache = made
            return made
        }
    }

    /// True while the stack is live. An `Atomic` (not actor state) because the off-actor read
    /// loop, drain loop, and periodic scheduler all gate on it.
    let _running = Atomic<Bool>(false)
    nonisolated var running: Bool { _running.load(ordering: .relaxed) }

    /// True during a deliberate full-stack TCP teardown so the resulting ERR_ABRT flood is demoted
    /// to debug while lwIP's own aborts still warn. An `Atomic` because ``TCPConnection`` reads it
    /// from its own actor to classify errors.
    let _isTearingDown = Atomic<Bool>(false)
    nonisolated var isTearingDown: Bool { _isTearingDown.load(ordering: .relaxed) }

    /// Timestamp of the last completed stack restart (used for throttling).
    var lastRestartTime: CFAbsoluteTime = 0

    /// Pending deferred restart when throttled. Cancelled and replaced on each new request.
    /// Fires its body on ``lwipQueue`` (hopped back on).
    var deferredRestartTask: Task<Void, Never>?

    /// Recurring stack-lifetime tasks. Centralizes their lifecycle and reconciles them
    /// on device wake.
    nonisolated let scheduler = TunnelScheduler()

    /// lwIP's periodic timeout tick (retransmit, persist, TIME_WAIT), vended by ``lwipBridge`` so
    /// the `DispatchSourceTimer` stays in the bridge layer. Self-suspends when lwIP's timeout list
    /// drains and re-arms on fresh input; ``BridgeTimer`` keeps the suspend count balanced. Owned
    /// by ``lwipQueue``.
    var lwipTick: BridgeTimer?
    
    private let _byteCounts = Mutex(TrafficByteCounts())
    nonisolated func addBytesIn(_ n: Int64, target: RouteTarget) {
        _byteCounts.withLock { $0.add(bytesIn: n, target: target) }
    }
    nonisolated func addBytesOut(_ n: Int64, target: RouteTarget) {
        _byteCounts.withLock { $0.add(bytesOut: n, target: target) }
    }
    /// Snapshot of all per-target counters, read once per stats poll.
    nonisolated var byteCounts: TrafficByteCounts { _byteCounts.withLock { $0 } }

    // MARK: - Log Buffer
    //
    // Recent logs for the main app's viewer. Locked because appends come from
    // I/O completion handlers, fetches from IPC.

    private let logEntries = Mutex<[TunnelLogEntry]>([])

    nonisolated func appendLog(_ message: String, level: TunnelLogLevel) {
        let now = CFAbsoluteTimeGetCurrent()
        logEntries.withLock { entries in
            entries.append(TunnelLogEntry(timestamp: now, level: level, message: message))
            Self.compactLogs(&entries, now: now)
        }
    }

    nonisolated func fetchLogs() -> [TunnelLogEntry] {
        let now = CFAbsoluteTimeGetCurrent()
        return logEntries.withLock { entries in
            Self.compactLogs(&entries, now: now)
            return entries
        }
    }

    /// Prunes by age, then by count.
    private static func compactLogs(_ entries: inout [TunnelLogEntry], now: CFAbsoluteTime) {
        let cutoff = now - TunnelConstants.logRetentionInterval
        entries.removeAll { $0.timestamp < cutoff }
        if entries.count > TunnelConstants.logMaxEntries {
            entries.removeFirst(entries.count - TunnelConstants.logMaxEntries)
        }
    }

    // MARK: - UDP Config Snapshot
    //
    // The UDP data plane (``udpPlane``) needs config that ``lwipQueue`` owns and
    // mutates; reading the stored properties cross-domain would race, so
    // ``lwipQueue`` publishes an immutable snapshot through a Mutex
    // on every change.

    /// Immutable view of the config the UDP path needs, published on change.
    struct UDPConfig {
        let configuration: ProxyConfiguration?
        let configurationID: UUID?
        let defaultRouteTarget: RouteTarget
        let blockUDP: Bool
        let quicPolicy: QUICPolicy
        let blockWebRTC: Bool
        let mitmEnabled: Bool
        let advertiseIPv6ToApps: Bool
    }
    private let _udpConfig = Mutex(UDPConfig(
        configuration: nil,
        configurationID: nil,
        defaultRouteTarget: .direct,
        blockUDP: false,
        quicPolicy: .blocked,
        blockWebRTC: true,
        mitmEnabled: false,
        advertiseIPv6ToApps: false
    ))

    /// Current UDP config snapshot; callable from any queue.
    nonisolated func udpConfig() -> UDPConfig { _udpConfig.withLock { $0 } }

    /// Whether `id` is the default outbound configuration; safe from any queue.
    nonisolated func isDefaultConfiguration(_ id: UUID) -> Bool {
        udpConfig().configurationID == id
    }

    /// Republishes the UDP config snapshot. Must be called on ``lwipQueue``.
    func publishUDPConfig() {
        let snapshot = UDPConfig(
            configuration: configuration,
            configurationID: configuration?.id,
            defaultRouteTarget: defaultRouteTarget,
            blockUDP: settings.blockUDP,
            quicPolicy: settings.quicPolicy,
            blockWebRTC: settings.blockWebRTC,
            mitmEnabled: mitmEnabled,
            advertiseIPv6ToApps: settings.advertiseIPv6ToApps
        )
        _udpConfig.withLock { $0 = snapshot }
    }

    /// Reflector snapshot: the read-callback thread reads it while ``lwipQueue``
    /// reloads it; an immutable value behind a Mutex, read once per inbound batch.
    private let _reflector = Mutex(Reflector.inactive)

    /// Current reflector snapshot; callable from any queue.
    nonisolated func reflector() -> Reflector { _reflector.withLock { $0 } }

    /// Publishes the routing context that detached script `Anywhere.http`
    /// fetches dial against. Must be called on ``lwipQueue``.
    func publishOutboundRoutingContext(configuration: ProxyConfiguration?) {
        OutboundConnector.setRoutingContext(OutboundConnector.RoutingContext(
            domainRouter: domainRouter,
            requestLog: requestLog,
            defaultRouteTarget: defaultRouteTarget,
            defaultConfiguration: configuration
        ))
    }

    /// Rebuilds and publishes the reflector. Must be called on ``lwipQueue``.
    func publishReflector() {
        let snapshot = settings.reflectionEnabled
            ? Reflector(addresses: settings.reflectionAddresses)
            : .inactive
        _reflector.withLock { $0 = snapshot }
    }

    /// Hashable 5-tuple key for UDP flows. Addresses are inline raw bytes
    /// (`SIMD16<UInt8>`, zero-padded; IPv4 in the first 4) so the per-packet
    /// fast-path lookup allocates nothing. `isIPv6` disambiguates families
    /// sharing the same leading bytes.
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

    /// Rising-edge latch so a sustained TCP connection storm logs once, not per
    /// refused connection. Owned by ``lwipQueue``.
    var tcpConnectionCapWarned = false

    /// Rising-edge latch for SYNs shed by the flow budget / exhaustion brake.
    /// Owned by ``lwipQueue``.
    var flowShedWarned = false

    /// Per-host SYN-reject flood tracker; consulted only by the isolated SYN-filter callback, so
    /// it is actor state rather than a shared global.
    let rejectFloodTracker = RejectFloodTracker()

    // These four are `Sendable` (all state behind Mutex/Atomic) and `nonisolated`, so the off-actor
    // read loop, the UDP plane, and the TCP connections reach them without hopping the stack actor.

    /// Domain-based DNS routing (loaded from App Group routing.json).
    nonisolated let domainRouter: DomainRouter

    /// Recent per-connection routing decisions, shown in the app's Requests view.
    nonisolated let requestLog = RequestLog()

    /// Fake-IP pool for mapping domains to synthetic IPs.
    nonisolated let fakeIPPool: FakeIPPool

    /// Connection-time routing decisions (fake-IP pool + domain + IP rules),
    /// shared by the TCP SYN filter, TCP accept, and UDP paths.
    nonisolated let connectionRouter: ConnectionRouter

    init() {
        let fakeIPPool = FakeIPPool()
        let domainRouter = DomainRouter()
        self.fakeIPPool = fakeIPPool
        self.domainRouter = domainRouter
        self.connectionRouter = ConnectionRouter(fakeIPPool: fakeIPPool, domainRouter: domainRouter)
        let (stream, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        self.outputKick = stream
        self.outputKickContinuation = continuation
        let (commandStream, commandContinuation) = AsyncStream.makeStream(of: UDPPlaneCommand.self)
        self.planeCommands = commandStream
        self.planeCommandContinuation = commandContinuation
        let (reapplyStream, reapplyContinuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        self.reapplySettingsSignal = reapplyStream
        self.reapplySettingsContinuation = reapplyContinuation
        // `udpPlane` is created in `start()`, where `self` is fully formed and the back-reference
        // is safe.
    }

    /// Kicks the output-drain consumer. Called by producers that flipped ``drainInFlight`` true
    /// (the lwIP output callback and the off-actor UDP/reflection paths), so it is `nonisolated`.
    nonisolated func kickOutputDrain() {
        outputKickContinuation.yield(())
    }

    /// Submits a mux/reclaim command to the ordered plane driver. Call on ``lwipQueue`` so commands
    /// stay ordered relative to each other. `nonisolated`: only touches the ordered continuation.
    nonisolated func submitPlaneCommand(_ command: UDPPlaneCommand) {
        planeCommandContinuation.yield(command)
    }

    /// Ends the plane-command channel so the driver drains its buffered commands and finishes.
    nonisolated func finishPlaneCommands() {
        planeCommandContinuation.finish()
    }

    /// Signals the provider to re-apply tunnel network settings (routes/DNS) via
    /// `setTunnelNetworkSettings`, resetting the virtual interface and flushing the OS DNS cache.
    /// An `AsyncStream` rather than a stored cross-actor closure: the provider consumes it on its
    /// own async context. `.bufferingNewest(1)` coalesces bursts — one reapply subsumes a prior one.
    nonisolated let reapplySettingsSignal: AsyncStream<Void>
    private nonisolated let reapplySettingsContinuation: AsyncStream<Void>.Continuation

    /// Requests a tunnel-settings reapply; safe from any domain.
    nonisolated func requestReapplyTunnelSettings() {
        reapplySettingsContinuation.yield(())
    }

    // MARK: - Runtime Configuration

    func configureRuntime(for configuration: ProxyConfiguration) {
        settings = TunnelSettings.load()
        connectionRouter.setPreventDNSLeak(settings.preventDNSLeak)
        proxyMode = Self.effectiveProxyMode(settings: settings, network: networkContext)

        if proxyMode == .direct {
            // Router is reset below, so every connection falls through to this
            // direct default, bypassing all proxies and rules.
            defaultRouteTarget = .direct
        } else {
            // Prefer the app's persisted selection — never a composited chain's throwaway id.
            defaultRouteTarget = AWCore.getSelectedChainId().map(RouteTarget.proxy)
                ?? AWCore.getSelectedConfigurationId().map(RouteTarget.proxy)
                ?? .proxy(configuration.id)
        }

        loadMITMSetting()

        publishUDPConfig()
        publishReflector()
        publishOutboundRoutingContext(configuration: configuration)

        // Build the Vision mux pool here on lwipQueue (which owns `configuration`), then hand it
        // to the UDP plane through the ordered command channel (so it can't be reordered against a
        // restart's reclaim).
        let multiplexerPool = configuration.outboundProtocol == .vless
            ? VLESSVisionUDPMultiplexerPool(configuration: configuration)
            : nil
        submitPlaneCommand(.setMultiplexerPool(multiplexerPool))

        // Only rule mode consults the router; global and direct reset it and
        // rely on the default outbound.
        if proxyMode == .rule {
            domainRouter.loadRoutingConfiguration()
        } else {
            domainRouter.reset()
        }
    }

    /// Effective mode under the trusted-network policy. Pure so the policy is
    /// unit-testable.
    static func effectiveProxyMode(settings: TunnelSettings, network: NetworkContext) -> ProxyMode {
        if network.isWiFi, let ssid = network.ssid, settings.trustedSSIDs.contains(ssid) {
            return .direct
        }
        if network.isCellular, settings.alwaysTrustCellular {
            return .direct
        }
        if network.isCellular, settings.alwaysUntrustCellular {
            return .global
        }
        return settings.baseProxyMode
    }

    /// ``effectiveProxyMode(settings:network:)`` for the current state.
    /// Must be called on ``lwipQueue``.
    func computeEffectiveProxyMode() -> ProxyMode {
        Self.effectiveProxyMode(settings: settings, network: networkContext)
    }

    func loadMITMSetting() {
        guard let data = AWCore.getMITMData(),
              let snapshot = MITMBinaryReader.decode(data) else {
            _mitmEnabled.store(false, ordering: .relaxed)
            mitmPolicy.reset()
            return
        }
        _mitmEnabled.store(snapshot.enabled, ordering: .relaxed)
        if snapshot.enabled {
            mitmPolicy.load(ruleSets: snapshot.ruleSets)
        } else {
            mitmPolicy.reset()
        }
    }

    // MARK: - IP Address Helpers

    /// Converts raw IP address bytes (4 for IPv4, 16 for IPv6) to a string.
    static func ipAddrToString(_ addr: UnsafeRawPointer, isIPv6: Bool) -> String {
        var buffer = (
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0),
            Int8(0), Int8(0), Int8(0), Int8(0), Int8(0), Int8(0)
        ) // 46 bytes = INET6_ADDRSTRLEN
        return withUnsafeMutablePointer(to: &buffer) { pointer in
            let cStr = pointer.withMemoryRebound(to: CChar.self, capacity: 46) { charPtr in
                lwip_ip_to_string(addr, isIPv6 ? 1 : 0, charPtr, 46)
            }
            if let cStr {
                return String(cString: cStr)
            }
            return "?"
        }
    }

    static func ipAddrToString(_ data: Data, isIPv6: Bool) -> String {
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return "?" }
            return ipAddrToString(base, isIPv6: isIPv6)
        }
    }

    static func ipAddrToString(_ addr: SIMD16<UInt8>, isIPv6: Bool) -> String {
        withUnsafeBytes(of: addr) { raw in
            guard let base = raw.baseAddress else { return "?" }
            return ipAddrToString(base, isIPv6: isIPv6)
        }
    }
}
