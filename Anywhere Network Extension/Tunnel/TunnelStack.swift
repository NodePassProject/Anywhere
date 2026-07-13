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

struct TrafficByteCounts {
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

/// Coordinator for the tunnel's data plane: TCP/ICMP feed the vendored lwIP
/// stack on ``lwipQueue``; UDP is handled entirely in Swift on ``udpQueue``
/// (lwIP is built `LWIP_UDP 0`).
class TunnelStack {

    // MARK: Properties

    /// Serial queue for all lwIP operations (lwIP is not thread-safe).
    let lwipQueue = DispatchQueue(label: AWCore.Identifier.lwipQueue,
                                  qos: .userInitiated,
                                  autoreleaseFrequency: .workItem)

    /// Serial queue owning the UDP data plane.
    let udpQueue = DispatchQueue(label: AWCore.Identifier.udpQueue,
                                 qos: .userInitiated,
                                 autoreleaseFrequency: .workItem)

    /// Queue for writing packets back to the tunnel.
    let outputQueue = DispatchQueue(label: AWCore.Identifier.outputQueue,
                                    qos: .userInitiated,
                                    autoreleaseFrequency: .workItem)

    var packetFlow: NEPacketTunnelFlow?
    var configuration: ProxyConfiguration?

    /// Identity of the default outbound, derived from the app's persisted
    /// selection so a chain resolves to its stable chain id, not the
    /// composite's throwaway id. Recomputed on every start/switch. Owned by
    /// ``lwipQueue``; udpQueue readers use ``UDPConfig/defaultRouteTarget``.
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
        /// True while a drain loop is running on ``outputQueue``; appenders only
        /// kick a new loop when false.
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
    var mitmEnabled: Bool = false
    let mitmPolicy = MITMRewritePolicy()
    var mitmLeafCache: MITMLeafCertCache?
    let mitmCertificateStore = MITMCertificateStore()

    var running = false

    /// True during a deliberate full-stack TCP teardown so the resulting
    /// ERR_ABRT flood is demoted to debug while lwIP's own aborts still warn.
    var isTearingDown = false

    /// Timestamp of the last completed stack restart (used for throttling).
    var lastRestartTime: CFAbsoluteTime = 0

    /// Pending deferred restart when throttled. Cancelled and replaced on each new request.
    var deferredRestart: DispatchWorkItem?

    /// Recurring stack-lifetime tasks. Centralizes their lifecycle and reconciles them
    /// on device wake.
    let scheduler = TunnelScheduler()

    var timeoutTimer: DispatchSourceTimer?

    /// True while ``timeoutTimer`` is suspended. Mutated only on ``lwipQueue``
    /// so it tracks the suspend count exactly — releasing a suspended
    /// `DispatchSource` traps.
    var lwipTickSuspended = false

    /// Per-target traffic counters. Payload bytes, not wire bytes (headers,
    /// ACKs, retransmits excluded). Written from ``lwipQueue``/``udpQueue``,
    /// read from the NE message handler — every access goes through the Mutex.
    private let _byteCounts = Mutex(TrafficByteCounts())
    func addBytesIn(_ n: Int64, target: RouteTarget) {
        _byteCounts.withLock { $0.add(bytesIn: n, target: target) }
    }
    func addBytesOut(_ n: Int64, target: RouteTarget) {
        _byteCounts.withLock { $0.add(bytesOut: n, target: target) }
    }
    /// Snapshot of all per-target counters, read once per stats poll.
    var byteCounts: TrafficByteCounts { _byteCounts.withLock { $0 } }

    // MARK: - Log Buffer
    //
    // Recent logs for the main app's viewer. Locked because appends come from
    // I/O completion handlers, fetches from IPC.

    private let logEntries = Mutex<[TunnelLogEntry]>([])

    func appendLog(_ message: String, level: TunnelLogLevel) {
        let now = CFAbsoluteTimeGetCurrent()
        logEntries.withLock { entries in
            entries.append(TunnelLogEntry(timestamp: now, level: level, message: message))
            Self.compactLogs(&entries, now: now)
        }
    }

    func fetchLogs() -> [TunnelLogEntry] {
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

    /// Mux manager for multiplexing UDP flows (created when Vision flow is
    /// active). Owned by ``udpQueue``.
    var udpMultiplexerPool: VLESSVisionUDPMultiplexerPool?

    // MARK: - UDP Config Snapshot
    //
    // The UDP path on ``udpQueue`` needs config that ``lwipQueue`` owns and
    // mutates; reading the stored properties cross-queue would race, so
    // ``lwipQueue`` publishes an immutable snapshot through a Mutex
    // on every change.

    /// Immutable view of the config the UDP path needs, published on change.
    struct UDPConfig {
        let configuration: ProxyConfiguration?
        /// `configuration?.id`, precomputed to avoid a cross-queue read.
        let configurationID: UUID?
        /// Mirror of ``TunnelStack/defaultRouteTarget`` for udpQueue readers.
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
    func udpConfig() -> UDPConfig { _udpConfig.withLock { $0 } }

    /// Whether `id` is the default outbound configuration; safe from any queue.
    func isDefaultConfiguration(_ id: UUID) -> Bool {
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
    func reflector() -> Reflector { _reflector.withLock { $0 } }

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

    /// Active UDP flows keyed by 5-tuple. Owned by ``udpQueue``.
    var udpFlows: [UDPFlowKey: UDPFlow] = [:]

    /// Rising-edge latch so a sustained flow storm logs once, not per evicted
    /// flow. Owned by ``udpQueue``.
    var udpFlowCapWarned = false

    /// Rising-edge latch so a sustained TCP connection storm logs once, not per
    /// refused connection. Owned by ``lwipQueue``.
    var tcpConnectionCapWarned = false

    /// Rising-edge latch for SYNs shed by the flow budget / exhaustion brake.
    /// Owned by ``lwipQueue``.
    var flowShedWarned = false

    /// Rising-edge latch for UDP flows shed by the flow budget / exhaustion
    /// brake. Owned by ``udpQueue``.
    var udpShedWarned = false

    /// Whether the UDP flow cap is shrunk to
    /// ``TunnelLimits/udpMaxFlowsUnderPressure``; see ``currentUDPFlowCap()``.
    /// Owned by ``udpQueue``.
    var udpPressureShedding = false

    /// Shared Shadowsocks UDP sessions keyed by configuration id: one session
    /// serves every flow for that configuration. Owned by ``udpQueue``.
    var ssUDPSessions: [UUID: ShadowsocksUDPSession] = [:]

    /// Domain-based DNS routing (loaded from App Group routing.json).
    let domainRouter: DomainRouter

    /// Recent per-connection routing decisions, shown in the app's Requests view.
    let requestLog = RequestLog()

    /// Fake-IP pool for mapping domains to synthetic IPs.
    let fakeIPPool: FakeIPPool

    /// Connection-time routing decisions (fake-IP pool + domain + IP rules),
    /// shared by the TCP SYN filter, TCP accept, and UDP paths.
    let connectionRouter: ConnectionRouter

    init() {
        let fakeIPPool = FakeIPPool()
        let domainRouter = DomainRouter()
        self.fakeIPPool = fakeIPPool
        self.domainRouter = domainRouter
        self.connectionRouter = ConnectionRouter(fakeIPPool: fakeIPPool, domainRouter: domainRouter)
    }

    /// Re-applies tunnel network settings via `setTunnelNetworkSettings`,
    /// resetting the virtual interface and flushing the OS DNS cache.
    var onTunnelSettingsNeedReapply: (() -> Void)?

    // MARK: - Shadowsocks UDP Sessions

    /// Returns the shared SS UDP session for `configuration`, creating or
    /// replacing terminal ones; sharing one sessionID + socket across flows
    /// restores full-cone NAT. Must be called on `udpQueue`.
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
    func purgeShadowsocksUDPSessions() {
        for (_, session) in ssUDPSessions {
            session.cancel()
        }
        ssUDPSessions.removeAll()
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

        udpQueue.async { [self] in
            if configuration.outboundProtocol == .vless {
                udpMultiplexerPool = VLESSVisionUDPMultiplexerPool(configuration: configuration, flowQueue: udpQueue)
            } else {
                udpMultiplexerPool = nil
            }
        }

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
            mitmEnabled = false
            mitmPolicy.reset()
            return
        }
        mitmEnabled = snapshot.enabled
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
