//
//  TunnelStack.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation
import NetworkExtension

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
    /// composite's throwaway id. Recomputed on every start/switch.
    var defaultRouteTarget: RouteTarget = .direct

    static let ipv4Proto = NSNumber(value: AF_INET)
    static let ipv6Proto = NSNumber(value: AF_INET6)

    /// Guards ``outputPackets``, ``outputProtocols``, ``pendingReleases``, and
    /// ``outputDrainInFlight``.
    let outputBufferLock = UnfairLock()
    /// Pending IP packets to ship to utun. Protected by ``outputBufferLock``.
    var outputPackets: [Data] = []
    /// Per-packet protocol family (AF_INET / AF_INET6). Protected by ``outputBufferLock``.
    var outputProtocols: [NSNumber] = []
    /// Sole owners of the buffers backing ``outputPackets`` (their ``Data``
    /// uses a `.none` deallocator). Index-aligned with ``outputPackets``;
    /// releases fire on ``lwipQueue``. Protected by ``outputBufferLock``.
    var pendingReleases: [PendingRelease] = []
    /// True while a drain loop is running on ``outputQueue``; appenders only
    /// kick a new loop when false. Protected by ``outputBufferLock``.
    var outputDrainInFlight = false

    /// ``fn(ctx)`` must run on ``lwipQueue``: `pbuf_free` and `mem_free`
    /// mutate per-pool freelists with no locking under NO_SYS=1.
    struct PendingRelease {
        let ctx: UnsafeMutableRawPointer?
        let fn: @convention(c) (UnsafeMutableRawPointer?) -> Void
    }

    /// Release placeholder for Swift-owned output packets; required so
    /// ``pendingReleases`` stays index-aligned with ``outputPackets``.
    static let noopRelease = PendingRelease(ctx: nil, fn: { _ in })

    // Settings read from App Group UserDefaults at start/restart and
    // live-reloaded via Darwin notification.
    var proxyMode: ProxyMode = .rule
    var hideVPNIcon: Bool = false
    var quicPolicy: QUICPolicy = .blocked
    var blockWebRTC: Bool = true
    var advertiseIPv6ToApps: Bool = false
    var encryptedDNSEnabled: Bool = false
    var encryptedDNSProtocol: String = "doh"
    var encryptedDNSServer: String = ""

    // Reflection settings; owned by ``lwipQueue``, published as the
    // ``reflector()`` snapshot, live-reloaded in place.
    var reflectionEnabled: Bool = false
    var reflectionAddresses: [String] = []

    // MARK: MITM
    //
    // Routing selects the upstream proxy; MITM decides whether to intercept
    // TLS in transit.
    var mitmEnabled: Bool = false
    let mitmPolicy = MITMRewritePolicy()
    /// Lazily created to defer keychain access until a session needs a leaf cert.
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

    /// Timestamp of the last network-path-change recovery (used for debouncing).
    var lastNetworkRecoveryTime: CFAbsoluteTime = 0

    /// Pending debounced network recovery. Cancelled and replaced on each new
    /// path update inside the debounce window.
    var pendingNetworkRecovery: DispatchWorkItem?

    var timeoutTimer: DispatchSourceTimer?

    /// True while ``timeoutTimer`` is suspended. Mutated only on ``lwipQueue``
    /// so it tracks the suspend count exactly — releasing a suspended
    /// `DispatchSource` traps.
    var lwipTickSuspended = false

    /// Active bypass country code (empty = disabled).
    var bypassCountryCode: String = ""

    /// Per-target traffic counters. Payload bytes, not wire bytes (headers,
    /// ACKs, retransmits excluded). Written from ``lwipQueue``/``udpQueue``,
    /// read from the NE message handler — every access takes ``countersLock``.
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
    // Each snapshot hops onto the owning queue; callers run on neither, so
    // `.sync` can't deadlock.

    /// Active TCP connections per lwIP's `tcp_active_pcbs` (LISTEN and
    /// TIME_WAIT excluded).
    var activeTCPConnections: Int {
        lwipQueue.sync { Int(lwip_bridge_active_tcp_count()) }
    }

    var activeUDPConnections: Int {
        udpQueue.sync { udpFlows.count }
    }

    // MARK: - Log Buffer
    //
    // Recent logs for the main app's viewer. NSLock: appends come from I/O
    // completion handlers, fetches from IPC.

    typealias LogLevel = TunnelLogLevel
    typealias LogEntry = TunnelLogEntry

    struct RecentTunnelInterruption {
        let timestamp: CFAbsoluteTime
        let level: LogLevel
        let summary: String
    }

    private let logLock = NSLock()
    private var logEntries: [LogEntry] = []

    func appendLog(_ message: String, level: LogLevel) {
        let now = CFAbsoluteTimeGetCurrent()
        logLock.lock()
        logEntries.append(LogEntry(timestamp: now, level: level, message: message))
        compactLogs(now: now)
        logLock.unlock()
    }

    func fetchLogs() -> [LogEntry] {
        let now = CFAbsoluteTimeGetCurrent()
        logLock.lock()
        compactLogs(now: now)
        let result = logEntries
        logLock.unlock()
        return result
    }

    /// Prunes by age, then by count. Caller must hold `logLock`.
    private func compactLogs(now: CFAbsoluteTime) {
        let cutoff = now - TunnelConstants.logRetentionInterval
        logEntries.removeAll { $0.timestamp < cutoff }
        if logEntries.count > TunnelConstants.logMaxEntries {
            logEntries.removeFirst(logEntries.count - TunnelConstants.logMaxEntries)
        }
    }

    /// Mux manager for multiplexing UDP flows (created when Vision flow is
    /// active). Owned by ``udpQueue``.
    var udpMultiplexerPool: VLESSVisionUDPMultiplexerPool?

    // MARK: - UDP Config Snapshot
    //
    // The UDP path on ``udpQueue`` needs config that ``lwipQueue`` owns and
    // mutates; reading the stored properties cross-queue would race, so
    // ``lwipQueue`` publishes an immutable snapshot under ``udpConfigLock``
    // on every change.

    /// Immutable view of the config the UDP path needs, published on change.
    struct UDPConfig {
        let configuration: ProxyConfiguration?
        /// `configuration?.id`, precomputed to avoid a cross-queue read.
        let configurationID: UUID?
        let quicPolicy: QUICPolicy
        let blockWebRTC: Bool
        let advertiseIPv6ToApps: Bool
        let mitmEnabled: Bool
    }
    private let udpConfigLock = UnfairLock()
    private var _udpConfig = UDPConfig(configuration: nil, configurationID: nil,
                                       quicPolicy: .blocked, blockWebRTC: true,
                                       advertiseIPv6ToApps: false, mitmEnabled: false)

    /// Current UDP config snapshot; callable from any queue.
    func udpConfig() -> UDPConfig { udpConfigLock.withLock { _udpConfig } }

    /// Whether `id` is the default outbound configuration; safe from any queue.
    func isDefaultConfiguration(_ id: UUID) -> Bool {
        udpConfig().configurationID == id
    }

    /// Republishes the UDP config snapshot. Must be called on ``lwipQueue``.
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

    // Reflector snapshot: the read-callback thread reads it while ``lwipQueue``
    // reloads it; an immutable value under a lock, read once per inbound batch.
    private let reflectorLock = UnfairLock()
    private var _reflector = Reflector.inactive

    /// Current reflector snapshot; callable from any queue.
    func reflector() -> Reflector { reflectorLock.withLock { _reflector } }

    /// Rebuilds and publishes the reflector. Must be called on ``lwipQueue``.
    func publishReflector() {
        let snapshot = reflectionEnabled ? Reflector(addresses: reflectionAddresses) : .inactive
        reflectorLock.withLock { _reflector = snapshot }
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
    var udpCleanupTimer: DispatchSourceTimer?

    /// Rising-edge latch so a sustained flow storm logs once, not per evicted
    /// flow. Owned by ``udpQueue``.
    var udpFlowCapWarned = false

    /// Shared Shadowsocks UDP sessions keyed by configuration id: one session
    /// serves every flow for that configuration. Owned by ``udpQueue``.
    var ssUDPSessions: [UUID: ShadowsocksUDPSession] = [:]

    /// Domain-based DNS routing (loaded from App Group routing.json).
    let domainRouter = DomainRouter()

    /// Recent per-connection routing decisions, shown in the app's Requests view.
    let requestLog = RequestLog()

    /// Fake-IP pool for mapping domains to synthetic IPs.
    let fakeIPPool = FakeIPPool()

    /// Re-applies tunnel network settings via `setTunnelNetworkSettings`,
    /// resetting the virtual interface and flushing the OS DNS cache.
    var onTunnelSettingsNeedReapply: (() -> Void)?

    /// Singleton for C callback access (one NE process = one stack).
    static var shared: TunnelStack?

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
        // Prefer the app's persisted selection — never a composited chain's throwaway id.
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

        publishUDPConfig()
        publishReflector()
        
        udpQueue.async { [self] in
            if configuration.outboundProtocol == .vless {
                udpMultiplexerPool = VLESSVisionUDPMultiplexerPool(configuration: configuration, flowQueue: udpQueue)
            } else {
                udpMultiplexerPool = nil
            }
        }

        if proxyMode != .global {
            domainRouter.loadRoutingConfiguration()
        } else {
            domainRouter.reset()
        }
    }

    private func loadIPv6Settings() {
        advertiseIPv6ToApps = AWCore.getAdvertiseIPv6ToApps()
    }

    private func loadBypassCountry() {
        bypassCountryCode = AWCore.getBypassCountryCode()
    }

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

    private func loadReflectionSetting() {
        reflectionEnabled = AWCore.getReflectionEnabled()
        reflectionAddresses = AWCore.getReflectionAddresses()
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
