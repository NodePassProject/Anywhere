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
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        lwipBridge.executor.asUnownedSerialExecutor()
    }

    nonisolated let lwipBridge = LWIPConcurrencyBridge(label: AWCore.Identifier.lwipQueue)
    
    var udpPlane: UDPPlane!
    
    let outputKick: AsyncStream<Void>
    private let outputKickContinuation: AsyncStream<Void>.Continuation
    
    let planeCommands: AsyncStream<UDPPlaneCommand>
    private let planeCommandContinuation: AsyncStream<UDPPlaneCommand>.Continuation
    
    var rootTask: Task<Void, Never>?
    
    enum NurseryJob {
        case deferredRestart(configuration: ProxyConfiguration, revalidateMode: Bool, delay: TimeInterval, generation: Int)
    }
    let nurseryJobs: AsyncStream<NurseryJob>
    nonisolated let nurseryJobContinuation: AsyncStream<NurseryJob>.Continuation

    var packetFlow: NEPacketTunnelFlow?
    var configuration: ProxyConfiguration?
    
    var defaultRouteTarget: RouteTarget = .direct

    static let ipv4Proto = NSNumber(value: AF_INET)
    static let ipv6Proto = NSNumber(value: AF_INET6)
    
    struct OutputBufferState {
        var packets: [Data] = []
        var protocols: [NSNumber] = []
        var releases: [LWIPReleaseAction] = []
        var drainInFlight = false
    }
    let outputBuffer = Mutex(OutputBufferState())
    
    var settings = TunnelSettings()
    
    var proxyMode: ProxyMode = .rule
    
    var networkContext = NetworkContext()
    
    private let _mitmEnabled = Atomic<Bool>(false)
    nonisolated var mitmEnabled: Bool { _mitmEnabled.load(ordering: .relaxed) }
    nonisolated let mitmPolicy = MITMRewritePolicy()
    private let _mitmLeafCache = Mutex<MITMLeafCertCache?>(nil)
    nonisolated let mitmCertificateStore = MITMCertificateStore()
    
    nonisolated func mitmLeafCacheCreatingIfNeeded() throws(AnywhereError) -> MITMLeafCertCache {
        try _mitmLeafCache.withLock { (cache) throws(AnywhereError) in
            if let cache { return cache }
            let made = try MITMLeafCertCache(store: mitmCertificateStore)
            cache = made
            return made
        }
    }
    
    let running = Atomic<Bool>(false)
    let isTearingDown = Atomic<Bool>(false)
    
    var lastRestartTime: CFAbsoluteTime = 0
    var deferredRestartGeneration = 0
    var deferredRestartScheduled = false
    
    var lwipTick: BridgeTimer?
    
    let byteCounts = Mutex(TrafficByteCounts())
    nonisolated func addBytesIn(_ n: Int64, target: RouteTarget) {
        byteCounts.withLock { $0.add(bytesIn: n, target: target) }
    }
    nonisolated func addBytesOut(_ n: Int64, target: RouteTarget) {
        byteCounts.withLock { $0.add(bytesOut: n, target: target) }
    }

    // MARK: - Log Buffer

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
    
    private static func compactLogs(_ entries: inout [TunnelLogEntry], now: CFAbsoluteTime) {
        let cutoff = now - TunnelConstants.logRetentionInterval
        entries.removeAll { $0.timestamp < cutoff }
        if entries.count > TunnelConstants.logMaxEntries {
            entries.removeFirst(entries.count - TunnelConstants.logMaxEntries)
        }
    }

    // MARK: - UDP Config Snapshot
    
    struct UDPConfig {
        let configuration: ProxyConfiguration?
        let configurationID: UUID?
        let defaultRouteTarget: RouteTarget
        let blockUDP: Bool
        let quicPolicy: QUICPolicy
        let blockWebRTC: Bool
        let mitmEnabled: Bool
        let interceptExemptDNSServers: Set<String>
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
        interceptExemptDNSServers: [],
        advertiseIPv6ToApps: false
    ))
    
    nonisolated func udpConfig() -> UDPConfig { _udpConfig.withLock { $0 } }
    
    nonisolated func isDefaultConfiguration(_ id: UUID) -> Bool {
        udpConfig().configurationID == id
    }
    
    func publishUDPConfig() {
        let snapshot = UDPConfig(
            configuration: configuration,
            configurationID: configuration?.id,
            defaultRouteTarget: defaultRouteTarget,
            blockUDP: settings.blockUDP,
            quicPolicy: settings.quicPolicy,
            blockWebRTC: settings.blockWebRTC,
            mitmEnabled: mitmEnabled,
            interceptExemptDNSServers: settings.interceptExemptDNSServers,
            advertiseIPv6ToApps: settings.advertiseIPv6ToApps
        )
        _udpConfig.withLock { $0 = snapshot }
    }
    
    private let _reflector = Mutex(Reflector.inactive)
    
    nonisolated func reflector() -> Reflector { _reflector.withLock { $0 } }
    
    func publishOutboundRoutingContext(configuration: ProxyConfiguration?) {
        OutboundConnector.setRoutingContext(OutboundConnector.RoutingContext(
            domainRouter: domainRouter,
            requestLog: requestLog,
            defaultRouteTarget: defaultRouteTarget,
            defaultConfiguration: configuration,
            preventDNSLeak: connectionRouter.preventDNSLeak.load(ordering: .relaxed)
        ))
    }
    
    func publishReflector() {
        let snapshot = settings.reflectionEnabled
            ? Reflector(addresses: settings.reflectionAddresses)
            : .inactive
        _reflector.withLock { $0 = snapshot }
    }
    
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
    
    var tcpConnectionCapWarned = false
    var flowShedWarned = false
    
    nonisolated let domainRouter: DomainRouter
    
    nonisolated let requestLog = RequestLog()
    
    nonisolated let fakeIPPool: FakeIPPool
    
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
        (self.nurseryJobs, self.nurseryJobContinuation) = AsyncStream.makeStream(of: NurseryJob.self)
        let (reapplyStream, reapplyContinuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        self.reapplySettingsSignal = reapplyStream
        self.reapplySettingsContinuation = reapplyContinuation
    }
    
    nonisolated func kickOutputDrain() {
        outputKickContinuation.yield(())
    }
    
    nonisolated func submitPlaneCommand(_ command: UDPPlaneCommand) {
        planeCommandContinuation.yield(command)
    }
    
    nonisolated func finishPlaneCommands() {
        planeCommandContinuation.finish()
    }
    
    nonisolated let reapplySettingsSignal: AsyncStream<Void>
    private nonisolated let reapplySettingsContinuation: AsyncStream<Void>.Continuation
    
    nonisolated func requestReapplyTunnelSettings() {
        reapplySettingsContinuation.yield(())
    }

    // MARK: - Runtime Configuration

    func configureRuntime(
        for configuration: ProxyConfiguration,
        precompiledRouting: DomainRouter.CompiledRouting? = nil
    ) {
        settings = TunnelSettings.load()
        connectionRouter.preventDNSLeak.store(settings.preventDNSLeak, ordering: .relaxed)
        proxyMode = Self.effectiveProxyMode(settings: settings, network: networkContext)
        RuleResolver.shared.setUpstream(settings.ipRuleDNSUpstream)
        
        if proxyMode == .direct {
            defaultRouteTarget = .direct
        } else {
            defaultRouteTarget = AWCore.getSelectedChainId().map(RouteTarget.proxy)
            ?? AWCore.getSelectedConfigurationId().map(RouteTarget.proxy)
            ?? .proxy(configuration.id)
        }
        
        loadMITMSetting()
        
        ConnectionMetrics.shared.setDefaultServer(configuration.id)

        publishUDPConfig()
        publishReflector()
        publishOutboundRoutingContext(configuration: configuration)
        
        let multiplexerPool = configuration.outboundProtocol == .vless
        ? VLESSVisionUDPMultiplexerPool(configuration: configuration)
        : nil
        submitPlaneCommand(.setMultiplexerPool(multiplexerPool))
        
        if proxyMode == .rule {
            if let precompiledRouting {
                domainRouter.install(precompiledRouting)
            } else {
                domainRouter.loadRoutingConfiguration()
            }
        } else {
            domainRouter.reset()
        }
    }
    
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
