//
//  TunnelStack.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation
import Synchronization
import NetworkExtension
import AnywhereIP

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

    mutating func add(_ counts: ByteCounts, target: RouteTarget) {
        guard counts.bytesIn != 0 || counts.bytesOut != 0 else { return }
        routes[target, default: ByteCounts()].bytesIn += counts.bytesIn
        routes[target, default: ByteCounts()].bytesOut += counts.bytesOut
    }
}

nonisolated final class TrafficMeter: Sendable {
    fileprivate final class Cell: Sendable {
        let target: RouteTarget
        let bytesIn = Atomic<Int64>(0)
        let bytesOut = Atomic<Int64>(0)

        init(target: RouteTarget) {
            self.target = target
        }

        var counts: TrafficByteCounts.ByteCounts {
            TrafficByteCounts.ByteCounts(
                bytesIn: bytesIn.load(ordering: .relaxed),
                bytesOut: bytesOut.load(ordering: .relaxed)
            )
        }
    }

    private let cell: Cell
    private let ledger: TrafficLedger

    fileprivate init(cell: Cell, ledger: TrafficLedger) {
        self.cell = cell
        self.ledger = ledger
    }

    deinit {
        ledger.settle(cell)
    }

    func addBytesIn(_ count: Int) {
        cell.bytesIn.wrappingAdd(Int64(count), ordering: .relaxed)
    }

    func addBytesOut(_ count: Int) {
        cell.bytesOut.wrappingAdd(Int64(count), ordering: .relaxed)
    }
}

nonisolated final class TrafficLedger: Sendable {
    private struct State {
        var settled = TrafficByteCounts()
        var live: [ObjectIdentifier: TrafficMeter.Cell] = [:]
    }

    private let state = Mutex(State())

    func open(target: RouteTarget) -> TrafficMeter {
        let cell = TrafficMeter.Cell(target: target)
        state.withLock { $0.live[ObjectIdentifier(cell)] = cell }
        return TrafficMeter(cell: cell, ledger: self)
    }

    func add(bytesIn byteCount: Int64, target: RouteTarget) {
        state.withLock { $0.settled.add(bytesIn: byteCount, target: target) }
    }

    func add(bytesOut byteCount: Int64, target: RouteTarget) {
        state.withLock { $0.settled.add(bytesOut: byteCount, target: target) }
    }

    fileprivate func settle(_ cell: TrafficMeter.Cell) {
        state.withLock { state in
            state.live.removeValue(forKey: ObjectIdentifier(cell))
            state.settled.add(cell.counts, target: cell.target)
        }
    }

    func snapshot() -> TrafficByteCounts {
        state.withLock { state in
            var counts = state.settled
            for cell in state.live.values {
                counts.add(cell.counts, target: cell.target)
            }
            return counts
        }
    }

    func reset() {
        state.withLock { state in
            state.settled = TrafficByteCounts()
            for cell in state.live.values {
                cell.bytesIn.store(0, ordering: .relaxed)
                cell.bytesOut.store(0, ordering: .relaxed)
            }
        }
    }
}

// MARK: - TCP Connection Table

nonisolated struct TCPConnectionTable {
    private(set) var connections: [ObjectIdentifier: TCPConnection] = [:] {
        didSet { FlowGauge.publishTCPTable(connections.count) }
    }

    var count: Int { connections.count }

    mutating func insert(_ connection: TCPConnection) {
        connections[ObjectIdentifier(connection)] = connection
    }

    mutating func remove(_ id: ObjectIdentifier) {
        connections.removeValue(forKey: id)
    }

    mutating func removeAll() {
        for connection in connections.values { connection.closeActivityRecord() }
        connections.removeAll()
    }
}

// MARK: - TunnelStack

actor TunnelStack {
    var ipStack: IPStack?
    nonisolated let dataPlaneGeneration = Atomic<UInt64>(0)

    var udpPlane: UDPPlane!

    private(set) var planeCommands: AsyncStream<UDPPlaneCommand>
    private var planeCommandContinuation: AsyncStream<UDPPlaneCommand>.Continuation

    var rootTask: Task<Void, Never>?

    enum NurseryJob {
        case deferredRestart(configuration: ProxyConfiguration, revalidateMode: Bool, delay: TimeInterval, generation: Int)
    }
    private(set) var nurseryJobs: AsyncStream<NurseryJob>
    var nurseryJobContinuation: AsyncStream<NurseryJob>.Continuation

    var packetFlow: NEPacketTunnelFlow?
    var configuration: ProxyConfiguration?

    var defaultRouteTarget: RouteTarget = .direct

    struct OutputBufferState {
        var generation: UInt64 = 0
        var writer: PacketFlowWriter?
        var packets: [OutboundPacket] = []
        var draining = false

        mutating func claimDrain() -> Bool {
            guard !draining, writer != nil else { return false }
            draining = true
            return true
        }

        mutating func take(_ packets: inout [OutboundPacket]) -> PacketFlowWriter? {
            guard let writer, !self.packets.isEmpty else {
                draining = false
                return nil
            }
            swap(&packets, &self.packets)
            return writer
        }
    }
    let outputBuffer = Mutex(OutputBufferState())
    
    func purgeOutputBuffer() {
        outputBuffer.withLock { buffer in
            buffer.generation = dataPlaneGeneration.load(ordering: .acquiring)
            buffer.packets.removeAll(keepingCapacity: true)
        }
    }

    func attachPacketFlow(_ packetFlow: NEPacketTunnelFlow?) {
        self.packetFlow = packetFlow
        let writer = packetFlow.map(PacketFlowWriter.init)
        outputBuffer.withLock { $0.writer = writer }
    }

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

    // MARK: - Lifecycle State

    private(set) var phase: TunnelPhase = .idle

    nonisolated let publishedPhase = Atomic<TunnelPhase>(.idle)

    nonisolated let ipStackAbortContext = Atomic<IPStackAbortContext>(.none)

    @discardableResult
    func transition(to new: TunnelPhase) -> Bool {
        let old = phase
        guard TunnelPhase.transition(&phase, to: new) else {
            if new == .starting {
                logger.debug("[Lifecycle] Start claim declined; phase is \(old)")
            } else {
                logger.error("[Lifecycle] Invalid transition \(old) → \(new); ignored")
            }
            return false
        }
        logger.debug("[Lifecycle] \(old) → \(new)")
        publishedPhase.store(new, ordering: .relaxed)
        return true
    }

    private(set) var startEpoch: UInt64 = 0

    func claimStartEpoch() -> UInt64 {
        startEpoch += 1
        return startEpoch
    }

    var lastRestartTime: TimeInterval = 0
    var deferredRestartGeneration = 0
    var deferredRestartScheduled = false
    var stopWaiters: [CheckedContinuation<Void, Never>] = []

    var ipStackTick: Task<Void, Never>?
    
    var dataPlaneUp = false
    
    nonisolated let liveIPStack = Mutex<IPStack?>(nil)

    nonisolated let udpCleanupResume = AsyncInbox<Void>(capacity: 1)

    nonisolated let tcpIdleSweepPoke = AsyncInbox<Void>(capacity: 1)
    nonisolated let tcpIdleSweepArmed = Atomic<TimeInterval>(.infinity)

    nonisolated let datagramIntake = Mutex<AsyncInbox<[InboundDatagram]>?>(nil)

    nonisolated let trafficLedger = TrafficLedger()
    nonisolated func openTrafficMeter(target: RouteTarget) -> TrafficMeter {
        trafficLedger.open(target: target.resolved(against: udpConfig().defaultRouteTarget))
    }
    nonisolated func addBytesIn(_ n: Int64, target: RouteTarget) {
        trafficLedger.add(bytesIn: n, target: target.resolved(against: udpConfig().defaultRouteTarget))
    }
    nonisolated func addBytesOut(_ n: Int64, target: RouteTarget) {
        trafficLedger.add(bytesOut: n, target: target.resolved(against: udpConfig().defaultRouteTarget))
    }
    nonisolated func byteCountsSnapshot() -> TrafficByteCounts {
        trafficLedger.snapshot()
    }
    nonisolated func resetByteCounts() {
        trafficLedger.reset()
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
    
    final class UDPConfig: Sendable {
        let configuration: ProxyConfiguration?
        let configurationID: UUID?
        let defaultRouteTarget: RouteTarget
        let blockUDP: Bool
        let quicPolicy: QUICPolicy
        let blockWebRTC: Bool
        let mitmEnabled: Bool
        let interceptExemptDNSServers: Set<String>

        init(
            configuration: ProxyConfiguration?,
            configurationID: UUID?,
            defaultRouteTarget: RouteTarget,
            blockUDP: Bool,
            quicPolicy: QUICPolicy,
            blockWebRTC: Bool,
            mitmEnabled: Bool,
            interceptExemptDNSServers: Set<String>
        ) {
            self.configuration = configuration
            self.configurationID = configurationID
            self.defaultRouteTarget = defaultRouteTarget
            self.blockUDP = blockUDP
            self.quicPolicy = quicPolicy
            self.blockWebRTC = blockWebRTC
            self.mitmEnabled = mitmEnabled
            self.interceptExemptDNSServers = interceptExemptDNSServers
        }
    }
    private let _udpConfig = Mutex(
        UDPConfig(
            configuration: nil,
            configurationID: nil,
            defaultRouteTarget: .direct,
            blockUDP: false,
            quicPolicy: .blocked,
            blockWebRTC: true,
            mitmEnabled: false,
            interceptExemptDNSServers: []
        )
    )

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
            interceptExemptDNSServers: settings.interceptExemptDNSServers
        )
        _udpConfig.withLock { $0 = snapshot }
    }

    private let _reflectionEnabled = Atomic<Bool>(false)
    nonisolated var reflectionEnabled: Bool { _reflectionEnabled.load(ordering: .relaxed) }

    func publishOutboundRoutingContext(configuration: ProxyConfiguration?) {
        OutboundConnector.setRoutingContext(OutboundConnector.RoutingContext(
            domainRouter: domainRouter,
            requestLog: requestLog,
            defaultRouteTarget: defaultRouteTarget,
            defaultConfiguration: configuration,
            preventDNSLeak: connectionRouter.preventDNSLeak.load(ordering: .relaxed)
        ))
    }

    func publishReflectionEnabled() {
        _reflectionEnabled.store(settings.reflectionEnabled, ordering: .relaxed)
    }

    struct UDPFlowKey: Hashable, CustomStringConvertible {
        let source: IPEndpoint
        let destination: IPEndpoint

        init(_ datagram: InboundDatagram) {
            source = datagram.source
            destination = datagram.destination
        }

        var description: String {
            "\(source)-\(destination)"
        }
    }

    nonisolated let domainRouter: DomainRouter

    nonisolated let requestLog = RequestLog()
    
    nonisolated let tcpActivity = ActivityPool(capacity: TunnelConstants.tcpActivityPoolCapacity)
    nonisolated let udpActivity = ActivityPool(capacity: TunnelConstants.udpActivityPoolCapacity)

    nonisolated let tcpBufferLedger = TCPBufferLedger(budget: TunnelConstants.tcpGlobalBufferBudget)

    nonisolated let tcpPressureLog = Mutex(PressureEventThrottle(label: "TCP", cap: TunnelLimits.tcpMaxConnections))
    nonisolated let tcpConnections = Mutex(TCPConnectionTable())

    nonisolated func removeTCPConnection(_ id: ObjectIdentifier) {
        tcpConnections.withLock { $0.remove(id) }
    }

    nonisolated let fakeIPPool: FakeIPPool

    nonisolated let connectionRouter: ConnectionRouter

    init() {
        let fakeIPPool = FakeIPPool()
        let domainRouter = DomainRouter()
        self.fakeIPPool = fakeIPPool
        self.domainRouter = domainRouter
        self.connectionRouter = ConnectionRouter(fakeIPPool: fakeIPPool, domainRouter: domainRouter)
        let (commandStream, commandContinuation) = AsyncStream.makeStream(of: UDPPlaneCommand.self)
        self.planeCommands = commandStream
        self.planeCommandContinuation = commandContinuation
        (self.nurseryJobs, self.nurseryJobContinuation) = AsyncStream.makeStream(of: NurseryJob.self)
        let (reapplyStream, reapplyContinuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        self.reapplySettingsState = Mutex((stream: reapplyStream, continuation: reapplyContinuation))
    }

    func submitPlaneCommand(_ command: UDPPlaneCommand) {
        planeCommandContinuation.yield(command)
    }

    func finishPlaneCommands() {
        planeCommandContinuation.finish()
    }

    func makeFreshDutyCycleStreams() {
        planeCommandContinuation.finish()
        (planeCommands, planeCommandContinuation) = AsyncStream.makeStream(of: UDPPlaneCommand.self)
        nurseryJobContinuation.finish()
        (nurseryJobs, nurseryJobContinuation) = AsyncStream.makeStream(of: NurseryJob.self)

        let (reapplyStream, reapplyContinuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
        let staleReapply: AsyncStream<Void>.Continuation = reapplySettingsState.withLock { current in
            let stale = current.continuation
            current = (stream: reapplyStream, continuation: reapplyContinuation)
            return stale
        }
        staleReapply.finish()
    }

    private nonisolated let reapplySettingsState: Mutex<(stream: AsyncStream<Void>, continuation: AsyncStream<Void>.Continuation)>

    nonisolated var reapplySettingsSignal: AsyncStream<Void> {
        reapplySettingsState.withLock { $0.stream }
    }

    nonisolated func requestReapplyTunnelSettings() {
        reapplySettingsState.withLock { $0.continuation }.yield(())
    }

    // MARK: - Runtime Configuration

    func configureRuntime(
        for configuration: ProxyConfiguration,
        precompiledRouting: DomainRouter.CompiledRouting? = nil
    ) {
        settings = TunnelSettings.load()
        connectionRouter.preventDNSLeak.store(settings.preventDNSLeak, ordering: .relaxed)
        proxyMode = Self.effectiveProxyMode(settings: settings, network: networkContext)

        defaultRouteTarget = proxyMode == .direct ? .direct : .proxy(configuration.id)
        requestLog.setDefaultRouteTarget(defaultRouteTarget)

        loadMITMSetting()

        ConnectionMetrics.shared.setDefaultServer(configuration.id)

        publishUDPConfig()
        publishReflectionEnabled()
        publishOutboundRoutingContext(configuration: configuration)

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
}
