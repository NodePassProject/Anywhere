//
//  TunnelStack+Lifecycle.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import Synchronization
@preconcurrency import NetworkExtension
import AnywhereIP

nonisolated private let logger = AnywhereLogger(category: "TunnelStack+Lifecycle")

extension TunnelStack {

    // MARK: - Lifecycle

    func start(packetFlow: NEPacketTunnelFlow, configuration: ProxyConfiguration) async -> Bool {
        guard transition(to: .starting) else { return false }
        let epoch = claimStartEpoch()
        TransportReclaim.unsealAll()
        makeFreshDutyCycleStreams()
        purgeOutputBuffer()
        AnywhereLogger.installLogSink { [weak self] message, level in
            let logLevel: TunnelLogLevel
            switch level {
            case .debug, .info: logLevel = .info
            case .warning: logLevel = .warning
            case .error: logLevel = .error
            }
            self?.appendLog(message, level: logLevel)
        }
        attachPacketFlow(packetFlow)
        self.configuration = configuration

        let udpPlane = UDPPlane(stack: self)
        self.udpPlane = udpPlane

        var precompiledRouting: DomainRouter.CompiledRouting?
        if Self.effectiveProxyMode(settings: TunnelSettings.load(), network: networkContext) == .rule {
            precompiledRouting = await domainRouter.compileRoutingConfiguration()
        }

        guard phase == .starting, epoch == startEpoch else {
            logger.warning("[TunnelStack] Start aborted: phase is \(phase), epoch \(epoch)/\(startEpoch)")
            if epoch == startEpoch {
                attachPacketFlow(nil)
                self.configuration = nil
                self.udpPlane = nil
            }
            return false
        }
        configureRuntime(for: configuration, precompiledRouting: precompiledRouting)
        bringUpDataPlane(configuration: configuration)

        rootTask = Task { await self.run(packetFlow: packetFlow, udpPlane: udpPlane) }

        transition(to: .running)
        logger.debug("[TunnelStack] Started")

        CertificatePolicy.startObserving()
        return true
    }

    // MARK: - Task tree

    private func run(packetFlow: NEPacketTunnelFlow, udpPlane: UDPPlane) async {
        await withDiscardingTaskGroup { group in
            group.addTask { [planeCommands] in
                for await command in planeCommands {
                    await udpPlane.apply(command)
                }
            }
            group.addTask {
                await self.runDutyCycle(packetFlow: packetFlow, udpPlane: udpPlane)
                await self.finishShutdown()
            }
        }
    }

    private func runDutyCycle(packetFlow: NEPacketTunnelFlow, udpPlane: UDPPlane) async {
        await withDiscardingTaskGroup { group in
            group.addTask { await self.runReadLoop(packetFlow: packetFlow, udpPlane: udpPlane) }
            group.addTask { await self.runSettingsObserver() }
            group.addTask { await self.runUDPCleanupLoop(udpPlane: udpPlane) }
            group.addTask { await self.runTCPIdleSweep() }
            for await job in self.nurseryJobs {
                switch job {
                case .deferredRestart(let configuration, let revalidateMode, let delay, let generation):
                    group.addTask {
                        await self.runDeferredRestart(
                            configuration: configuration,
                            revalidateMode: revalidateMode,
                            delay: delay,
                            generation: generation
                        )
                    }
                }
            }
            group.cancelAll()
        }
    }

    private func finishShutdown() {
        TransportReclaim.sealAll()
        tearDownDataPlane(tcp: .graceful)
        purgeOutputBuffer()
        attachPacketFlow(nil)
        OutboundConnector.setRoutingContext(nil)
        fakeIPPool.reset()
        connectionRouter.clearRejectMarks()
        ConnectionMetrics.shared.setDefaultServer(nil)
        configuration = nil
        finishPlaneCommands()
    }

    func stop() async {
        switch phase {
        case .idle, .stopped:
            return
        case .stopping:
            await withCheckedContinuation { stopWaiters.append($0) }
            return
        case .starting, .running:
            break
        }
        transition(to: .stopping)
        nurseryJobContinuation.finish()
        await rootTask?.value
        rootTask = nil
        AnywhereLogger.installLogSink(nil)
        transition(to: .stopped)
        let waiters = stopWaiters
        stopWaiters = []
        for waiter in waiters { waiter.resume() }
    }
    
    func applyConfiguration(_ newConfiguration: ProxyConfiguration) {
        guard phase == .running else {
            logger.warning("[VPN] Configuration switch ignored: phase is \(phase)")
            return
        }
        guard newConfiguration != configuration else { return }
        logger.info("[VPN] Configuration switched")
        restartStack(configuration: newConfiguration)
    }

    func sleep() {
        guard phase == .running, let configuration else { return }
        logger.info("[VPN] Device sleep")
        tearDownDataPlane(tcp: .silent)
        bringUpDataPlane(configuration: configuration)
    }

    func updateNetworkContext(_ context: NetworkContext) {
        guard context != networkContext else { return }
        networkContext = context

        guard phase == .running, let configuration else { return }
        let newEffective = computeEffectiveProxyMode()
        guard newEffective != proxyMode else { return }
        restartStack(configuration: configuration, revalidateMode: true)
    }

    // MARK: - Data plane

    private enum TCPTeardown {
        case graceful
        case silent
    }
    
    private func bringUpDataPlane(configuration: ProxyConfiguration) {
        guard !dataPlaneUp else {
            logger.error("[TunnelStack] Data plane already up; bring-up ignored")
            return
        }
        dataPlaneUp = true
        let ipStack = makeIPStack()
        self.ipStack = ipStack
        liveIPStack.withLock { $0 = ipStack }
        startIPStackTick()
        submitPlaneCommand(.setMultiplexerPool(configuration.makeUDPMultiplexerPool()))
        logger.debug("[TunnelStack] Data plane up")
    }
    
    private func tearDownDataPlane(tcp: TCPTeardown) {
        guard dataPlaneUp else { return }
        dataPlaneUp = false
        liveIPStack.withLock { $0 = nil }

        ipStackTick?.cancel()
        ipStackTick = nil

        ipStackAbortContext.store(.teardown, ordering: .relaxed)
        switch tcp {
        case .graceful:
            purgeOutputBuffer()
            closeAllActiveTCP()
            dataPlaneGeneration.wrappingAdd(1, ordering: .acquiringAndReleasing)
        case .silent:
            dataPlaneGeneration.wrappingAdd(1, ordering: .acquiringAndReleasing)
            purgeOutputBuffer()
            discardAllActiveTCP()
        }

        reclaimAllOutboundPools()
        submitPlaneCommand(.reclaim)

        ipStack?.shutdown()
        ipStack = nil
        tcpConnections.withLock { $0.removeAll() }
        ipStackAbortContext.store(.none, ordering: .relaxed)
        logger.debug("[TunnelStack] Data plane down")
    }

    private func closeAllActiveTCP() {
        for connection in ipStack?.connections() ?? [] { connection.close() }
    }

    private func discardAllActiveTCP() {
        for connection in ipStack?.connections() ?? [] { connection.discard() }
    }

    private func reclaimAllOutboundPools() {
        TransportReclaim.reclaimAll()
        MITMScriptHTTP2Pool.shared.reclaim()
    }

    // MARK: - Restart

    private func restartStack(configuration: ProxyConfiguration, revalidateMode: Bool = false) {
        if revalidateMode, deferredRestartScheduled { return }

        let now = MonotonicClock.now
        let elapsed = now - lastRestartTime

        if elapsed < TunnelConstants.restartThrottleInterval {
            let delay = TunnelConstants.restartThrottleInterval - elapsed
            deferredRestartGeneration += 1
            deferredRestartScheduled = true
            nurseryJobContinuation.yield(.deferredRestart(
                configuration: configuration, revalidateMode: revalidateMode,
                delay: delay, generation: deferredRestartGeneration
            ))
            logger.debug("[TunnelStack] Restart throttled, deferred by \(String(format: "%.0f", delay * 1000))ms")
            return
        }

        restartStackNow(configuration: configuration)
    }

    private func runDeferredRestart(
        configuration: ProxyConfiguration,
        revalidateMode: Bool,
        delay: TimeInterval,
        generation: Int
    ) async {
        try? await Task.sleep(seconds: delay, precision: .relaxed)
        guard generation == deferredRestartGeneration else { return }
        deferredRestartScheduled = false
        guard !Task.isCancelled, phase == .running else { return }
        if revalidateMode, computeEffectiveProxyMode() == proxyMode { return }
        restartStackNow(configuration: configuration)
    }

    private func restartStackNow(configuration: ProxyConfiguration) {
        guard phase == .running else {
            logger.warning("[TunnelStack] Restart ignored: phase is \(phase)")
            return
        }
        deferredRestartGeneration += 1
        deferredRestartScheduled = false
        lastRestartTime = MonotonicClock.now

        tearDownDataPlane(tcp: .graceful)

        connectionRouter.clearRejectMarks()

        self.configuration = configuration
        configureRuntime(for: configuration)
        bringUpDataPlane(configuration: configuration)
        logger.debug("[TunnelStack] Restarted")
    }

    // MARK: - Settings Observation

    private func runSettingsObserver() async {
        let activeConfiguration = AWNotificationCenter.Notification.activeConfigurationChanged as String
        let settings = AWNotificationCenter.Notification.tunnelSettingsChanged as String
        let routing = AWNotificationCenter.Notification.routingChanged as String
        let mitm = AWNotificationCenter.Notification.mitmChanged as String
        for await name in DarwinNotificationConcurrencyBridge.names([
            AWNotificationCenter.Notification.activeConfigurationChanged,
            AWNotificationCenter.Notification.tunnelSettingsChanged,
            AWNotificationCenter.Notification.routingChanged,
            AWNotificationCenter.Notification.mitmChanged
        ]) {
            switch name {
            case activeConfiguration: handleActiveConfigurationChanged()
            case settings: handleSettingsChanged()
            case routing: await handleRoutingChanged()
            case mitm: handleMITMChanged()
            default: break
            }
        }
    }

    private func handleActiveConfigurationChanged() {
        guard phase == .running else { return }
        let active: ProxyConfiguration?
        do {
            active = try ActiveConfiguration.load()
        } catch {
            logger.report(AnywhereError.store(.corrupted(.configurations, detail: AnywhereError.describe(error))))
            return
        }
        guard let active else {
            logger.warning("[VPN] Active configuration cleared; keeping the running one")
            return
        }
        applyConfiguration(active)
    }

    private func handleSettingsChanged() {
        DNSHosts.shared.invalidate()
        guard phase == .running, let configuration else { return }

        let old = settings
        let new = TunnelSettings.load()
        guard new != old else { return }
        logger.info("[VPN] Settings changed")
        settings = new
        
        publishUDPConfig()

        if new.quicPolicy != old.quicPolicy {
            submitPlaneCommand(.revalidateQUIC)
        }
        if new.preventDNSLeak != old.preventDNSLeak {
            connectionRouter.preventDNSLeak.store(new.preventDNSLeak, ordering: .relaxed)
        }
        if new.reflectionEnabled != old.reflectionEnabled {
            publishReflectionEnabled()
        }
        let tunnelRoutesChanged = new.tunnelIncludedRoutes != old.tunnelIncludedRoutes
            || new.tunnelExcludedRoutes != old.tunnelExcludedRoutes
            || new.hideVPNIcon != old.hideVPNIcon
            || new.reflectionEnabled != old.reflectionEnabled
        if tunnelRoutesChanged {
            requestReapplyTunnelSettings()
        }

        if computeEffectiveProxyMode() != proxyMode {
            restartStack(configuration: configuration)
        }
    }

    private func handleRoutingChanged() async {
        guard phase == .running else { return }
        guard proxyMode == .rule else { return }
        logger.info("[VPN] Routing changed")
        let compiled = await domainRouter.compileRoutingConfiguration()
        guard phase == .running, proxyMode == .rule else { return }
        domainRouter.install(compiled)
        connectionRouter.clearRejectMarks()
    }

    private func handleMITMChanged() {
        guard phase == .running else { return }
        logger.info("[VPN] MITM settings changed")
        loadMITMSetting()
        publishUDPConfig()
        submitPlaneCommand(.revalidateQUIC)
    }
}
