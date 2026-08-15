//
//  TunnelStack+Lifecycle.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import NetworkExtension
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TunnelStack+Lifecycle")

extension TunnelStack {

    // MARK: - Lifecycle

    func start(packetFlow: NEPacketTunnelFlow, configuration: ProxyConfiguration) async -> Bool {
        guard transition(to: .starting) else { return false }
        let epoch = claimStartEpoch()
        TransportReclaim.unsealAll()
        pendingConfigurationSwitch = nil
        pendingSuspend = false
        pendingWake = false
        makeFreshDutyCycleStreams()
        AnywhereLogger.installLogSink { [weak self] message, level in
            let logLevel: TunnelLogLevel
            switch level {
            case .debug, .info: logLevel = .info
            case .warning: logLevel = .warning
            case .error: logLevel = .error
            }
            self?.appendLog(message, level: logLevel)
        }
        self.packetFlow = packetFlow
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
                self.packetFlow = nil
                self.configuration = nil
                self.udpPlane = nil
            }
            return false
        }
        configureRuntime(for: configuration, precompiledRouting: precompiledRouting)

        installLwipCallbacks()
        lwip_bridge_init()
        startTimeoutTimer()

        rootTask = Task { await self.run(packetFlow: packetFlow, udpPlane: udpPlane) }

        transition(to: .running)
        logger.debug("[TunnelStack] Started")

        CertificatePolicy.startObserving()
        if let pending = pendingConfigurationSwitch {
            pendingConfigurationSwitch = nil
            switchConfiguration(pending)
        }
        if pendingSuspend {
            pendingSuspend = false
            suspendOutbound()
        } else if pendingWake {
            pendingWake = false
            invalidateOutboundState(configuration: configuration)
        }
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
            group.addTask { [outputKick] in
                for await _ in outputKick {
                    await self.drainOutputLoop(packetFlow: packetFlow)
                }
            }
            group.addTask { await self.runReadLoop(packetFlow: packetFlow, udpPlane: udpPlane) }
            group.addTask { await self.runSettingsObserver() }
            group.addTask { await self.runUDPCleanupLoop(udpPlane: udpPlane) }
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
        shutdownInternal()
        purgeOutputBuffer()
        lwip_bridge_set_host_ctx(nil)
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
        case .starting, .running, .suspended:
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

    func switchConfiguration(_ newConfiguration: ProxyConfiguration) {
        if phase == .starting {
            logger.info("[VPN] Configuration switch deferred until start completes")
            pendingConfigurationSwitch = newConfiguration
            return
        }
        guard phase.isActive else {
            logger.warning("[VPN] Configuration switch ignored: phase is \(phase)")
            return
        }
        logger.info("[VPN] Configuration switched")
        restartStack(configuration: newConfiguration)
    }

    func handleWake() {
        pendingSuspend = false
        guard phase.isActive, let configuration else {
            if phase == .starting { pendingWake = true }
            return
        }
        logger.info("[VPN] Device wake")
        if phase == .suspended {
            transition(to: .running)
        }
        invalidateOutboundState(configuration: configuration)
    }

    func suspendOutbound() {
        switch phase {
        case .running:
            logger.info("[VPN] Path offline/sleep")
            transition(to: .suspended)
        case .starting:
            logger.info("[VPN] Path offline/sleep during start")
            pendingSuspend = true
            pendingWake = false
            return
        case .suspended:
            logger.info("[VPN] Path offline/sleep while suspended")
        case .idle, .stopping, .stopped:
            return
        }
        reclaimAllOutboundPools()
        reclaimInstanceTransports(rebuildMultiplexerPool: false)
    }

    func updateNetworkContext(isWiFi: Bool, isCellular: Bool, ssid: String?) {
        guard phase.isActive, let configuration else { return }

        let context = NetworkContext(isWiFi: isWiFi, isCellular: isCellular, ssid: ssid)
        guard context != networkContext else { return }
        networkContext = context

        let newEffective = computeEffectiveProxyMode()
        guard newEffective != proxyMode else { return }
        logger.info("[VPN] Trusted-network policy: effective mode \(proxyMode.rawValue) → \(newEffective.rawValue) (Wi-Fi=\(isWiFi), cellular=\(isCellular), SSID=\(ssid ?? "—"))")
        restartStack(configuration: configuration, revalidateMode: true)
    }

    private func invalidateOutboundState(configuration: ProxyConfiguration) {
        closeAllActiveTCP()
        reclaimAllOutboundPools()
        reclaimInstanceTransports(rebuildMultiplexerPool: true)
    }

    private func closeAllActiveTCP() {
        lwip_bridge_for_each_tcp { arg in
            guard let arg else { return }
            BridgeContext.unretained(arg, as: TCPConnection.self).assumeIsolated { $0.close() }
        }
    }

    private func reclaimAllOutboundPools() {
        TransportReclaim.reclaimAll()
        MITMScriptHTTP2Pool.shared.reclaim()
    }

    private func reclaimInstanceTransports(rebuildMultiplexerPool: Bool) {
        let rebuiltMultiplexerPool: VLESSVisionUDPMultiplexerPool?
        if rebuildMultiplexerPool, let configuration, configuration.outboundProtocol == .vless {
            rebuiltMultiplexerPool = VLESSVisionUDPMultiplexerPool(configuration: configuration)
        } else {
            rebuiltMultiplexerPool = nil
        }
        submitPlaneCommand(.reclaim(replacementMultiplexerPool: rebuiltMultiplexerPool))
    }

    private func shutdownInternal() {
        lwipTick?.cancel()
        lwipTick = nil

        purgeOutputBuffer()

        closeAllActiveTCP()

        reclaimAllOutboundPools()
        reclaimInstanceTransports(rebuildMultiplexerPool: false)

        lwipAbortContext.store(.teardown, ordering: .relaxed)
        lwip_bridge_shutdown()
        lwipAbortContext.store(.none, ordering: .relaxed)
        FlowGauge.publishTCPTable(0)
        logger.debug("[TunnelStack] Shutdown complete")
    }

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
        try? await Task.sleep(for: .seconds(delay))
        guard generation == deferredRestartGeneration else { return }
        deferredRestartScheduled = false
        guard !Task.isCancelled, phase.isActive else { return }
        if revalidateMode, computeEffectiveProxyMode() == proxyMode { return }
        restartStackNow(configuration: configuration)
    }

    private func restartStackNow(configuration: ProxyConfiguration) {
        guard phase.isActive else {
            logger.warning("[TunnelStack] Restart ignored: phase is \(phase)")
            return
        }
        deferredRestartGeneration += 1
        deferredRestartScheduled = false
        lastRestartTime = MonotonicClock.now

        shutdownInternal()

        connectionRouter.clearRejectMarks()

        self.configuration = configuration
        configureRuntime(for: configuration)
        installLwipCallbacks()
        lwip_bridge_init()
        startTimeoutTimer()
        logger.debug("[TunnelStack] Restarted")
    }

    // MARK: - Settings Observation

    private func runSettingsObserver() async {
        let settings = AWNotificationCenter.Notification.tunnelSettingsChanged as String
        let routing = AWNotificationCenter.Notification.routingChanged as String
        let mitm = AWNotificationCenter.Notification.mitmChanged as String
        for await name in DarwinNotificationConcurrencyBridge.names([
            AWNotificationCenter.Notification.tunnelSettingsChanged,
            AWNotificationCenter.Notification.routingChanged,
            AWNotificationCenter.Notification.mitmChanged
        ]) {
            switch name {
            case settings: handleSettingsChanged()
            case routing: await handleRoutingChanged()
            case mitm: handleMITMChanged()
            default: break
            }
        }
    }

    private func handleSettingsChanged() {
        guard phase.isActive, let configuration else { return }

        let old = settings
        let new = TunnelSettings.load()
        guard new != old else { return }
        settings = new

        if new.quicPolicy != old.quicPolicy {
            logger.info("[VPN] QUIC policy changed: \(old.quicPolicy.rawValue) -> \(new.quicPolicy.rawValue)")
        }
        if new.blockUDP != old.blockUDP {
            logger.info("[VPN] Block UDP changed: \(old.blockUDP) -> \(new.blockUDP)")
        }
        if new.blockWebRTC != old.blockWebRTC {
            logger.info("[VPN] Block WebRTC changed: \(old.blockWebRTC) -> \(new.blockWebRTC)")
        }
        if new.preventDNSLeak != old.preventDNSLeak {
            logger.info("[VPN] Prevent DNS Leak changed: \(old.preventDNSLeak) -> \(new.preventDNSLeak)")
            connectionRouter.preventDNSLeak.store(new.preventDNSLeak, ordering: .relaxed)
        }
        if new.reflectionEnabled != old.reflectionEnabled || new.reflectionAddresses != old.reflectionAddresses {
            logger.info("[VPN] Reflection changed: enabled=\(new.reflectionEnabled), addresses=\(new.reflectionAddresses)")
            publishReflector()
        }
        if new.ipRuleDNSUpstream != old.ipRuleDNSUpstream {
            logger.info("[VPN] IP-rule DNS changed")
            RuleResolver.shared.setUpstream(new.ipRuleDNSUpstream)
        }
        if new.interceptExemptDNSServers != old.interceptExemptDNSServers {
            logger.info("[VPN] DNS interception exemptions changed: \(new.interceptExemptDNSServers.sorted())")
        }
        publishUDPConfig()

        if new.tunnelIncludedRoutes != old.tunnelIncludedRoutes || new.tunnelExcludedRoutes != old.tunnelExcludedRoutes {
            logger.info("[VPN] Custom routes changed: included=\(new.tunnelIncludedRoutes), excluded=\(new.tunnelExcludedRoutes)")
            requestReapplyTunnelSettings()
        }

        let proxyModeChanged = computeEffectiveProxyMode() != proxyMode
        let hideVPNIconChanged = new.hideVPNIcon != old.hideVPNIcon
        let advertiseIPv6ToAppsChanged = new.advertiseIPv6ToApps != old.advertiseIPv6ToApps

        guard proxyModeChanged || hideVPNIconChanged || advertiseIPv6ToAppsChanged else {
            return
        }

        logger.info("[VPN] Settings changed")

        if advertiseIPv6ToAppsChanged || hideVPNIconChanged {
            requestReapplyTunnelSettings()
        }

        restartStack(configuration: configuration)
    }

    private func handleRoutingChanged() async {
        guard phase.isActive else { return }
        guard proxyMode == .rule else { return }
        logger.info("[VPN] Routing changed")
        domainRouter.install(await domainRouter.compileRoutingConfiguration())
        connectionRouter.clearRejectMarks()
    }

    private func handleMITMChanged() {
        guard phase.isActive else { return }
        logger.info("[VPN] MITM settings changed")
        loadMITMSetting()
        publishUDPConfig()
    }
}
