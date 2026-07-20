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
    
    func start(packetFlow: NEPacketTunnelFlow, configuration: ProxyConfiguration) async {
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

        _running.store(true, ordering: .relaxed)

        var precompiledRouting: DomainRouter.CompiledRouting?
        if Self.effectiveProxyMode(settings: TunnelSettings.load(), network: networkContext) == .rule {
            precompiledRouting = await domainRouter.compileRoutingConfiguration()
        }
        configureRuntime(for: configuration, precompiledRouting: precompiledRouting)

        lwipBridge.installCallbacks(host: self)
        lwipBridge.initEngine()
        startTimeoutTimer()
        // Spawned last; the output kicks and plane commands raised while the runtime configured
        // are buffered in their streams, so the tree loses nothing by starting late.
        rootTask = Task { await self.run(packetFlow: packetFlow, udpPlane: udpPlane) }
        logger.debug("[TunnelStack] Started")

        CertificatePolicy.startObserving()
    }

    // MARK: - Task tree

    /// The stack's task tree. The plane-command driver sits beside the duty cycle, not inside it:
    /// shutdown must finish the command channel and let the driver drain the final `.reclaim`
    /// (which closes the UDP flows) — cancelling it mid-drain would drop buffered commands.
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

    /// The full-duty children plus on-demand nursery jobs. ``stop()`` finishing ``nurseryJobs``
    /// ends the job loop; the `cancelAll` then stops intake (read, drain, observer, cleanup, and
    /// any pending deferred restart) and the group joins before ``finishShutdown()`` tears the
    /// engine down — so nothing feeds a half-shut engine.
    private func runDutyCycle(packetFlow: NEPacketTunnelFlow, udpPlane: UDPPlane) async {
        await withDiscardingTaskGroup { group in
            // Output drain: awaits ``outputKick`` and drains the buffer to utun off the lwIP/UDP
            // queues so producers never block on `writePackets`. One consumer keeps it serial.
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
                        await self.runDeferredRestart(configuration: configuration,
                                                      revalidateMode: revalidateMode,
                                                      delay: delay, generation: generation)
                    }
                }
            }
            group.cancelAll()
        }
    }

    /// The ordered teardown, run on the actor once the duty cycle has ended.
    private func finishShutdown() {
        shutdownInternal()  // submits the final `.reclaim` to the plane driver
        // After shutdown so the teardown's own callbacks (RSTs, errors) still reach the stack.
        lwipBridge.clearHost()
        OutboundConnector.setRoutingContext(nil)
        fakeIPPool.reset()
        configuration = nil
        // Finish the command channel so the driver drains its buffered commands (including the
        // final reclaim that closes the UDP flows) and ends — the last child of the tree.
        finishPlaneCommands()
    }

    /// Tears the stack down by ending its task tree: finishing ``nurseryJobs`` stops the duty
    /// cycle (intake ends before the engine teardown), the tree runs ``finishShutdown()`` on the
    /// actor, and the plane driver drains the final reclaim before the root completes — so the
    /// UDP plane teardown is done when this returns. The await releases the lwIP queue while the
    /// tree winds down.
    func stop() async {
        _running.store(false, ordering: .relaxed)
        nurseryJobContinuation.finish()
        await rootTask?.value
        rootTask = nil

        AnywhereLogger.installLogSink(nil)
        // `packetFlow` is deliberately kept: the output-drain loop and the packet-read loop hold
        // captured references, so dropping it here would race a late transport completion. The
        // reference dies with the provider, which owns both objects.
    }

    /// Restarts the stack on the existing packet flow under the new configuration.
    func switchConfiguration(_ newConfiguration: ProxyConfiguration) {
        logger.info("[VPN] Configuration switched")
        restartStack(configuration: newConfiguration)
    }

    /// Invalidates outbound proxy state after device wake: the kernel tears
    /// down our outbound sockets across sleep, but in-process lwIP state survives.
    func handleWake() {
        // Wake catch-up: the cleanup loop fires promptly if its interval fell due while frozen.
        udpCleanupPoke.yield(())
        guard running, let configuration else { return }
        logger.info("[VPN] Device wake")
        invalidateOutboundState(configuration: configuration)
    }

    /// Releases upstream transports on sleep/path-down — the kernel tears down
    /// their sockets, so holding them just pins FDs. No mux rebuild (no path to
    /// dial over) and no force-close of app-facing TCP legs.
    func suspendOutbound() {
        guard running else { return }
        logger.info("[VPN] Path offline/sleep")

        reclaimAllOutboundPools()
        reclaimInstanceTransports(rebuildMultiplexerPool: false)
    }

    /// Rebuilds the instance upstream transports `suspendOutbound` released and flushes
    /// stale DNS, once the path returns. Pooled and app-facing legs are left to their
    /// viability handlers; pooled transports rebuild on the next dial.
    func resumeOutbound() {
        guard running, configuration != nil else { return }
        logger.info("[VPN] Path restored")
        DNSResolver.shared.flush()
        reclaimInstanceTransports(rebuildMultiplexerPool: true)
    }

    /// Caches the egress identity and re-derives the effective mode. A change in
    /// effective mode restarts the stack so new connections use the new outbound.
    func updateNetworkContext(isWiFi: Bool, isCellular: Bool, ssid: String?) {
        guard running, let configuration else { return }

        let context = NetworkContext(isWiFi: isWiFi, isCellular: isCellular, ssid: ssid)
        guard context != networkContext else { return }
        networkContext = context

        let newEffective = computeEffectiveProxyMode()
        guard newEffective != proxyMode else { return }
        logger.info("[VPN] Trusted-network policy: effective mode \(proxyMode.rawValue) → \(newEffective.rawValue) (Wi-Fi=\(isWiFi), cellular=\(isCellular), SSID=\(ssid ?? "—"))")
        restartStack(configuration: configuration, revalidateMode: true)
    }

    /// Flushes cached DNS and invalidates all outbound transport state while
    /// leaving the lwIP netif, listeners, and timers running.
    private func invalidateOutboundState(configuration: ProxyConfiguration) {
        // Cached answers may not route on the new path; flush so the next dial re-resolves.
        DNSResolver.shared.flush()

        // Close app-facing TCP legs BEFORE tearing down upstreams: close() sets
        // `closed` synchronously (on lwipQueue), so teardown error completions
        // can't pre-empt a graceful FIN into a RST.
        lwipBridge.closeAllActiveTCP()

        reclaimAllOutboundPools()
        reclaimInstanceTransports(rebuildMultiplexerPool: true)
    }

    /// Reclaims process-wide outbound pools: `TransportReclaim` (Shared) plus the extension-only
    /// script `fetch` HTTP/2 pool, which Shared can't see.
    private func reclaimAllOutboundPools() {
        TransportReclaim.reclaimAll()
        MITMScriptHTTP2Pool.shared.reclaim()
    }

    /// Reclaims the UDP plane's per-tunnel transports (Vision mux, SS UDP sessions, per-flow UDP
    /// connections) and installs the rebuilt mux. The teardown runs on ``udpPlane`` (serialized
    /// against intake), submitted through the ordered command channel so it can't be reordered
    /// against a restart's follow-up `setMultiplexerPool`.
    private func reclaimInstanceTransports(rebuildMultiplexerPool: Bool) {
        // Build the replacement mux on the stack actor, which owns `configuration`.
        let rebuiltMultiplexerPool: VLESSVisionUDPMultiplexerPool?
        if rebuildMultiplexerPool, let configuration, configuration.outboundProtocol == .vless {
            rebuiltMultiplexerPool = VLESSVisionUDPMultiplexerPool(configuration: configuration)
        } else {
            rebuiltMultiplexerPool = nil
        }
        submitPlaneCommand(.reclaim(replacementMultiplexerPool: rebuiltMultiplexerPool))
    }

    /// Shuts down the lwIP stack and all active flows.
    private func shutdownInternal() {
        // `BridgeTimer.cancel` balances any outstanding suspend before tearing the source down.
        lwipTick?.cancel()
        lwipTick = nil

        outputBuffer.withLock { buffer in
            buffer.packets.removeAll(keepingCapacity: true)
            buffer.protocols.removeAll(keepingCapacity: true)
            // The release fns are the only owners (.none deallocator); calling
            // them synchronously is safe — we're on `lwipQueue`.
            for r in buffer.releases {
                r.fn(r.ctx)
            }
            buffer.releases.removeAll(keepingCapacity: true)
            buffer.drainInFlight = false
        }

        reclaimAllOutboundPools()
        reclaimInstanceTransports(rebuildMultiplexerPool: false)

        _isTearingDown.store(true, ordering: .relaxed)
        lwipBridge.shutdownEngine()
        _isTearingDown.store(false, ordering: .relaxed)
        logger.debug("[TunnelStack] Shutdown complete")
    }

    /// Tears down all connections and restarts the lwIP stack. Throttled to once per
    /// restartThrottleInterval; only the last deferred request runs.
    private func restartStack(configuration: ProxyConfiguration, revalidateMode: Bool = false) {
        // A trusted-network restart is redundant when one is already pending — that
        // restart re-derives the effective mode from the current egress when it runs.
        if revalidateMode, deferredRestartScheduled { return }

        let now = CFAbsoluteTimeGetCurrent()
        let elapsed = now - lastRestartTime

        if elapsed < TunnelConstants.restartThrottleInterval {
            let delay = TunnelConstants.restartThrottleInterval - elapsed
            // A nursery job rather than a stored task: the fresh generation supersedes any earlier
            // deferred request (only the last one runs), and the duty cycle's teardown cancels the
            // job's sleep with the rest of the tree.
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

    /// The deferred-restart nursery job: sleeps off the throttle window, then restarts if still
    /// the current request.
    private func runDeferredRestart(configuration: ProxyConfiguration, revalidateMode: Bool,
                                    delay: TimeInterval, generation: Int) async {
        try? await Task.sleep(for: .seconds(delay))
        guard !Task.isCancelled else { return }
        guard generation == deferredRestartGeneration else { return }  // superseded
        deferredRestartScheduled = false
        guard running else { return }
        // The egress (and effective mode) may have reverted within the throttle window;
        // skip the teardown when it already matches.
        if revalidateMode, computeEffectiveProxyMode() == proxyMode { return }
        restartStackNow(configuration: configuration)
    }

    /// Performs the actual stack restart. `running` stays `true` so the existing read loop
    /// continues; the FakeIP pool is preserved — routing is decided at connection time, so cached
    /// fake IPs stay valid.
    private func restartStackNow(configuration: ProxyConfiguration) {
        // An immediate restart supersedes any pending deferred one.
        deferredRestartGeneration += 1
        deferredRestartScheduled = false
        lastRestartTime = CFAbsoluteTimeGetCurrent()

        shutdownInternal()

        self.configuration = configuration
        configureRuntime(for: configuration)
        lwipBridge.installCallbacks(host: self)
        lwipBridge.initEngine()
        startTimeoutTimer()
        logger.debug("[TunnelStack] Restarted")
    }

    // MARK: - Settings Observation

    /// Duty-cycle child: applies Darwin settings/routing/MITM notifications on the actor. Ends on
    /// cancellation — the stream's `onTermination` unregisters the CFNotificationCenter observers.
    private func runSettingsObserver() async {
        // Names precomputed once for the switch; `DarwinNotificationConcurrencyBridge` yields the
        // posted name and keeps the CFNotificationCenter/`Unmanaged` glue inside the bridge.
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
        guard running, let configuration else { return }

        let old = settings
        let new = TunnelSettings.load()
        guard new != old else { return }
        // Committed even when only trusted-network inputs changed, so a
        // later network transition derives the mode from fresh settings.
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
            connectionRouter.setPreventDNSLeak(new.preventDNSLeak)
        }
        if new.reflectionEnabled != old.reflectionEnabled || new.reflectionAddresses != old.reflectionAddresses {
            logger.info("[VPN] Reflection changed: enabled=\(new.reflectionEnabled), addresses=\(new.reflectionAddresses)")
            publishReflector()
        }
        // Several live flags ride the UDP snapshot; republish once for
        // whichever changed.
        publishUDPConfig()

        // Custom routes only change the tunnel network settings — reapply
        // in place, before the restart guard below.
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

        // These toggles change tunnel network settings (routes/DNS);
        // re-apply them before restarting the stack.
        if advertiseIPv6ToAppsChanged || hideVPNIconChanged {
            requestReapplyTunnelSettings()
        }

        restartStack(configuration: configuration)
    }
    
    private func handleRoutingChanged() async {
        guard running else { return }
        guard proxyMode == .rule else { return }
        logger.info("[VPN] Routing changed")
        domainRouter.install(await domainRouter.compileRoutingConfiguration())
    }
    
    private func handleMITMChanged() {
        guard running else { return }
        logger.info("[VPN] MITM settings changed")
        loadMITMSetting()
        publishUDPConfig()
    }
}
