//
//  TunnelStack+Lifecycle.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import NetworkExtension

nonisolated private let logger = AnywhereLogger(category: "TunnelStack+Lifecycle")

extension TunnelStack {

    // MARK: - Lifecycle

    func start(packetFlow: NEPacketTunnelFlow, configuration: ProxyConfiguration) {
        TunnelStack.shared = self
        AnywhereLogger.logSink = { [weak self] message, level in
            let logLevel: TunnelStack.LogLevel
            switch level {
            // `debug` never reaches the sink; mapped defensively.
            case .debug, .info: logLevel = .info
            case .warning: logLevel = .warning
            case .error: logLevel = .error
            }
            self?.appendLog(message, level: logLevel)
        }
        PerformanceMonitor.start()
        self.packetFlow = packetFlow
        self.configuration = configuration

        lwipQueue.async { [self] in
            running = true

            configureRuntime(for: configuration)
            registerCallbacks()
            lwip_bridge_init()
            startTimeoutTimer()
            startUDPCleanupTimer()
            installFDPressureReliefHandler()
            startReadingPackets()
            logger.debug("[TunnelStack] Started, mode=\(proxyMode.rawValue), advertiseIPv6=\(advertiseIPv6ToApps), encryptedDNS=\(encryptedDNSEnabled), bypass=\(!bypassCountryCode.isEmpty)")
        }

        startObservingSettings()
        CertificatePolicy.startObserving()
    }

    func stop() {
        stopObservingSettings()
        clearFDPressureReliefHandler()
        lwipQueue.sync { [self] in
            running = false
            deferredRestart?.cancel()
            deferredRestart = nil
            pendingNetworkRecovery?.cancel()
            pendingNetworkRecovery = nil
            shutdownInternal()
            fakeIPPool.reset()
        }

        AnywhereLogger.logSink = nil
        PerformanceMonitor.stop()
        packetFlow = nil
        configuration = nil
        TunnelStack.shared = nil
    }

    /// Restarts the stack on the existing packet flow under the new configuration.
    func switchConfiguration(_ newConfiguration: ProxyConfiguration) {
        lwipQueue.async { [self] in
            logger.info("[VPN] Configuration switched; reconnecting active connections")
            restartStack(configuration: newConfiguration)
        }
    }

    /// Invalidates outbound proxy state after device wake: the kernel tears
    /// down our outbound sockets across sleep, but in-process lwIP state survives.
    func handleWake() {
        lwipQueue.async { [self] in
            guard running, let configuration else { return }
            logger.info("[VPN] Device wake: invalidating outbound proxy state")
            invalidateOutboundState(configuration: configuration)
        }
    }

    /// Releases upstream transports on sleep/path-down — the kernel tears down
    /// their sockets, so holding them just pins FDs. No mux rebuild (no path to
    /// dial over) and no force-close of app-facing TCP legs.
    func suspendOutbound() {
        lwipQueue.async { [self] in
            guard running else { return }
            logger.info("[VPN] Path offline/sleep: releasing upstream transports; will rebuild when it returns")

            TransportReclaim.reclaimAll()
            reclaimInstanceTransports(rebuildMultiplexerPool: false)
        }
    }

    /// Recovers connections after a network path change (only outbound sockets
    /// are stranded — no full restart). Debounced: leading edge fires
    /// immediately; a burst coalesces into one trailing recovery.
    func handleNetworkPathChange(summary: String) {
        lwipQueue.async { [self] in
            guard running, configuration != nil else { return }

            let now = CFAbsoluteTimeGetCurrent()
            let elapsed = now - lastNetworkRecoveryTime

            if elapsed < TunnelConstants.networkRecoveryDebounceInterval {
                pendingNetworkRecovery?.cancel()
                let delay = TunnelConstants.networkRecoveryDebounceInterval - elapsed
                let work = DispatchWorkItem { [self] in
                    pendingNetworkRecovery = nil
                    guard running else { return }
                    performNetworkRecovery(summary: summary)
                }
                pendingNetworkRecovery = work
                lwipQueue.asyncAfter(deadline: .now() + delay, execute: work)
                logger.debug("[TunnelStack] Network recovery debounced, deferred by \(String(format: "%.0f", delay * 1000))ms")
                return
            }

            performNetworkRecovery(summary: summary)
        }
    }

    /// Caches the egress identity and re-derives the effective mode. A change in
    /// effective mode restarts the stack so new connections use the new outbound.
    func updateNetworkContext(isWiFi: Bool, isCellular: Bool, ssid: String?) {
        lwipQueue.async { [self] in
            guard running, let configuration else { return }

            let unchanged = isWiFi == currentNetworkIsWiFi
                && isCellular == currentNetworkIsCellular
                && ssid == currentSSID
            currentNetworkIsWiFi = isWiFi
            currentNetworkIsCellular = isCellular
            currentSSID = ssid
            guard !unchanged else { return }

            let newEffective = computeEffectiveProxyMode()
            guard newEffective != proxyMode else { return }
            logger.info("[VPN] Trusted-network policy: effective mode \(proxyMode.rawValue) → \(newEffective.rawValue) (Wi-Fi=\(isWiFi), cellular=\(isCellular), SSID=\(ssid ?? "—"))")
            restartStack(configuration: configuration, revalidateMode: true)
        }
    }

    /// Runs the recovery and stamps the debounce clock. Must be called on `lwipQueue`.
    private func performNetworkRecovery(summary: String) {
        pendingNetworkRecovery?.cancel()
        pendingNetworkRecovery = nil
        lastNetworkRecoveryTime = CFAbsoluteTimeGetCurrent()
        guard let configuration else { return }
        logger.warning("[VPN] Recovering connections after \(summary)")
        invalidateOutboundState(configuration: configuration)
    }

    /// Flushes cached DNS and invalidates all outbound transport state while
    /// leaving the lwIP netif, listeners, and timers running. Must be called
    /// on `lwipQueue`.
    private func invalidateOutboundState(configuration: ProxyConfiguration) {
        // Cached answers may not route on the new path; flush so the next dial re-resolves.
        DNSResolver.shared.flush()

        // Close app-facing TCP legs BEFORE tearing down upstreams: close() sets
        // `closed` synchronously (on lwipQueue), so teardown error completions
        // can't pre-empt a graceful FIN into a RST.
        lwip_bridge_for_each_tcp { arg in
            guard let arg else { return }
            Unmanaged<TCPConnection>.fromOpaque(arg).takeUnretainedValue().close()
        }

        TransportReclaim.reclaimAll()
        reclaimInstanceTransports(rebuildMultiplexerPool: true)
    }

    /// Reclaims the udpQueue-owned per-tunnel transports (Vision mux, SS UDP
    /// sessions, per-flow UDP connections). Must be called on `lwipQueue`.
    private func reclaimInstanceTransports(rebuildMultiplexerPool: Bool) {
        // Build the replacement mux on lwipQueue, which owns `configuration`.
        let rebuiltMultiplexerPool: VLESSVisionUDPMultiplexerPool?
        if rebuildMultiplexerPool, let configuration, configuration.outboundProtocol == .vless {
            rebuiltMultiplexerPool = VLESSVisionUDPMultiplexerPool(configuration: configuration, flowQueue: udpQueue)
        } else {
            rebuiltMultiplexerPool = nil
        }

        udpQueue.sync {
            udpMultiplexerPool?.closeAll()
            udpMultiplexerPool = rebuiltMultiplexerPool
            purgeShadowsocksUDPSessions()
            for (_, flow) in udpFlows {
                flow.close()
            }
            udpFlows.removeAll()
        }
    }

    /// Shuts down the lwIP stack and all active flows. Must be called on `lwipQueue`.
    private func shutdownInternal() {
        timeoutTimer?.cancel()
        if lwipTickSuspended {
            lwipTickSuspended = false
            timeoutTimer?.resume()
        }
        timeoutTimer = nil
        udpCleanupTimer?.cancel()
        udpCleanupTimer = nil

        outputBufferLock.withLock {
            outputPackets.removeAll(keepingCapacity: true)
            outputProtocols.removeAll(keepingCapacity: true)
            // The release fns are the only owners (.none deallocator); calling
            // them synchronously is safe — we're on `lwipQueue`.
            for r in pendingReleases {
                r.fn(r.ctx)
            }
            pendingReleases.removeAll(keepingCapacity: true)
            outputDrainInFlight = false
        }

        TransportReclaim.reclaimAll()
        reclaimInstanceTransports(rebuildMultiplexerPool: false)

        isTearingDown = true
        lwip_bridge_shutdown()
        isTearingDown = false
        logger.debug("[TunnelStack] Shutdown complete")
    }

    /// Tears down all connections and restarts the lwIP stack. Must be called on `lwipQueue`.
    /// Throttled to once per restartThrottleInterval; only the last deferred request runs.
    private func restartStack(configuration: ProxyConfiguration, revalidateMode: Bool = false) {
        // A trusted-network restart is redundant when one is already pending — that
        // restart re-derives the effective mode from the current egress when it runs.
        if revalidateMode, deferredRestart != nil { return }

        let now = CFAbsoluteTimeGetCurrent()
        let elapsed = now - lastRestartTime

        if elapsed < TunnelConstants.restartThrottleInterval {
            deferredRestart?.cancel()
            let delay = TunnelConstants.restartThrottleInterval - elapsed
            let work = DispatchWorkItem { [self] in
                deferredRestart = nil
                guard running else { return }
                // The egress (and effective mode) may have reverted within the
                // throttle window; skip the teardown when it already matches.
                if revalidateMode, computeEffectiveProxyMode() == proxyMode { return }
                restartStackNow(configuration: configuration)
            }
            deferredRestart = work
            lwipQueue.asyncAfter(deadline: .now() + delay, execute: work)
            logger.debug("[TunnelStack] Restart throttled, deferred by \(String(format: "%.0f", delay * 1000))ms")
            return
        }

        restartStackNow(configuration: configuration)
    }

    /// Performs the actual stack restart. Must be called on `lwipQueue`.
    /// `running` stays `true` so the existing read loop continues; the FakeIP
    /// pool is preserved — routing is decided at connection time, so cached
    /// fake IPs stay valid.
    private func restartStackNow(configuration: ProxyConfiguration) {
        deferredRestart?.cancel()
        deferredRestart = nil
        lastRestartTime = CFAbsoluteTimeGetCurrent()

        shutdownInternal()

        self.configuration = configuration
        configureRuntime(for: configuration)
        registerCallbacks()
        lwip_bridge_init()
        startTimeoutTimer()
        startUDPCleanupTimer()
        logger.debug("[TunnelStack] Restarted, mode=\(proxyMode.rawValue), advertiseIPv6=\(advertiseIPv6ToApps), encryptedDNS=\(encryptedDNSEnabled), bypass=\(!bypassCountryCode.isEmpty)")
    }

    // MARK: - Settings Observation
    //
    // Three Darwin notifications: "tunnelSettingsChanged" restarts the stack;
    // "routingChanged" and "mitmChanged" reload in place — routing/MITM
    // decisions bind when a connection opens, so already-open connections
    // deliberately keep their old rules until they close.

    private func startObservingSettings() {
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            Unmanaged.passUnretained(self).toOpaque(),
            { _, observer, _, _, _ in
                guard let observer else { return }
                let stack = Unmanaged<TunnelStack>.fromOpaque(observer).takeUnretainedValue()
                stack.handleSettingsChanged()
            },
            AWCore.Notification.tunnelSettingsChanged,
            nil,
            .deliverImmediately
        )

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            Unmanaged.passUnretained(self).toOpaque(),
            { _, observer, _, _, _ in
                guard let observer else { return }
                let stack = Unmanaged<TunnelStack>.fromOpaque(observer).takeUnretainedValue()
                stack.handleRoutingChanged()
            },
            AWCore.Notification.routingChanged,
            nil,
            .deliverImmediately
        )

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            Unmanaged.passUnretained(self).toOpaque(),
            { _, observer, _, _, _ in
                guard let observer else { return }
                let stack = Unmanaged<TunnelStack>.fromOpaque(observer).takeUnretainedValue()
                stack.handleMITMChanged()
            },
            AWCore.Notification.mitmChanged,
            nil,
            .deliverImmediately
        )
    }

    private func stopObservingSettings() {
        CFNotificationCenterRemoveEveryObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            Unmanaged.passUnretained(self).toOpaque()
        )
    }

    /// Restarts the stack when a restart-requiring toggle changed; QUIC, Block
    /// WebRTC, and Reflection changes instead reload in place.
    private func handleSettingsChanged() {
        lwipQueue.async { [self] in
            guard running, let configuration else { return }
            
            let baseProxyMode = AWCore.getProxyMode()
            let trustedSSIDs = Set(AWCore.getTrustedSSIDs())
            let alwaysUntrustCellular = AWCore.getAlwaysUntrustCellular()
            // Keep the inputs current even when the effective mode is unchanged, so a
            // later network transition derives the mode from fresh settings.
            self.baseProxyMode = baseProxyMode
            self.trustedSSIDs = trustedSSIDs
            self.alwaysUntrustCellular = alwaysUntrustCellular
            let effectiveProxyMode = computeEffectiveProxyMode(base: baseProxyMode,
                                                               trusted: trustedSSIDs,
                                                               untrustCellular: alwaysUntrustCellular)
            let hideVPNIcon = AWCore.getHideVPNIcon()
            let advertiseIPv6ToApps = AWCore.getAdvertiseIPv6ToApps()
            let encryptedDNSEnabled = AWCore.getEncryptedDNSEnabled()
            let encryptedDNSProtocol = AWCore.getEncryptedDNSProtocol()
            let encryptedDNSServer = AWCore.getEncryptedDNSServer()

            // QUIC policy only drives the per-datagram UDP/443 decision —
            // reload in place rather than dropping every connection.
            let quicPolicy = AWCore.getQUICPolicy()
            if quicPolicy != self.quicPolicy {
                logger.info("[VPN] QUIC policy changed: \(self.quicPolicy.rawValue) -> \(quicPolicy.rawValue)")
                self.quicPolicy = quicPolicy
                // May be the only change (the guard below returns without a
                // restart), so republish the UDP snapshot here.
                publishUDPConfig()
            }

            // Block WebRTC only drives the per-datagram STUN check; reload in
            // place, before the change-detection guard below.
            let blockWebRTC = AWCore.getBlockWebRTC()
            if blockWebRTC != self.blockWebRTC {
                logger.info("[VPN] Block WebRTC changed: \(self.blockWebRTC) -> \(blockWebRTC)")
                self.blockWebRTC = blockWebRTC
                publishUDPConfig()
            }

            // Reflection is a pure read-path setting; reload in place, before
            // the change-detection guard below.
            let reflectionEnabled = AWCore.getReflectionEnabled()
            let reflectionAddresses = AWCore.getReflectionAddresses()
            if reflectionEnabled != self.reflectionEnabled || reflectionAddresses != self.reflectionAddresses {
                logger.info("[VPN] Reflection changed: enabled=\(reflectionEnabled), addresses=\(reflectionAddresses)")
                self.reflectionEnabled = reflectionEnabled
                self.reflectionAddresses = reflectionAddresses
                publishReflector()
            }

            let proxyModeChanged = effectiveProxyMode != self.proxyMode
            let hideVPNIconChanged = hideVPNIcon != self.hideVPNIcon
            let advertiseIPv6ToAppsChanged = advertiseIPv6ToApps != self.advertiseIPv6ToApps
            let encryptedDNSEnabledChanged = encryptedDNSEnabled != self.encryptedDNSEnabled
            let encryptedDNSProtocolChanged = encryptedDNSProtocol != self.encryptedDNSProtocol
            let encryptedDNSServerChanged = encryptedDNSServer != self.encryptedDNSServer

            guard proxyModeChanged || hideVPNIconChanged || advertiseIPv6ToAppsChanged || encryptedDNSEnabledChanged || encryptedDNSProtocolChanged || encryptedDNSServerChanged else {
                return
            }
            
            logger.info("[VPN] Settings changed, reconnecting active connections")

            // These toggles change tunnel network settings (routes/DNS);
            // re-apply them before restarting the stack.
            if advertiseIPv6ToAppsChanged || encryptedDNSEnabledChanged || encryptedDNSProtocolChanged || encryptedDNSServerChanged || hideVPNIconChanged {
                onTunnelSettingsNeedReapply?()
            }

            restartStack(configuration: configuration)
        }
    }

    /// Reloads the routing rules in place — no restart; routing binds at
    /// connection accept, so active flows stay valid. No-op unless in rule mode
    /// (global and trusted-network direct reset the router and ignore rules).
    private func handleRoutingChanged() {
        lwipQueue.async { [self] in
            guard running else { return }
            guard proxyMode == .rule else { return }
            logger.info("[VPN] Routing changed; reloading rules in place")
            domainRouter.loadRoutingConfiguration()
        }
    }

    /// Rebuilds the MITM matcher in place on `lwipQueue` — no restart; sessions
    /// snapshot their rules at connection open, so only new connections see the change.
    fileprivate func handleMITMChanged() {
        lwipQueue.async { [self] in
            guard running else { return }
            logger.info("[VPN] MITM settings changed; reloading matcher")
            loadMITMSetting()
            // `mitmEnabled` gates the UDP/443 MITM decision via the snapshot;
            // republish so udpQueue sees the new toggle.
            publishUDPConfig()
        }
    }
}
