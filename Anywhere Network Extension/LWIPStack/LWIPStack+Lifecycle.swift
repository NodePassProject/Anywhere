//
//  LWIPStack+Lifecycle.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import NetworkExtension

private let logger = AnywhereLogger(category: "LWIPStack")

extension LWIPStack {

    // MARK: - Lifecycle

    /// Starts the lwIP stack and begins reading packets from the tunnel.
    ///
    /// - Parameters:
    ///   - packetFlow: The tunnel's packet flow for reading/writing IP packets.
    ///   - configuration: The proxy configuration.
    func start(packetFlow: NEPacketTunnelFlow, configuration: ProxyConfiguration) {
        LWIPStack.shared = self
        AnywhereLogger.logSink = { [weak self] message, level in
            let logLevel: LWIPStack.LogLevel
            switch level {
            case .info: logLevel = .info
            case .warning: logLevel = .warning
            case .error: logLevel = .error
            }
            self?.appendLog(message, level: logLevel)
        }
        self.packetFlow = packetFlow
        self.configuration = configuration

        lwipQueue.async { [self] in
            running = true
            totalBytesIn = 0
            totalBytesOut = 0

            configureRuntime(for: configuration)
            registerCallbacks()
            lwip_bridge_init()
            startTimeoutTimer()
            startUDPCleanupTimer()
            installFDPressureReliefHandler()
            startReadingPackets()
            logger.debug("[LWIPStack] Started, mode=\(proxyMode.rawValue), mux=\(muxManager != nil), advertiseIPv6=\(advertiseIPv6ToApps), encryptedDNS=\(encryptedDNSEnabled), bypass=\(!bypassCountryCode.isEmpty)")
        }

        startObservingSettings()
        CertificatePolicy.startObserving()
    }

    /// Stops the lwIP stack and closes all active flows.
    func stop() {
        stopObservingSettings()
        clearFDPressureReliefHandler()
        lwipQueue.sync { [self] in
            running = false
            deferredRestart?.cancel()
            deferredRestart = nil
            shutdownInternal()
            fakeIPPool.reset()
        }

        AnywhereLogger.logSink = nil
        packetFlow = nil
        configuration = nil
        LWIPStack.shared = nil
    }

    /// Switches to a new configuration, tearing down all active connections.
    ///
    /// Shuts down the lwIP stack and all VLESS connections, then restarts
    /// with the new configuration using the existing packet flow.
    func switchConfiguration(_ newConfiguration: ProxyConfiguration) {
        lwipQueue.async { [self] in
            logger.info("[VPN] Configuration switched; reconnecting active connections")
            restartStack(configuration: newConfiguration)
        }
    }

    /// Invalidates outbound proxy state after the device wakes from sleep.
    ///
    /// The lwIP netif, listeners, timers, and routing state all survive
    /// suspension intact — they live in our own memory, not the kernel's.
    /// What the kernel does tear down is outbound sockets: the Vision mux's
    /// long-lived TCP, per-flow UDP proxy connections, and the transport
    /// sockets held by each ``LWIPTCPConnection``. Those are what this
    /// method invalidates, leaving the rest of the stack running so idle
    /// flows and the FakeIP pool are preserved.
    ///
    /// TCP flows are aborted via ``lwip_bridge_abort_all_tcp`` so each PCB's
    /// err callback releases its Swift side (which closes the now-dead proxy
    /// socket). The netif and listener PCBs stay up, so new client activity
    /// is served without waiting on a netif rebuild.
    func handleWake() {
        lwipQueue.async { [self] in
            guard running, let configuration else { return }
            logger.info("[VPN] Device wake: invalidating outbound proxy state")

            muxManager?.closeAll()
            if Self.shouldUseVisionMux(configuration) {
                muxManager = MuxManager(configuration: configuration, lwipQueue: lwipQueue)
            } else {
                muxManager = nil
            }
            
            HysteriaClient.closeAll()
            AnyTLSManager.shared.closeAll()
            purgeShadowsocksUDPSessions()
            HTTP3SessionPool.shared.closeAll()

            for (_, flow) in udpFlows {
                flow.close()
            }
            udpFlows.removeAll()

            isTearingDown = true
            lwip_bridge_abort_all_tcp()
            isTearingDown = false
        }
    }

    /// Tears down all active connections and restarts the stack on the current
    /// configuration. Called when the network path changes significantly
    /// (interface switch or restored from unavailable) so that stale
    /// connections bound to the old interface are replaced immediately.
    func handleNetworkPathChange(summary: String) {
        lwipQueue.async { [self] in
            guard running, let configuration else { return }
            logger.warning("[VPN] Restarting stack after \(summary)")
            restartStack(configuration: configuration)
        }
    }

    /// Shuts down the lwIP stack and all active flows. Must be called on `lwipQueue`.
    /// Does NOT change `running` — callers manage it:
    /// - `stop()` sets `running = false` before calling (kills the packet read loop).
    /// - `restartStack()` leaves `running = true` (existing read loop continues).
    ///
    /// Note: Does NOT reset FakeIPPool. Callers handle pool lifecycle:
    /// - `stop()` calls `fakeIPPool.reset()` (full teardown, no reconnections expected).
    /// - `restartStack()` preserves pool as-is (routing decisions are made at connection time).
    private func shutdownInternal() {
        totalBytesIn = 0
        totalBytesOut = 0

        timeoutTimer?.cancel()
        timeoutTimer = nil
        udpCleanupTimer?.cancel()
        udpCleanupTimer = nil

        outputBufferLock.withLock {
            outputPackets.removeAll(keepingCapacity: true)
            outputProtocols.removeAll(keepingCapacity: true)
            // Data deallocator is .none, so the release fns are the only
            // way to free the pbufs/buffers. Synchronous calls are safe:
            // shutdownInternal runs inside ``lwipQueue.sync``.
            for r in pendingReleases {
                r.fn(r.ctx)
            }
            pendingReleases.removeAll(keepingCapacity: true)
            outputDrainInFlight = false
        }

        muxManager?.closeAll()
        muxManager = nil

        purgeShadowsocksUDPSessions()
        HysteriaClient.closeAll()
        HTTP3SessionPool.shared.closeAll()
        
        for (_, flow) in udpFlows {
            flow.close()
        }
        udpFlows.removeAll()

        isTearingDown = true
        lwip_bridge_shutdown()
        isTearingDown = false
        logger.debug("[LWIPStack] Shutdown complete")
    }

    /// Tears down all connections and restarts the lwIP stack. Must be called on `lwipQueue`.
    ///
    /// Throttled to at most once per ``TunnelConstants/restartThrottleInterval``. When a restart is
    /// requested within the cooldown window the request is deferred; only the last
    /// deferred request executes (earlier ones are cancelled and replaced).
    private func restartStack(configuration: ProxyConfiguration) {
        let now = CFAbsoluteTimeGetCurrent()
        let elapsed = now - lastRestartTime

        if elapsed < TunnelConstants.restartThrottleInterval {
            deferredRestart?.cancel()
            let delay = TunnelConstants.restartThrottleInterval - elapsed
            let work = DispatchWorkItem { [self] in
                deferredRestart = nil
                guard running else { return }
                restartStackNow(configuration: configuration)
            }
            deferredRestart = work
            lwipQueue.asyncAfter(deadline: .now() + delay, execute: work)
            logger.debug("[LWIPStack] Restart throttled, deferred by \(String(format: "%.0f", delay * 1000))ms")
            return
        }

        restartStackNow(configuration: configuration)
    }

    /// Performs the actual stack restart. Must be called on `lwipQueue`.
    /// `running` stays `true` so the existing `readPackets` loop continues uninterrupted —
    /// packets queued on lwipQueue during reinit are processed after `lwip_bridge_init()`.
    /// FakeIPPool is preserved across restarts — since all DNS queries get fake IPs and
    /// routing decisions are made at connection time, cached fake IPs remain valid.
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
        // Note: startReadingPackets() is NOT called here — the existing read loop
        // (started in start()) continues because `running` was never set to false.
        logger.debug("[LWIPStack] Restarted, mode=\(proxyMode.rawValue), mux=\(muxManager != nil), advertiseIPv6=\(advertiseIPv6ToApps), encryptedDNS=\(encryptedDNSEnabled), bypass=\(!bypassCountryCode.isEmpty)")
    }

    // MARK: - Settings Observation
    //
    // Three Darwin notifications are observed. Only "tunnelSettingsChanged"
    // triggers a full stack restart; the other two reload in place to avoid
    // tearing down active connections for edits that don't invalidate them.
    //
    // 1. "tunnelSettingsChanged" — posted by SettingsView when IPv6/Encrypted DNS/Country Bypass toggles change.
    //    Triggers a full stack restart (shutdownInternal → restartStack),
    //    which closes all TCP/UDP connections and re-reads settings.
    //    FakeIPPool is preserved. IPv6 additionally re-applies tunnel
    //    network settings (routes + DNS servers).
    //
    // 2. "routingChanged" — posted whenever routing rules or rule-set
    //    assignments change. Does NOT restart the stack: routing decisions
    //    are made at connection accept time, so already-established flows
    //    remain valid under any rule edit. The DomainRouter rule tiers and
    //    configuration map are rebuilt in place on lwipQueue so the reload
    //    serializes against new accept callbacks. New connections pick up
    //    the new rules immediately; existing connections keep running over
    //    their already-chosen proxy (or DIRECT path) until they close
    //    naturally. This means an assignment change from Proxy A to Proxy B
    //    only affects future connections — active flows on Proxy A continue
    //    until they end. We accept this drift because the alternative
    //    (killing every connection on every rule edit) is the very
    //    disruption this change exists to eliminate.
    //
    // 3. "mitmChanged" — posted by MITMSnapshot.save() when the MITM toggle or
    //    rules change. Does NOT restart the stack: connections in flight keep
    //    their TLS legs and lwIP state. The in-memory hostname matcher is
    //    rebuilt in place on lwipQueue so it serializes against new accept
    //    callbacks. Note that the policy is shared by reference with every
    //    live MITMSession, so active sessions DO pick up the new rules on
    //    their next request head (the rewriters re-query
    //    ``MITMRewritePolicy.rules(for:phase:)`` per message), and the
    //    MITMScriptStore buckets for rule sets the user just deleted are
    //    purged immediately — any active scripts on those sets lose their
    //    in-memory ``Anywhere.store`` state. We accept this drift over the
    //    alternative (snapshotting the policy per session) because the
    //    expected use case is short-lived connections plus deliberate edits
    //    during script development, where seeing the new rules apply
    //    promptly is the desired behaviour.

    /// Registers Darwin notification observers for cross-process settings changes.
    private func startObservingSettings() {
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            Unmanaged.passUnretained(self).toOpaque(),
            { _, observer, _, _, _ in
                guard let observer else { return }
                let stack = Unmanaged<LWIPStack>.fromOpaque(observer).takeUnretainedValue()
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
                let stack = Unmanaged<LWIPStack>.fromOpaque(observer).takeUnretainedValue()
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
                let stack = Unmanaged<LWIPStack>.fromOpaque(observer).takeUnretainedValue()
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

    /// Handles the "tunnelSettingsChanged" notification (ipv6/bypass/encrypted DNS toggles).
    /// Compares current values against UserDefaults and restarts the stack if changed.
    /// Stack restart closes all connections, clears FakeIPPool, and re-reads all settings.
    private func handleSettingsChanged() {
        lwipQueue.async { [self] in
            guard running, let configuration else { return }
            
            let proxyMode = AWCore.getProxyMode()
            let bypassCountryCode = AWCore.getBypassCountryCode()
            let hideVPNIcon = AWCore.getHideVPNIcon()
            let blockQUICEnabled = AWCore.getBlockQUICEnabled()
            let advertiseIPv6ToApps = AWCore.getAdvertiseIPv6ToApps()
            let encryptedDNSEnabled = AWCore.getEncryptedDNSEnabled()
            let encryptedDNSProtocol = AWCore.getEncryptedDNSProtocol()
            let encryptedDNSServer = AWCore.getEncryptedDNSServer()

            let proxyModeChanged = proxyMode != self.proxyMode
            let bypassCountryChanged = bypassCountryCode != self.bypassCountryCode
            let hideVPNIconChanged = hideVPNIcon != self.hideVPNIcon
            let blockQUICEnabledChanged = blockQUICEnabled != self.blockQUICEnabled
            let advertiseIPv6ToAppsChanged = advertiseIPv6ToApps != self.advertiseIPv6ToApps
            let encryptedDNSEnabledChanged = encryptedDNSEnabled != self.encryptedDNSEnabled
            let encryptedDNSProtocolChanged = encryptedDNSProtocol != self.encryptedDNSProtocol
            let encryptedDNSServerChanged = encryptedDNSServer != self.encryptedDNSServer

            guard proxyModeChanged || bypassCountryChanged || hideVPNIconChanged || blockQUICEnabledChanged || advertiseIPv6ToAppsChanged || encryptedDNSEnabledChanged || encryptedDNSProtocolChanged || encryptedDNSServerChanged else {
                return
            }
            
            logger.info("[VPN] Settings changed, reconnecting active connections")

            // IPv6 connections toggle affects tunnel network settings (IPv6 routes + DNS servers).
            // Encrypted DNS changes also affect tunnel settings (NEDNSOverHTTPSSettings / NEDNSOverTLSSettings).
            // Hide VPN Icon toggles IPv4 route shape and IPv6 claim, also tunnel settings.
            // Must re-apply via PacketTunnelProvider before restarting the stack.
            if advertiseIPv6ToAppsChanged || encryptedDNSEnabledChanged || encryptedDNSProtocolChanged || encryptedDNSServerChanged || hideVPNIconChanged {
                onTunnelSettingsNeedReapply?()
            }

            restartStack(configuration: configuration)
        }
    }

    /// Handles the "routingChanged" notification (routing rules or rule-set assignments changed).
    ///
    /// Reloads DomainRouter rules and configurations in place — no stack
    /// restart, no FakeIPPool rebuild, no connection teardown. In global
    /// mode the router is unused, so the notification is a no-op. Routing
    /// decisions are made at connection accept time, so active flows stay
    /// valid under any rule edit and new flows pick up the new rules on
    /// their next accept callback (serialized by lwipQueue).
    ///
    /// Do NOT call onTunnelSettingsNeedReapply here — setTunnelNetworkSettings
    /// should only be triggered by IPv6 changes (which affect tunnel routes
    /// and DNS servers). Routing changes do not alter
    /// NEPacketTunnelNetworkSettings.
    private func handleRoutingChanged() {
        lwipQueue.async { [self] in
            guard running else { return }
            guard proxyMode != .global else { return }
            logger.info("[VPN] Routing changed; reloading rules in place")
            domainRouter.loadRoutingConfiguration()
        }
    }

    /// Handles the "mitmChanged" notification (MITM toggle or rules changed).
    ///
    /// No stack restart is needed — we rebuild the matcher in place on
    /// `lwipQueue` to serialize against connection accept callbacks. Live
    /// sessions share the policy object by reference, so they pick up the
    /// new rules on their next request head; rule-set deletions also drop
    /// the corresponding ``MITMScriptStore`` buckets. See the
    /// ``startObservingSettings`` comment for the full picture.
    fileprivate func handleMITMChanged() {
        lwipQueue.async { [self] in
            guard running else { return }
            logger.info("[VPN] MITM settings changed; reloading matcher")
            loadMITMSetting()
        }
    }
}
