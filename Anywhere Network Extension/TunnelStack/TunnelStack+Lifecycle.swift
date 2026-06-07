//
//  TunnelStack+Lifecycle.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import NetworkExtension

private let logger = AnywhereLogger(category: "TunnelStack")

extension TunnelStack {

    // MARK: - Lifecycle

    /// Starts the lwIP stack and begins reading packets from the tunnel.
    ///
    /// - Parameters:
    ///   - packetFlow: The tunnel's packet flow for reading/writing IP packets.
    ///   - configuration: The proxy configuration.
    func start(packetFlow: NEPacketTunnelFlow, configuration: ProxyConfiguration) {
        TunnelStack.shared = self
        AnywhereLogger.logSink = { [weak self] message, level in
            let logLevel: TunnelStack.LogLevel
            switch level {
            // `debug` is below `minimumSinkLevel`, so it never reaches the
            // sink; map it defensively to the lowest user-visible bucket in
            // case the floor is ever lowered.
            case .debug, .info: logLevel = .info
            case .warning: logLevel = .warning
            case .error: logLevel = .error
            }
            self?.appendLog(message, level: logLevel)
        }
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
            logger.debug("[TunnelStack] Started, mode=\(proxyMode.rawValue), mux=\(Self.shouldUseVisionMux(configuration)), advertiseIPv6=\(advertiseIPv6ToApps), encryptedDNS=\(encryptedDNSEnabled), bypass=\(!bypassCountryCode.isEmpty)")
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
            pendingNetworkRecovery?.cancel()
            pendingNetworkRecovery = nil
            shutdownInternal()
            fakeIPPool.reset()
        }

        AnywhereLogger.logSink = nil
        packetFlow = nil
        configuration = nil
        TunnelStack.shared = nil
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
    /// sockets held by each ``TCPConnection``. Those are what this
    /// method invalidates, leaving the rest of the stack running so idle
    /// flows and the FakeIP pool are preserved.
    ///
    /// Each TCP leg is closed gracefully (see ``invalidateOutboundState``):
    /// idle legs get a FIN, in-flight legs downgrade to a RST, and the proxy
    /// socket behind each is torn down. The netif and listener PCBs stay up,
    /// so new client activity is served without waiting on a netif rebuild.
    func handleWake() {
        lwipQueue.async { [self] in
            guard running, let configuration else { return }
            logger.info("[VPN] Device wake: invalidating outbound proxy state")
            invalidateOutboundState(configuration: configuration)
        }
    }

    /// Releases the dead upstream transports when the network goes away
    /// (`.unsatisfied`) or the device sleeps — the "down edge" companion to
    /// ``invalidateOutboundState``'s "up edge". The kernel has torn down, or is
    /// about to tear down, their sockets, so the Vision mux's long-lived TCP,
    /// the QUIC/Hysteria/HTTP3/AnyTLS sessions, the Shadowsocks UDP sessions, and
    /// the per-flow UDP proxy connections are dead weight; freeing them promptly
    /// stops us pinning sockets we can't use for the duration of the outage.
    ///
    /// Deliberately conservative: it does NOT re-resolve DNS or rebuild the mux
    /// (there's no path to dial over) and does NOT force-close the app-facing TCP
    /// legs. A leg riding a freed shared session (Hysteria/Nowhere/AnyTLS/HTTP3, or a
    /// UDP-over-mux flow) sees a graceful downlink EOF — ``MuxManager/closeAll``
    /// and friends deliver no error — and winds down on its own; a leg actively
    /// writing when its session drops aborts on the failed send; per-connection
    /// VLESS legs and direct (bypass) legs are simply left open. Whatever is still
    /// open is closed gracefully and the transports rebuilt when the path returns
    /// or the device wakes, via ``invalidateOutboundState``. Hops onto `lwipQueue`
    /// internally, where all transport state (including ``muxManager``) is owned,
    /// so it serialises against connection accepts and dials.
    func suspendOutbound() {
        lwipQueue.async { [self] in
            guard running else { return }
            logger.info("[VPN] Path offline/sleep: releasing upstream transports; will rebuild when it returns")

            HysteriaClient.closeAll()
            NowhereClient.closeAll()
            AnyTLSManager.shared.closeAll()
            HTTP3SessionPool.shared.closeAll()

            // The Vision mux, SS UDP sessions, and per-flow UDP state are
            // udpQueue-owned, so release them there. The sync hop is
            // deadlock-free: udpQueue work never sync-waits back on lwipQueue.
            udpQueue.sync {
                muxManager?.closeAll()
                muxManager = nil
                purgeShadowsocksUDPSessions()
                for (_, flow) in udpFlows {
                    flow.close()
                }
                udpFlows.removeAll()
            }
        }
    }

    /// Recovers active connections after the network path changes (interface
    /// switch, restored from unavailable, Wi-Fi roam, NAT rebind). Like device
    /// wake, the lwIP netif, listeners, and timers all survive — only the
    /// outbound sockets are stranded on network state that no longer exists —
    /// so this runs the same lightweight ``invalidateOutboundState`` rather
    /// than a full stack restart. Each app-facing TCP leg is closed gracefully
    /// (FIN for idle legs, RST only for in-flight ones), so apps reconnect over
    /// the new path without a blanket reset.
    ///
    /// Debounced by ``TunnelConstants/networkRecoveryDebounceInterval``: the
    /// leading edge fires immediately, and a burst of updates within the window
    /// (typical of a handoff) coalesces into a single trailing recovery. Only
    /// the last deferred request runs.
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

    /// Runs the outbound-state invalidation for a settled network path and
    /// stamps the debounce clock. Must be called on `lwipQueue`.
    private func performNetworkRecovery(summary: String) {
        pendingNetworkRecovery?.cancel()
        pendingNetworkRecovery = nil
        lastNetworkRecoveryTime = CFAbsoluteTimeGetCurrent()
        guard let configuration else { return }
        logger.warning("[VPN] Recovering connections after \(summary)")
        invalidateOutboundState(configuration: configuration)
    }

    /// Re-resolves the cached DNS answers and invalidates all outbound
    /// transport state — the Vision mux, QUIC/Hysteria/HTTP3/AnyTLS sessions,
    /// Shadowsocks UDP sessions, per-flow UDP proxy connections, and every
    /// active TCP leg — while leaving the lwIP netif, listeners, and timers
    /// running. Must be called on `lwipQueue`.
    ///
    /// Shared by device-wake and network-path-change recovery: both face the
    /// same problem (the kernel's outbound sockets are bound to network state
    /// that no longer exists) and neither needs the local stack rebuilt.
    /// Rather than RST every app-facing leg, each TCP connection is closed
    /// gracefully via ``lwip_bridge_for_each_tcp`` + ``TCPConnection/close()``:
    /// idle legs receive a FIN and reconnect transparently, while in-flight
    /// legs downgrade to a RST that triggers idempotent retries. The netif and
    /// listener PCBs stay up, so new client activity is served without waiting
    /// on a netif rebuild.
    private func invalidateOutboundState(configuration: ProxyConfiguration) {
        // Cached DNS answers were resolved over the network path we're leaving
        // and may not route on the new one (GeoDNS/CDN locality, split-horizon
        // DNS, captive-portal answers). Drop every cached host so the next dial
        // over the new path takes a fresh lookup: the first connection to each
        // host pays one cold resolve, but it's guaranteed an answer that routes
        // on the current network rather than a stale cross-network IP — the
        // safer trade-off while reconnecting.
        DNSResolver.shared.flush()

        // Gracefully close every app-facing TCP leg before tearing down the
        // upstream transports below. close() flushes already-received downlink
        // bytes, then tcp_close sends a FIN to idle legs — the client reconnects
        // on its next request, seamlessly — and lets lwIP downgrade in-flight
        // legs (unacknowledged rx data) to a RST, an unambiguous error that
        // drives idempotent retries. Closing first sets `closed` on each
        // connection synchronously (we're on lwipQueue), so the upstream
        // teardown's error completions become no-ops and can't pre-empt a
        // graceful FIN into a RST. No ERR_ABRT callbacks fire — tcp_close clears
        // the PCB callbacks before closing — so `isTearingDown` is unnecessary
        // here, unlike the abort path in shutdownInternal.
        lwip_bridge_for_each_tcp { arg in
            guard let arg else { return }
            Unmanaged<TCPConnection>.fromOpaque(arg).takeUnretainedValue().close()
        }

        HysteriaClient.closeAll()
        NowhereClient.closeAll()
        AnyTLSManager.shared.closeAll()
        HTTP3SessionPool.shared.closeAll()

        // The Vision mux, SS UDP sessions, and per-flow UDP state are
        // udpQueue-owned. Tear them down and rebuild the mux on that queue:
        // serialized against flow processing, so a flow handled after this finds
        // the mux ready, while one caught mid-churn is torn down with the rest
        // (wake / path-change resets connections regardless).
        let useMux = Self.shouldUseVisionMux(configuration)
        udpQueue.sync {
            muxManager?.closeAll()
            muxManager = useMux ? MuxManager(configuration: configuration, flowQueue: udpQueue) : nil
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
            // Data deallocator is .none, so the release fns are the only
            // way to free the pbufs/buffers. Synchronous calls are safe:
            // shutdownInternal runs inside ``lwipQueue.sync``.
            for r in pendingReleases {
                r.fn(r.ctx)
            }
            pendingReleases.removeAll(keepingCapacity: true)
            outputDrainInFlight = false
        }

        HysteriaClient.closeAll()
        NowhereClient.closeAll()
        HTTP3SessionPool.shared.closeAll()

        // mux / SS sessions / flows are udpQueue-owned — close them there and
        // wait, so they're fully released before lwip_bridge_shutdown tears down
        // the stack. The sync hop is deadlock-free: no udpQueue work ever
        // sync-waits back on lwipQueue.
        udpQueue.sync {
            muxManager?.closeAll()
            muxManager = nil
            purgeShadowsocksUDPSessions()
            for (_, flow) in udpFlows {
                flow.close()
            }
            udpFlows.removeAll()
        }

        isTearingDown = true
        lwip_bridge_shutdown()
        isTearingDown = false
        logger.debug("[TunnelStack] Shutdown complete")
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
            logger.debug("[TunnelStack] Restart throttled, deferred by \(String(format: "%.0f", delay * 1000))ms")
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
        logger.debug("[TunnelStack] Restarted, mode=\(proxyMode.rawValue), mux=\(Self.shouldUseVisionMux(configuration)), advertiseIPv6=\(advertiseIPv6ToApps), encryptedDNS=\(encryptedDNSEnabled), bypass=\(!bypassCountryCode.isEmpty)")
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

    /// Handles the "tunnelSettingsChanged" notification (ipv6/bypass/encrypted DNS toggles).
    /// Compares current values against UserDefaults and restarts the stack if changed.
    /// Stack restart closes all connections, clears FakeIPPool, and re-reads all settings.
    private func handleSettingsChanged() {
        lwipQueue.async { [self] in
            guard running, let configuration else { return }
            
            let proxyMode = AWCore.getProxyMode()
            let bypassCountryCode = AWCore.getBypassCountryCode()
            let hideVPNIcon = AWCore.getHideVPNIcon()
            let advertiseIPv6ToApps = AWCore.getAdvertiseIPv6ToApps()
            let encryptedDNSEnabled = AWCore.getEncryptedDNSEnabled()
            let encryptedDNSProtocol = AWCore.getEncryptedDNSProtocol()
            let encryptedDNSServer = AWCore.getEncryptedDNSServer()

            // QUIC policy only drives the per-datagram UDP/443 decision, read
            // on this queue in handleInboundUDP — reload it in place rather
            // than restarting the stack (which would drop every connection).
            let quicPolicy = AWCore.getQUICPolicy()
            if quicPolicy != self.quicPolicy {
                logger.info("[VPN] QUIC policy changed: \(self.quicPolicy.rawValue) -> \(quicPolicy.rawValue)")
                self.quicPolicy = quicPolicy
                // Propagate to the UDP snapshot — the per-datagram UDP/443
                // decision in handleInboundUDP reads it from there. This may be
                // the only change (the guard below returns without a restart),
                // so republish here rather than relying on configureRuntime.
                publishUDPConfig()
            }

            // Reflection is a pure read-path setting: reflection happens
            // in the read callback off the published snapshot, with no effect on
            // tunnel network settings or any connection state. Reload it in place
            // like quicPolicy rather than restarting the stack (which would drop
            // every connection); this may also be the only change, so it must
            // run before the change-detection guard below.
            let reflectionEnabled = AWCore.getReflectionEnabled()
            let reflectionAddresses = AWCore.getReflectionAddresses()
            if reflectionEnabled != self.reflectionEnabled || reflectionAddresses != self.reflectionAddresses {
                logger.info("[VPN] Reflection changed: enabled=\(reflectionEnabled), addresses=\(reflectionAddresses)")
                self.reflectionEnabled = reflectionEnabled
                self.reflectionAddresses = reflectionAddresses
                publishReflector()
            }

            let proxyModeChanged = proxyMode != self.proxyMode
            let bypassCountryChanged = bypassCountryCode != self.bypassCountryCode
            let hideVPNIconChanged = hideVPNIcon != self.hideVPNIcon
            let advertiseIPv6ToAppsChanged = advertiseIPv6ToApps != self.advertiseIPv6ToApps
            let encryptedDNSEnabledChanged = encryptedDNSEnabled != self.encryptedDNSEnabled
            let encryptedDNSProtocolChanged = encryptedDNSProtocol != self.encryptedDNSProtocol
            let encryptedDNSServerChanged = encryptedDNSServer != self.encryptedDNSServer

            guard proxyModeChanged || bypassCountryChanged || hideVPNIconChanged || advertiseIPv6ToAppsChanged || encryptedDNSEnabledChanged || encryptedDNSProtocolChanged || encryptedDNSServerChanged else {
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
    /// valid under any rule edit and new flows pick up the new rules on their
    /// next accept callback. The reload runs on lwipQueue but takes
    /// DomainRouter's internal lock, so a concurrent UDP new-flow lookup on
    /// udpQueue never observes a half-rebuilt table.
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
    /// `lwipQueue` to serialize against connection accept callbacks. Each MITM
    /// session snapshots its matching rules when the connection opens (see
    /// ``MITMHTTP1Stream/init`` and the HTTP/2 rewriter), so a reload takes
    /// effect on the **next new connection**: an already-open keep-alive /
    /// HTTP/2 / SSE connection keeps the rule snapshot it started with until it
    /// closes. Rule-set deletions also drop the corresponding
    /// ``MITMScriptStore`` buckets. See the ``startObservingSettings`` comment
    /// for the full picture.
    fileprivate func handleMITMChanged() {
        lwipQueue.async { [self] in
            guard running else { return }
            logger.info("[VPN] MITM settings changed; reloading matcher")
            loadMITMSetting()
            // `mitmEnabled` gates the UDP/443 MITM decision via the snapshot;
            // republish so udpQueue sees the new toggle (the matcher itself is
            // shared by reference and already reloaded under its own lock).
            publishUDPConfig()
        }
    }
}
