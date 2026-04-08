//
//  LWIPStack+Lifecycle.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
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
            clearRecentTunnelInterruption()

            configureRuntime(for: configuration, shouldLoadProxyServerAddresses: true)
            registerCallbacks()
            lwip_bridge_init()
            startTimeoutTimer()
            startUDPCleanupTimer()
            startReadingPackets()
            logger.debug("[LWIPStack] Started, mode=\(proxyMode.rawValue), mux=\(muxManager != nil), ipv6dns=\(ipv6DNSEnabled), encryptedDNS=\(encryptedDNSEnabled), bypass=\(!bypassCountryCode.isEmpty)")
        }

        startObservingSettings()
    }

    /// Stops the lwIP stack and closes all active flows.
    func stop() {
        stopObservingSettings()
        lwipQueue.sync { [self] in
            running = false
            deferredRestart?.cancel()
            deferredRestart = nil
            shutdownInternal()
            fakeIPPool.reset()
            clearRecentTunnelInterruption()
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
            noteRecentTunnelInterruption(summary: "configuration switch", level: .info)
            restartStack(configuration: newConfiguration)
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
            noteRecentTunnelInterruption(summary: summary, level: .warning)
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

        outputPackets.removeAll(keepingCapacity: true)
        outputProtocols.removeAll(keepingCapacity: true)
        outputFlushScheduled = false
        outputWriteInFlight = false

        muxManager?.closeAll()
        muxManager = nil

        let flowCount = udpFlows.count
        for (_, flow) in udpFlows {
            flow.close()
        }
        udpFlows.removeAll()

        lwip_bridge_shutdown()
        logger.debug("[LWIPStack] Shutdown complete, closed \(flowCount) UDP flows")
    }

    /// Minimum interval between stack restarts (seconds).
    private static let restartThrottleInterval: CFAbsoluteTime = 1.0

    /// Tears down all connections and restarts the lwIP stack. Must be called on `lwipQueue`.
    ///
    /// Throttled to at most once per ``restartThrottleInterval``. When a restart is
    /// requested within the cooldown window the request is deferred; only the last
    /// deferred request executes (earlier ones are cancelled and replaced).
    private func restartStack(configuration: ProxyConfiguration) {
        let now = CFAbsoluteTimeGetCurrent()
        let elapsed = now - lastRestartTime

        if elapsed < Self.restartThrottleInterval {
            deferredRestart?.cancel()
            let delay = Self.restartThrottleInterval - elapsed
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
        configureRuntime(for: configuration, shouldLoadProxyServerAddresses: false)
        registerCallbacks()
        lwip_bridge_init()
        startTimeoutTimer()
        startUDPCleanupTimer()
        // Note: startReadingPackets() is NOT called here — the existing read loop
        // (started in start()) continues because `running` was never set to false.
        logger.debug("[LWIPStack] Restarted, mode=\(proxyMode.rawValue), mux=\(muxManager != nil), ipv6dns=\(ipv6DNSEnabled), encryptedDNS=\(encryptedDNSEnabled), bypass=\(!bypassCountryCode.isEmpty)")
    }

    // MARK: - Settings Observation
    //
    // Two Darwin notifications are observed. Both trigger a full stack restart
    // (shutdownInternal → restartStack), which closes all TCP/UDP connections
    // and re-reads settings. FakeIPPool is preserved — routing decisions are
    // made at connection time, so rule changes take effect immediately.
    //
    // 1. "settingsChanged" — posted by SettingsView when IPv6/Encrypted DNS/Country Bypass toggles change.
    //    IPv6 additionally re-applies tunnel network settings (routes + DNS servers).
    //
    // 2. "routingChanged" — posted by RuleSetListView when routing rule assignments change.

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
            TunnelConstants.Notification.settingsChanged,
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
            TunnelConstants.Notification.routingChanged,
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

    /// Handles the "settingsChanged" notification (ipv6/bypass/encrypted DNS toggles).
    /// Compares current values against UserDefaults and restarts the stack if changed.
    /// Stack restart closes all connections, clears FakeIPPool, and re-reads all settings.
    private func handleSettingsChanged() {
        lwipQueue.async { [self] in
            guard running, let configuration else { return }

            let ipv6DNSEnabled = AWCore.userDefaults.bool(forKey: TunnelConstants.UserDefaultsKey.ipv6DNSEnabled)
            let bypassCountryCode = AWCore.userDefaults.string(forKey: TunnelConstants.UserDefaultsKey.bypassCountryCode) ?? ""
            let encryptedDNSEnabled = AWCore.userDefaults.bool(forKey: TunnelConstants.UserDefaultsKey.encryptedDNSEnabled)
            let encryptedDNSProtocol = AWCore.userDefaults.string(forKey: TunnelConstants.UserDefaultsKey.encryptedDNSProtocol) ?? TunnelConstants.defaultEncryptedDNSProtocol
            let encryptedDNSServer = AWCore.userDefaults.string(forKey: TunnelConstants.UserDefaultsKey.encryptedDNSServer) ?? ""
            let proxyMode = AWCore.userDefaults.string(forKey: TunnelConstants.UserDefaultsKey.proxyMode).flatMap(ProxyMode.init) ?? .rule

            let ipv6DNSEnabledChanged = ipv6DNSEnabled != self.ipv6DNSEnabled
            let bypassCountryChanged = bypassCountryCode != self.bypassCountryCode
            let encryptedDNSEnabledChanged = encryptedDNSEnabled != self.encryptedDNSEnabled
            let encryptedDNSProtocolChanged = encryptedDNSProtocol != self.encryptedDNSProtocol
            let encryptedDNSServerChanged = encryptedDNSServer != self.encryptedDNSServer
            let proxyModeChanged = proxyMode != self.proxyMode

            guard ipv6DNSEnabledChanged || bypassCountryChanged || encryptedDNSEnabledChanged || encryptedDNSProtocolChanged || encryptedDNSServerChanged || proxyModeChanged else {
                return
            }

            var changedSettings: [String] = []
            if ipv6DNSEnabledChanged { changedSettings.append("IPv6 DNS") }
            if bypassCountryChanged { changedSettings.append("bypass country") }
            if encryptedDNSEnabledChanged || encryptedDNSProtocolChanged || encryptedDNSServerChanged {
                changedSettings.append("encrypted DNS")
            }
            if proxyModeChanged { changedSettings.append("proxy mode") }
            let changedSummary = changedSettings.joined(separator: ", ")
            logger.info("[VPN] Settings changed (\(changedSummary)); reconnecting active connections")
            noteRecentTunnelInterruption(summary: "settings change", level: .info)

            // IPv6 connections toggle affects tunnel network settings (IPv6 routes + DNS servers).
            // Encrypted DNS changes also affect tunnel settings (NEDNSOverHTTPSSettings / NEDNSOverTLSSettings).
            // Must re-apply via PacketTunnelProvider before restarting the stack.
            if ipv6DNSEnabledChanged || encryptedDNSEnabledChanged || encryptedDNSProtocolChanged || encryptedDNSServerChanged {
                onTunnelSettingsNeedReapply?()
            }

            restartStack(configuration: configuration)
        }
    }

    /// Handles the "routingChanged" notification (routing rule assignments changed).
    /// Restarts the stack to close all connections using outdated proxy configurations,
    /// rebuilds the FakeIPPool, and reloads DomainRouter rules from routing.json.
    /// Note: Do NOT call onTunnelSettingsNeedReapply here — setTunnelNetworkSettings
    /// should only be triggered by IPv6 changes (which affect tunnel routes and DNS servers).
    /// Routing changes do not alter NEPacketTunnelNetworkSettings.
    private func handleRoutingChanged() {
        lwipQueue.async { [self] in
            guard running, let configuration else { return }
            logger.info("[VPN] Routing changed; reconnecting active connections")
            noteRecentTunnelInterruption(summary: "routing change", level: .info)
            restartStack(configuration: configuration)
        }
    }
}
