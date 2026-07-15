//
//  PacketTunnelProvider.swift
//  Anywhere
//
//  Created by NodePassProject on 1/23/26.
//

import NetworkExtension
import Network
#if os(iOS)
import WidgetKit
#endif

nonisolated private let logger = AnywhereLogger(category: "PacketTunnelProvider")

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let tunnelStack = TunnelStack()
    private let statsRecorder = StatsRecorder()
    private let pathMonitorQueue = DispatchQueue(label: AWCore.Identifier.pathMonitorQueue)
    private var pathMonitor: NWPathMonitor?
    /// Last observed path status; nil before the first update.
    private var lastPathStatus: Network.NWPath.Status?

    /// True while `suspendOutbound` has released transports for the current outage;
    /// drives the symmetric `resumeOutbound` on the up edge.
    private var outboundSuspended = false

    // MARK: - Tunnel Lifecycle
    
    override func startTunnel(options: [String : NSObject]? = nil) async throws {
        // App starts pass the configuration in `options`; Settings/On-Demand starts
        // pass nil, so fall back to the last persisted configuration.
        let configuration: ProxyConfiguration?
        if let messageData = options?[TunnelMessage.optionKey] as? Data,
           case .setConfiguration(let config) = try? JSONDecoder().decode(TunnelMessage.self, from: messageData) {
            configuration = config
        } else if let savedData = AWCore.getLastConfigurationData() {
            configuration = try? JSONDecoder().decode(ProxyConfiguration.self, from: savedData)
        } else {
            configuration = nil
        }
        
        guard let configuration else {
            logger.error("[VPN] Invalid or missing configuration")
            throw NSError(domain: AWCore.Identifier.errorDomain, code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid configuration"])
        }
        
        tunnelStack.onTunnelSettingsNeedReapply = { [weak self] in
            self?.reapplyTunnelSettings()
        }
        
        let settings = buildTunnelSettings()
        
        Task {
            do {
                try await setTunnelNetworkSettings(settings)
                
#if os(iOS)
                ControlCenter.shared.reloadControls(ofKind: "com.argsment.Anywhere.Widget.VPNToggle")
#endif
                
                self.tunnelStack.start(packetFlow: self.packetFlow,
                                       configuration: configuration)
                self.startMonitoringPath()
                self.statsRecorder.start { [weak self] in
                    return StatsRecorder.RawValues(
                        byteCounts: self?.tunnelStack.byteCounts ?? TrafficByteCounts(),
                        tcpConnectionCount: FlowGauge.liveTCP,
                        udpConnectionCount: FlowGauge.liveUDP,
                        memoryBytes: Self.memoryFootprint()
                    )
                }
            } catch {
                logger.error("[VPN] Failed to set tunnel settings: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Tunnel Settings

    private func buildTunnelSettings() -> NEPacketTunnelNetworkSettings {
        let tunnelAddressIPv4 = TunnelConstants.tunnelAddressIPv4
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelAddressIPv4)

        let hideVPNIcon = AWCore.getHideVPNIcon()
        let includedRoutes = Self.parseRoutes(AWCore.getTunnelIncludedRoutes())
        let excludedRoutes = Self.parseRoutes(AWCore.getTunnelExcludedRoutes())

        let ipv4Settings = NEIPv4Settings(addresses: [tunnelAddressIPv4], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()] + includedRoutes.ipv4
        var excludedIPv4Routes = excludedRoutes.ipv4
        if hideVPNIcon {
            excludedIPv4Routes.append(NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "255.255.255.254"))
        }
        ipv4Settings.excludedRoutes = excludedIPv4Routes
        settings.ipv4Settings = ipv4Settings

        // Claiming IPv6 tunnel settings makes iOS show the VPN icon on cellular,
        // so we drop IPv6 entirely (custom routes included) when hideVPNIcon is enabled.
        let advertiseIPv6ToApps = AWCore.getAdvertiseIPv6ToApps() && !hideVPNIcon
        if advertiseIPv6ToApps {
            let ipv6Settings = NEIPv6Settings(addresses: [TunnelConstants.tunnelAddressIPv6], networkPrefixLengths: [64])
            ipv6Settings.includedRoutes = [NEIPv6Route.default()] + includedRoutes.ipv6
            ipv6Settings.excludedRoutes = excludedRoutes.ipv6
            settings.ipv6Settings = ipv6Settings
        }

        // Plain DNS is intercepted by lwIP on UDP/53; an in-tunnel server address
        // keeps queries reachable only through utun, so they cannot leak.
        let plainDNSServers: [String]
        if advertiseIPv6ToApps {
            plainDNSServers = [tunnelAddressIPv4, TunnelConstants.tunnelAddressIPv6]
        } else {
            plainDNSServers = [tunnelAddressIPv4]
        }

        settings.dnsSettings = NEDNSSettings(servers: plainDNSServers)
        settings.mtu = 1500

        return settings
    }

    /// Parses user-configured route strings ("address" or "address/prefix").
    private static func parseRoutes(_ strings: [String]) -> (ipv4: [NEIPv4Route], ipv6: [NEIPv6Route]) {
        var ipv4Routes: [NEIPv4Route] = []
        var ipv6Routes: [NEIPv6Route] = []

        for string in strings {
            if string.contains(":") {
                if let route = parseIPv6Route(string) {
                    ipv6Routes.append(route)
                }
            } else if let route = parseIPv4Route(string) {
                ipv4Routes.append(route)
            }
        }

        return (ipv4: ipv4Routes, ipv6: ipv6Routes)
    }

    /// Host bits beyond the prefix are zeroed.
    private static func parseIPv4Route(_ string: String) -> NEIPv4Route? {
        let parts = string.split(separator: "/", maxSplits: 1)
        guard let addressPart = parts.first else { return nil }
        var address = in_addr()
        guard inet_pton(AF_INET, String(addressPart), &address) == 1 else { return nil }

        var prefixLength = 32
        if parts.count == 2 {
            guard let parsed = Int(parts[1]), (0...32).contains(parsed) else { return nil }
            prefixLength = parsed
        }

        let mask: UInt32 = prefixLength == 0 ? 0 : ~UInt32(0) << (32 - prefixLength)
        let network = UInt32(bigEndian: address.s_addr) & mask
        return NEIPv4Route(destinationAddress: dottedQuad(network), subnetMask: dottedQuad(mask))
    }

    /// Host bits beyond the prefix are zeroed.
    private static func parseIPv6Route(_ string: String) -> NEIPv6Route? {
        let parts = string.split(separator: "/", maxSplits: 1)
        guard let addressPart = parts.first else { return nil }
        var address = in6_addr()
        guard inet_pton(AF_INET6, String(addressPart), &address) == 1 else { return nil }

        var prefixLength = 128
        if parts.count == 2 {
            guard let parsed = Int(parts[1]), (0...128).contains(parsed) else { return nil }
            prefixLength = parsed
        }

        withUnsafeMutableBytes(of: &address) { bytes in
            for byteIndex in bytes.indices {
                let bitPosition = byteIndex * 8
                if bitPosition >= prefixLength {
                    bytes[byteIndex] = 0
                } else if bitPosition + 8 > prefixLength {
                    bytes[byteIndex] &= ~UInt8(0) << (8 - (prefixLength - bitPosition))
                }
            }
        }

        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else { return nil }
        return NEIPv6Route(destinationAddress: String(cString: buffer), networkPrefixLength: NSNumber(value: prefixLength))
    }

    private static func dottedQuad(_ value: UInt32) -> String {
        "\((value >> 24) & 0xFF).\((value >> 16) & 0xFF).\((value >> 8) & 0xFF).\(value & 0xFF)"
    }

    /// Re-applies tunnel settings from current UserDefaults; resets the virtual
    /// interface and flushes the OS DNS cache.
    private func reapplyTunnelSettings() {
        let settings = buildTunnelSettings()
        setTunnelNetworkSettings(settings) { error in
            if let error {
                logger.error("[VPN] Failed to reapply tunnel settings: \(error.localizedDescription)")
            } else {
                logger.info("[VPN] Tunnel settings reapplied")
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
#if os(iOS)
        ControlCenter.shared.reloadControls(ofKind: "com.argsment.Anywhere.Widget.VPNToggle")
#endif
        
        statsRecorder.stop()
        stopMonitoringPath()
        logTunnelStop(reason: reason)
        tunnelStack.stop()
    }

    // MARK: - App Messages

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let message = try? JSONDecoder().decode(TunnelMessage.self, from: messageData) else {
            completionHandler?(nil)
            return
        }

        switch message {
        case .setConfiguration(let configuration):
            tunnelStack.switchConfiguration(configuration)
            completionHandler?(nil)

        case .testLatency(let configuration):
            Task {
                let result = await LatencyTester.test(configuration)
                let response = LatencyTestResponse(result)
                completionHandler?(try? JSONEncoder().encode(response))
            }

        case .fetchStats:
            let response = statsRecorder.snapshot()
            completionHandler?(try? JSONEncoder().encode(response))

        case .fetchLogs:
            let response = LogsResponse(logs: tunnelStack.fetchLogs())
            completionHandler?(try? JSONEncoder().encode(response))

        case .fetchRequests:
            let response = RequestsResponse(requests: tunnelStack.requestLog.snapshot())
            completionHandler?(try? JSONEncoder().encode(response))
        }
    }

    /// Memory footprint in bytes (`phys_footprint`, the figure jetsam uses for the
    /// extension's tight budget); 0 if the Mach call fails.
    private static func memoryFootprint() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size
        )
        let kr = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), intPtr, &count)
            }
        }
        return kr == KERN_SUCCESS ? info.phys_footprint : 0
    }

    override func sleep() async {
        statsRecorder.noteSleep()
        tunnelStack.suspendOutbound()
    }

    override func wake() {
        statsRecorder.noteWake()
        tunnelStack.handleWake()
    }

    // MARK: - Path Monitoring

    private func startMonitoringPath() {
        guard pathMonitor == nil else { return }

        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            self?.handlePathUpdate(path)
        }
        monitor.start(queue: pathMonitorQueue)
        pathMonitor = monitor
    }

    private func stopMonitoringPath() {
        pathMonitor?.cancel()
        pathMonitor = nil
        lastPathStatus = nil
        outboundSuspended = false
    }

    /// Hands the egress identity (incl. Wi-Fi SSID on iOS) to the stack for the
    /// trusted-network policy. `availableInterfaces.first` is the OS-preferred egress.
    private func resolveAndUpdateNetworkContext(_ path: Network.NWPath) {
        let primaryType = path.availableInterfaces.first?.type
        let isWiFi = primaryType == .wifi
        let isCellular = primaryType == .cellular
#if os(iOS)
        if isWiFi {
            // Requires the "Access WiFi Information" entitlement; otherwise `ssid`
            // is nil and the network is treated as untrusted.
            NEHotspotNetwork.fetchCurrent { [weak self] network in
                self?.tunnelStack.updateNetworkContext(isWiFi: true, isCellular: false, ssid: network?.ssid)
            }
            return
        }
#endif
        tunnelStack.updateNetworkContext(isWiFi: isWiFi, isCellular: isCellular, ssid: nil)
    }

    /// Applies the trusted-network policy, releases upstream transports while the
    /// path is down, and rebuilds them (flushing stale DNS) when it returns. Per-leg
    /// recovery is left to the NW transports' viability handlers.
    private func handlePathUpdate(_ path: Network.NWPath) {
        let previousStatus = lastPathStatus
        lastPathStatus = path.status

        switch path.status {
        case .satisfied:
            resolveAndUpdateNetworkContext(path)

            if outboundSuspended {
                // Up edge: rebuild the transports suspendOutbound released; flush stale DNS.
                outboundSuspended = false
                logger.info("[VPN] Network path restored: \(Self.pathSummary(path))")
                tunnelStack.resumeOutbound()
            } else if previousStatus == nil {
                logger.info("[VPN] Network path ready: \(Self.pathSummary(path))")
            }
            // Otherwise satisfied→satisfied (e.g. an egress move): per-connection
            // viability retires any stranded leg, so there's no global teardown.

            if reasserting {
                reasserting = false
            }

        case .requiresConnection:
            // Dedupe repeated callbacks in the same state; nothing to recover onto yet.
            guard previousStatus != .requiresConnection else { return }
            logger.warning("[VPN] Network path waiting for attachment\(Self.unsatisfiedSuffix(path))")
            reasserting = true

        case .unsatisfied:
            // Idempotent on repeated unsatisfied callbacks.
            guard !outboundSuspended else { return }
            outboundSuspended = true
            logger.warning("[VPN] Network path unavailable\(Self.unsatisfiedSuffix(path))")
            reasserting = true
            // Down edge: release dead upstream transports; rebuilt on the up edge.
            tunnelStack.suspendOutbound()

        @unknown default:
            logger.warning("[VPN] Network path changed unexpectedly")
        }
    }

    private func logTunnelStop(reason: NEProviderStopReason) {
        let message: String
        let level: TunnelLogLevel

        switch reason {
        case .userInitiated:
            message = "[VPN] Tunnel stopped by user"
            level = .info
        case .providerFailed:
            message = "[VPN] Tunnel stopped because the provider failed"
            level = .error
        case .noNetworkAvailable:
            message = "[VPN] Tunnel stopped because the network became unavailable"
            level = .warning
        case .unrecoverableNetworkChange:
            message = "[VPN] Tunnel stopped because the network path changed"
            level = .warning
        case .providerDisabled:
            message = "[VPN] Tunnel stopped because the provider was disabled"
            level = .warning
        case .authenticationCanceled:
            message = "[VPN] Tunnel stopped because authentication was canceled"
            level = .warning
        case .configurationFailed:
            message = "[VPN] Tunnel stopped because configuration failed"
            level = .error
        case .idleTimeout:
            message = "[VPN] Tunnel stopped after being idle"
            level = .warning
        case .configurationDisabled:
            message = "[VPN] Tunnel stopped because the configuration was disabled"
            level = .warning
        case .configurationRemoved:
            message = "[VPN] Tunnel stopped because the configuration was removed"
            level = .warning
        case .superceded:
            message = "[VPN] Tunnel stopped because another VPN took over"
            level = .warning
        case .userLogout:
            message = "[VPN] Tunnel stopped because the user logged out"
            level = .warning
        case .userSwitch:
            message = "[VPN] Tunnel stopped because the active user changed"
            level = .warning
        case .connectionFailed:
            message = "[VPN] Tunnel stopped because the VPN connection failed"
            level = .warning
        case .sleep:
            message = "[VPN] Tunnel stopped for device sleep"
            level = .warning
        case .appUpdate:
            message = "[VPN] Tunnel stopped for app update"
            level = .info
        case .internalError:
            message = "[VPN] Tunnel stopped because Network Extension hit an internal error"
            level = .error
        case .none:
            message = "[VPN] Tunnel stopped"
            level = .info
        @unknown default:
            message = "[VPN] Tunnel stopped for an unknown reason"
            level = .warning
        }

        switch level {
        case .info:
            logger.info(message)
        case .warning:
            logger.warning(message)
        case .error:
            logger.error(message)
        }
    }

    private static func pathSummary(_ path: Network.NWPath) -> String {
        let interfaceTypes: [String] = [
            (NWInterface.InterfaceType.wifi, "Wi-Fi"),
            (.wiredEthernet, "Ethernet"),
            (.cellular, "cellular"),
            (.loopback, "loopback"),
            (.other, "other")
        ]
        .compactMap { path.usesInterfaceType($0.0) ? $0.1 : nil }

        var parts = [interfaceTypes.isEmpty ? "no interface" : interfaceTypes.joined(separator: "+")]
        switch (path.supportsIPv4, path.supportsIPv6) {
        case (true, true): parts.append("IPv4/IPv6")
        case (true, false): parts.append("IPv4")
        case (false, true): parts.append("IPv6")
        case (false, false): break
        }
        if path.isExpensive { parts.append("expensive") }
        if path.isConstrained { parts.append("constrained") }
        return parts.joined(separator: ", ")
    }

    private static func unsatisfiedSuffix(_ path: Network.NWPath) -> String {
        let reason: String?
        switch path.unsatisfiedReason {
        case .notAvailable:
            reason = nil
        case .cellularDenied:
            reason = "cellular denied"
        case .wifiDenied:
            reason = "Wi-Fi denied"
        case .localNetworkDenied:
            reason = "local network denied"
        case .vpnInactive:
            reason = "required VPN inactive"
        @unknown default:
            reason = "unspecified reason"
        }
        return reason.map { " (\($0))" } ?? ""
    }

}
