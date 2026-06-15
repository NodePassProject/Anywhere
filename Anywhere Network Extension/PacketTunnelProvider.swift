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

private let logger = AnywhereLogger(category: "PacketTunnelProvider")

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let tunnelStack = TunnelStack()
    private let statsRecorder = StatsRecorder()
    private let pathMonitorQueue = DispatchQueue(label: AWCore.Identifier.pathMonitorQueue)
    private var pathMonitor: NWPathMonitor?
    private var lastPathSnapshot: PathSnapshot?

    /// Connection-relevant snapshot of a network path. A primary-interface change
    /// strands established sockets; the other flags only distinguish additive changes.
    private struct PathSnapshot {
        let status: Network.NWPath.Status
        let unsatisfiedReason: String?
        let primaryInterface: PrimaryInterface?
        let interfaceSummary: String
        let supportsIPv4: Bool
        let supportsIPv6: Bool
        let isExpensive: Bool
        let isConstrained: Bool

        /// Egress interface identity (name + BSD index + type); a change means the
        /// default route moved, invalidating every socket bound to the old interface.
        struct PrimaryInterface: Equatable, CustomStringConvertible {
            let name: String
            let index: Int
            let type: NWInterface.InterfaceType

            var description: String {
                let typeName: String
                switch type {
                case .wifi: typeName = "Wi-Fi"
                case .cellular: typeName = "cellular"
                case .wiredEthernet: typeName = "Ethernet"
                case .loopback: typeName = "loopback"
                case .other: typeName = "other"
                @unknown default: typeName = "unknown"
                }
                return "\(name)/\(typeName)"
            }
        }

        var summary: String {
            var parts = [interfaceSummary]

            switch (supportsIPv4, supportsIPv6) {
            case (true, true):
                parts.append("IPv4/IPv6")
            case (true, false):
                parts.append("IPv4")
            case (false, true):
                parts.append("IPv6")
            case (false, false):
                break
            }

            if isExpensive {
                parts.append("expensive")
            }
            if isConstrained {
                parts.append("constrained")
            }

            return parts.joined(separator: ", ")
        }
    }

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
                if #available(iOS 18.0, *) {
                    ControlCenter.shared.reloadControls(ofKind: "com.argsment.Anywhere.Widget.VPNToggle")
                }
#endif
                
                self.tunnelStack.start(packetFlow: self.packetFlow,
                                       configuration: configuration)
                self.startMonitoringPath()
                self.statsRecorder.start {
                    return StatsRecorder.RawValues(
                        byteCounts: self.tunnelStack.byteCounts,
                        tcpConnectionCount: self.tunnelStack.activeTCPConnections,
                        udpConnectionCount: self.tunnelStack.activeUDPConnections,
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
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.8.0.1")

        let hideVPNIcon = AWCore.getHideVPNIcon()
        let ipv4Settings = NEIPv4Settings(addresses: ["10.8.0.1"], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        ipv4Settings.excludedRoutes = hideVPNIcon ? [NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "255.255.255.254")] : []
        settings.ipv4Settings = ipv4Settings

        // Claiming IPv6 tunnel settings makes iOS show the VPN icon on cellular,
        // so we drop IPv6 entirely when hideVPNIcon is enabled.
        let advertiseIPv6ToApps = AWCore.getAdvertiseIPv6ToApps() && !hideVPNIcon
        if advertiseIPv6ToApps {
            let ipv6Settings = NEIPv6Settings(addresses: ["fd00::1"], networkPrefixLengths: [64])
            ipv6Settings.includedRoutes = [NEIPv6Route.default()]
            ipv6Settings.excludedRoutes = []
            settings.ipv6Settings = ipv6Settings
        }

        // Plain DNS is intercepted by lwIP on UDP/53; an in-tunnel server address
        // keeps queries reachable only through utun, so they cannot leak.
        let plainDNSServers: [String]
        if advertiseIPv6ToApps {
            plainDNSServers = ["10.8.0.1", "fd00::1"]
        } else {
            plainDNSServers = ["10.8.0.1"]
        }

        // Fallback when the encrypted-DNS hostname fails to resolve; the OS dials
        // these IPs directly, so they must speak DoT/DoH.
        let encryptedDNSFallbackServers = TunnelConstants.fallbackDNSServers(includeIPv6: advertiseIPv6ToApps)

        let encryptedDNSEnabled = AWCore.getEncryptedDNSEnabled()
        let encryptedDNSProtocol = AWCore.getEncryptedDNSProtocol()
        let encryptedDNSServer = AWCore.getEncryptedDNSServer()

        if encryptedDNSEnabled, !encryptedDNSServer.isEmpty {
            if encryptedDNSProtocol == "dot" {
                let serverIPs = Self.resolveEncryptedDNSHostname(encryptedDNSServer, includeIPv6: advertiseIPv6ToApps)
                let dnsSettings = NEDNSOverTLSSettings(servers: serverIPs ?? encryptedDNSFallbackServers)
                dnsSettings.serverName = encryptedDNSServer
                settings.dnsSettings = dnsSettings
                logger.info("[VPN] DNS: DoT \(encryptedDNSServer)")
            } else if let serverURL = URL(string: encryptedDNSServer) {
                let serverIPs = serverURL.host.flatMap { Self.resolveEncryptedDNSHostname($0, includeIPv6: advertiseIPv6ToApps) }
                let dnsSettings = NEDNSOverHTTPSSettings(servers: serverIPs ?? encryptedDNSFallbackServers)
                dnsSettings.serverURL = serverURL
                settings.dnsSettings = dnsSettings
                logger.info("[VPN] DNS: DoH \(encryptedDNSServer)")
            } else {
                settings.dnsSettings = NEDNSSettings(servers: plainDNSServers)
                logger.warning("[VPN] Invalid DoH URL, falling back to plain DNS")
            }
        } else {
            settings.dnsSettings = NEDNSSettings(servers: plainDNSServers)
        }
        settings.mtu = 1500

        return settings
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
        if #available(iOS 18.0, *) {
            ControlCenter.shared.reloadControls(ofKind: "com.argsment.Anywhere.Widget.VPNToggle")
        }
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
        let kr = withUnsafeMutablePointer(to: &info) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { intPtr in
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
        lastPathSnapshot = nil
    }

    /// What changed between two satisfied paths and whether it strands existing outbound sockets.
    private enum SatisfiedChange {
        /// Nothing connection-relevant changed.
        case unchanged
        /// The egress interface moved; every outbound socket is stranded — recover.
        case interfaceChanged(String)
        /// Same interface but IPv4 reachability dropped; IPv4 proxy legs can no longer send — recover.
        case ipv4EgressLost
        /// Only additive/orthogonal attributes changed; existing connections stay valid.
        case capabilityOnly(String)
    }

    private func handlePathUpdate(_ path: Network.NWPath) {
        let snapshot = Self.makePathSnapshot(from: path)
        let previous = lastPathSnapshot
        lastPathSnapshot = snapshot

        // First update after start: just record the baseline.
        guard let previous else {
            logger.info("[VPN] Network path ready: \(snapshot.summary)")
            return
        }

        switch snapshot.status {
        case .satisfied:
            if previous.status != .satisfied {
                // Restored after a drop: any leg that outlived the gap is stale.
                logger.info("[VPN] Network path restored: \(snapshot.summary); recovering connections")
                tunnelStack.handleNetworkPathChange(summary: "network path restored")
            } else {
                // Recover only on a real egress move; additive changes (e.g. IPv6
                // arriving on the same Wi-Fi) leave connections valid.
                switch Self.classifySatisfiedChange(from: previous, to: snapshot) {
                case .interfaceChanged(let detail):
                    logger.info("[VPN] Egress interface changed (\(detail)); recovering connections")
                    tunnelStack.handleNetworkPathChange(summary: "interface change")
                case .ipv4EgressLost:
                    logger.info("[VPN] IPv4 egress lost (\(snapshot.summary)); recovering connections")
                    tunnelStack.handleNetworkPathChange(summary: "IPv4 egress lost")
                case .capabilityOnly(let what):
                    logger.debug("[VPN] Path attributes changed (\(what)); connections unaffected")
                case .unchanged:
                    break
                }
            }
            if reasserting {
                reasserting = false
            }

        case .requiresConnection:
            // Dedupe repeated callbacks in the same state; nothing to recover onto yet.
            guard previous.status != .requiresConnection else { return }
            let reasonSuffix = snapshot.unsatisfiedReason.map { " (\($0))" } ?? ""
            logger.warning("[VPN] Network path waiting for attachment\(reasonSuffix); active connections may pause")
            reasserting = true

        case .unsatisfied:
            guard previous.status != .unsatisfied else { return }
            let reasonSuffix = snapshot.unsatisfiedReason.map { " (\($0))" } ?? ""
            logger.warning("[VPN] Network path unavailable\(reasonSuffix); releasing upstream transports")
            reasserting = true
            // Down edge: release dead upstream transports instead of pinning sockets
            // through the outage; rebuilt on the up edge.
            tunnelStack.suspendOutbound()

        @unknown default:
            logger.warning("[VPN] Network path changed unexpectedly; active connections may reconnect")
        }
    }

    /// Classifies a satisfied→satisfied transition. Outbound sockets are pinned to
    /// their egress interface, so additive changes on an unchanged interface are
    /// deliberate no-ops.
    private static func classifySatisfiedChange(from prev: PathSnapshot, to cur: PathSnapshot) -> SatisfiedChange {
        if prev.primaryInterface != cur.primaryInterface {
            let from = prev.primaryInterface?.description ?? "none"
            let to = cur.primaryInterface?.description ?? "none"
            return .interfaceChanged("\(from) → \(to)")
        }

        if prev.supportsIPv4 && !cur.supportsIPv4 {
            return .ipv4EgressLost
        }

        var deltas: [String] = []
        if prev.supportsIPv6 != cur.supportsIPv6 { deltas.append(cur.supportsIPv6 ? "+IPv6" : "-IPv6") }
        if !prev.supportsIPv4 && cur.supportsIPv4 { deltas.append("+IPv4") }
        if prev.isExpensive != cur.isExpensive { deltas.append(cur.isExpensive ? "+expensive" : "-expensive") }
        if prev.isConstrained != cur.isConstrained { deltas.append(cur.isConstrained ? "+constrained" : "-constrained") }
        if !deltas.isEmpty { return .capabilityOnly(deltas.joined(separator: ", ")) }

        return .unchanged
    }

    private func logTunnelStop(reason: NEProviderStopReason) {
        let message: String
        let level: TunnelStack.LogLevel

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

    private static func makePathSnapshot(from path: Network.NWPath) -> PathSnapshot {
        let interfaceTypes: [String] = [
            (NWInterface.InterfaceType.wifi, "Wi-Fi"),
            (.wiredEthernet, "Ethernet"),
            (.cellular, "cellular"),
            (.loopback, "loopback"),
            (.other, "other")
        ]
        .compactMap { path.usesInterfaceType($0.0) ? $0.1 : nil }

        let unsatisfiedReason: String?
        if #available(iOS 14.2, tvOS 17.0, *) {
            switch path.unsatisfiedReason {
            case .notAvailable:
                unsatisfiedReason = nil
            case .cellularDenied:
                unsatisfiedReason = "cellular denied"
            case .wifiDenied:
                unsatisfiedReason = "Wi-Fi denied"
            case .localNetworkDenied:
                unsatisfiedReason = "local network denied"
            case .vpnInactive:
                unsatisfiedReason = "required VPN inactive"
            @unknown default:
                unsatisfiedReason = "unspecified reason"
            }
        } else {
            unsatisfiedReason = nil
        }

        // availableInterfaces is ordered by preference, so the first is the OS-preferred egress.
        let primaryInterface = path.availableInterfaces.first.map {
            PathSnapshot.PrimaryInterface(name: $0.name, index: $0.index, type: $0.type)
        }

        return PathSnapshot(
            status: path.status,
            unsatisfiedReason: unsatisfiedReason,
            primaryInterface: primaryInterface,
            interfaceSummary: interfaceTypes.isEmpty ? "no interface" : interfaceTypes.joined(separator: "+"),
            supportsIPv4: path.supportsIPv4,
            supportsIPv6: path.supportsIPv6,
            isExpensive: path.isExpensive,
            isConstrained: path.isConstrained
        )
    }

    // MARK: - Encrypted DNS Hostname Resolution

    /// Resolves a hostname via getaddrinfo for the `servers` list of DoH/DoT
    /// settings; returns nil for IP literals or on failure.
    private static func resolveEncryptedDNSHostname(_ hostname: String, includeIPv6: Bool) -> [String]? {
        // Skip resolution for IP literals — they can be used directly as servers
        var addr = in_addr()
        var addr6 = in6_addr()
        if inet_pton(AF_INET, hostname, &addr) == 1 || inet_pton(AF_INET6, hostname, &addr6) == 1 {
            return nil
        }

        var hints = addrinfo()
        hints.ai_family = includeIPv6 ? AF_UNSPEC : AF_INET
        hints.ai_socktype = SOCK_STREAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(hostname, nil, &hints, &result) == 0, let res = result else {
            logger.warning("[VPN] Failed to resolve encrypted DNS server: \(hostname)")
            return nil
        }
        defer { freeaddrinfo(res) }

        var ips: [String] = []
        var current: UnsafeMutablePointer<addrinfo>? = res
        while let info = current {
            switch info.pointee.ai_family {
            case AF_INET:
                info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ptr in
                    var sinAddr = ptr.pointee.sin_addr
                    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    inet_ntop(AF_INET, &sinAddr, &buf, socklen_t(INET_ADDRSTRLEN))
                    ips.append(String(cString: buf))
                }
            case AF_INET6:
                info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { ptr in
                    var sin6Addr = ptr.pointee.sin6_addr
                    var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    inet_ntop(AF_INET6, &sin6Addr, &buf, socklen_t(INET6_ADDRSTRLEN))
                    ips.append(String(cString: buf))
                }
            default:
                break
            }
            current = info.pointee.ai_next
        }

        return ips.isEmpty ? nil : ips
    }

    // MARK: - Configuration Parsing

    static func parseConfiguration(from configurationDict: [String: Any]) -> ProxyConfiguration? {
        ProxyConfiguration.parse(from: configurationDict)
    }
}
