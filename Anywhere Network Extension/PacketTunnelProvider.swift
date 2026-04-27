//
//  PacketTunnelProvider.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/23/26.
//

import NetworkExtension
import Network
#if os(iOS)
import WidgetKit
#endif

private let logger = AnywhereLogger(category: "PacketTunnel")

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let lwipStack = LWIPStack()
    private let pathMonitorQueue = DispatchQueue(label: AWCore.Identifier.pathMonitorQueue)
    private var pathMonitor: NWPathMonitor?
    private var lastPathSnapshot: PathSnapshot?

    private struct PathSnapshot: Equatable {
        let status: Network.NWPath.Status
        let unsatisfiedReason: String?
        let interfaceSummary: String
        let primaryInterfaceName: String?
        let supportsIPv4: Bool
        let supportsIPv6: Bool
        let isExpensive: Bool
        let isConstrained: Bool

        // Equality intentionally excludes supportsIPv4/supportsIPv6/isExpensive/isConstrained.
        // Those flags can flip on the same interface (Low Data Mode toggles, IPv6 RA arriving late)
        // without invalidating existing connections — restarting on them is wasted work.
        // The primary interface name (e.g., en0, pdp_ip0) is included so genuine interface swaps
        // are caught even when the summary string collapses to the same type (e.g., Wi-Fi → Wi-Fi).
        // Only the primary (satisfied) interface is tracked — standby interfaces in
        // availableInterfaces can appear/disappear without affecting the active route.
        static func == (lhs: PathSnapshot, rhs: PathSnapshot) -> Bool {
            lhs.status == rhs.status &&
            lhs.unsatisfiedReason == rhs.unsatisfiedReason &&
            lhs.interfaceSummary == rhs.interfaceSummary &&
            lhs.primaryInterfaceName == rhs.primaryInterfaceName
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
    //
    // Tunnel network settings (routes, DNS servers) are applied at start and can be
    // re-applied live via reapplyTunnelSettings() when settings change.
    //
    // Currently re-applied when:
    // - IPv6 connections toggle: adds/removes IPv6 routes and IPv6 DNS servers.
    // - Encrypted DNS changes: switches between NEDNSSettings,
    //   NEDNSOverHTTPSSettings, or NEDNSOverTLSSettings based on protocol
    //   and custom server configuration.
    //
    // NOT re-applied when (stack restart is sufficient):
    // - Encrypted DNS toggle without custom server: DDR blocking in LWIPStack
    //   controls behavior at the DNS interception level; no tunnel settings
    //   change needed.
    // - Bypass country: only affects per-connection GeoIP checks in LWIPStack.

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // When started from the app, configuration is passed in options.
        // When started from Settings or Always On (On Demand), options is nil —
        // fall back to the last configuration saved in the App Group.
        let configurationDict: [String: Any]?
        if let dict = options?["config"] as? [String: Any] {
            configurationDict = dict
        } else if let savedData = AWCore.getLastConfigurationData(),
                  let dict = try? JSONSerialization.jsonObject(with: savedData) as? [String: Any] {
            configurationDict = dict
        } else {
            configurationDict = nil
        }

        guard let configurationDict, let configuration = Self.parseConfiguration(from: configurationDict) else {
            logger.error("[VPN] Invalid or missing configuration")
            completionHandler(NSError(domain: AWCore.Identifier.errorDomain, code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid configuration"]))
            return
        }

        lwipStack.onTunnelSettingsNeedReapply = { [weak self] in
            self?.reapplyTunnelSettings()
        }

        let settings = buildTunnelSettings()

        setTunnelNetworkSettings(settings) { error in
            if let error {
                logger.error("[VPN] Failed to set tunnel settings: \(error.localizedDescription)")
                completionHandler(error)
                return
            }
            
#if os(iOS)
            if #available(iOS 18.0, *) {
                ControlCenter.shared.reloadControls(ofKind: "com.argsment.Anywhere.Widget.VPNToggle")
            }
#endif
            
            self.lwipStack.start(packetFlow: self.packetFlow,
                                 configuration: configuration)
            self.startMonitoringPath()
            
            completionHandler(nil)
        }
    }

    // MARK: - Tunnel Settings
    //
    // Builds NEPacketTunnelNetworkSettings from current UserDefaults.
    // Reads: encryptedDNSEnabled, encryptedDNSProtocol, encryptedDNSServer.
    // When encrypted DNS is enabled with a custom server, uses NEDNSOverHTTPSSettings
    // or NEDNSOverTLSSettings. Otherwise DDR auto-upgrade is controlled at the lwIP level.

    // MARK: - Bypass Routes
    //
    // These local/private IP ranges are always excluded from the VPN tunnel (sent directly).
    // Proxy server addresses are NOT excluded here — they are bypassed at the lwIP level
    // (isProxyServerAddress check) which handles DNS rotation and covers all proxies.
    //
    // Domain-based entries (localhost, *.local, captive.apple.com) are not
    // expressible as packet-level route exclusions:
    //   - localhost   → loopback; the OS never routes 127.0.0.0/8 into the tunnel
    //   - *.local     → mDNS/Bonjour; addresses fall in private/link-local ranges below
    //   - captive.apple.com → handled by the OS captive-portal detection layer

    private static let bypassIPv4Routes: [NEIPv4Route] = [
        NEIPv4Route(destinationAddress: "10.0.0.0",      subnetMask: "255.0.0.0"),     // 10.0.0.0/8
        NEIPv4Route(destinationAddress: "172.16.0.0",    subnetMask: "255.240.0.0"),   // 172.16.0.0/12
        NEIPv4Route(destinationAddress: "192.168.0.0",   subnetMask: "255.255.0.0"),   // 192.168.0.0/16
        NEIPv4Route(destinationAddress: "100.64.0.0",    subnetMask: "255.192.0.0"),   // 100.64.0.0/10
        NEIPv4Route(destinationAddress: "162.14.0.0",    subnetMask: "255.255.0.0"),   // 162.14.0.0/16
        NEIPv4Route(destinationAddress: "211.99.96.0",   subnetMask: "255.255.224.0"), // 211.99.96.0/19
        NEIPv4Route(destinationAddress: "162.159.192.0", subnetMask: "255.255.255.0"), // 162.159.192.0/24
        NEIPv4Route(destinationAddress: "162.159.193.0", subnetMask: "255.255.255.0"), // 162.159.193.0/24
        NEIPv4Route(destinationAddress: "162.159.195.0", subnetMask: "255.255.255.0"), // 162.159.195.0/24
    ]

    private static let bypassIPv6Routes: [NEIPv6Route] = [
        NEIPv6Route(destinationAddress: "fc00::", networkPrefixLength: 7),  // fc00::/7  unique-local
        NEIPv6Route(destinationAddress: "fe80::", networkPrefixLength: 10), // fe80::/10 link-local
    ]

    private func buildTunnelSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.8.0.1")

        let hideVPNIcon = AWCore.getHideVPNIcon()
        let ipv4Settings = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        ipv4Settings.excludedRoutes = (hideVPNIcon ? [NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "255.255.255.254")] : []) + Self.bypassIPv4Routes
        settings.ipv4Settings = ipv4Settings

        // Claiming IPv6 tunnel settings makes iOS show the VPN icon on cellular,
        // so we drop IPv6 entirely when hideVPNIcon is enabled.
        let ipv6DNSEnabled = AWCore.getIPv6DNSEnabled() && !hideVPNIcon
        if ipv6DNSEnabled {
            let ipv6Settings = NEIPv6Settings(addresses: ["fd00::2"], networkPrefixLengths: [64])
            ipv6Settings.includedRoutes = [NEIPv6Route.default()]
            ipv6Settings.excludedRoutes = Self.bypassIPv6Routes
            settings.ipv6Settings = ipv6Settings
        }

        let dnsServers: [String]
        if ipv6DNSEnabled {
            dnsServers = ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
        } else {
            dnsServers = ["1.1.1.1", "1.0.0.1"]
        }

        let encryptedDNSEnabled = AWCore.getEncryptedDNSEnabled()
        let encryptedDNSProtocol = AWCore.getEncryptedDNSProtocol()
        let encryptedDNSServer = AWCore.getEncryptedDNSServer()

        if encryptedDNSEnabled, !encryptedDNSServer.isEmpty {
            if encryptedDNSProtocol == "dot" {
                let serverIPs = Self.resolveEncryptedDNSHostname(encryptedDNSServer, includeIPv6: ipv6DNSEnabled)
                let dnsSettings = NEDNSOverTLSSettings(servers: serverIPs ?? dnsServers)
                dnsSettings.serverName = encryptedDNSServer
                settings.dnsSettings = dnsSettings
                logger.info("[VPN] DNS: DoT \(encryptedDNSServer)")
            } else if let serverURL = URL(string: encryptedDNSServer) {
                let serverIPs = serverURL.host.flatMap { Self.resolveEncryptedDNSHostname($0, includeIPv6: ipv6DNSEnabled) }
                let dnsSettings = NEDNSOverHTTPSSettings(servers: serverIPs ?? dnsServers)
                dnsSettings.serverURL = serverURL
                settings.dnsSettings = dnsSettings
                logger.info("[VPN] DNS: DoH \(encryptedDNSServer)")
            } else {
                settings.dnsSettings = NEDNSSettings(servers: dnsServers)
                logger.warning("[VPN] Invalid DoH URL, falling back to plain DNS")
            }
        } else {
            settings.dnsSettings = NEDNSSettings(servers: dnsServers)
        }
        settings.mtu = 1500

        return settings
    }

    /// Re-applies tunnel network settings with current UserDefaults values.
    /// Called by LWIPStack via onTunnelSettingsNeedReapply when IPv6/encrypted DNS settings change.
    /// Resets the virtual interface and flushes the OS DNS cache.
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
        
        stopMonitoringPath()
        logTunnelStop(reason: reason)
        lwipStack.stop()
    }

    // MARK: - App Messages

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let dict = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any] else {
            completionHandler?(nil)
            return
        }

        let messageType = dict["type"] as? String

        if messageType == "stats" {
            let response: [String: Any] = [
                "bytesIn": lwipStack.totalBytesIn,
                "bytesOut": lwipStack.totalBytesOut
            ]
            let data = try? JSONSerialization.data(withJSONObject: response)
            completionHandler?(data)
            return
        }

        if messageType == "logs" {
            let logs = lwipStack.fetchLogs()
            let response: [String: Any] = ["logs": logs]
            let data = try? JSONSerialization.data(withJSONObject: response)
            completionHandler?(data)
            return
        }

        if messageType == "proxyAddresses" {
            if let addresses = dict["addresses"] as? [String] {
                lwipStack.updateProxyServerAddresses(addresses)
            }
            completionHandler?(nil)
            return
        }

        // Configuration switch (explicit "configuration" type or legacy messages without a type key)
        guard let configuration = Self.parseConfiguration(from: dict) else {
            completionHandler?(nil)
            return
        }

        lwipStack.switchConfiguration(configuration)
        completionHandler?(nil)
    }

    override func wake() {
        lwipStack.handleWake()
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

    private func handlePathUpdate(_ path: Network.NWPath) {
        let snapshot = Self.makePathSnapshot(from: path)
        let previous = lastPathSnapshot
        lastPathSnapshot = snapshot

        guard previous != snapshot else { return }

        if previous == nil {
            logger.info("[VPN] Network path ready: \(snapshot.summary)")
            return
        }

        switch snapshot.status {
        case .satisfied:
            if previous?.status == .satisfied {
                logger.info("[VPN] Network path changed to \(snapshot.summary); restarting connections on new interface")
                lwipStack.handleNetworkPathChange(summary: "network interface change")
            } else {
                logger.info("[VPN] Network path restored: \(snapshot.summary); restarting connections")
                lwipStack.handleNetworkPathChange(summary: "network path restored")
            }
            // Signal the system that the tunnel has recovered from any prior interruption
            if reasserting {
                reasserting = false
            }

        case .requiresConnection:
            let reasonSuffix = snapshot.unsatisfiedReason.map { " (\($0))" } ?? ""
            logger.warning("[VPN] Network path waiting for attachment\(reasonSuffix); active connections may pause")
            reasserting = true

        case .unsatisfied:
            let reasonSuffix = snapshot.unsatisfiedReason.map { " (\($0))" } ?? ""
            logger.warning("[VPN] Network path unavailable\(reasonSuffix); active connections interrupted")
            reasserting = true

        @unknown default:
            logger.warning("[VPN] Network path changed unexpectedly; active connections may reconnect")
        }
    }

    private func logTunnelStop(reason: NEProviderStopReason) {
        let message: String
        let level: LWIPStack.LogLevel

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

        return PathSnapshot(
            status: path.status,
            unsatisfiedReason: unsatisfiedReason,
            interfaceSummary: interfaceTypes.isEmpty ? "no interface" : interfaceTypes.joined(separator: "+"),
            primaryInterfaceName: path.availableInterfaces.first?.name,
            supportsIPv4: path.supportsIPv4,
            supportsIPv6: path.supportsIPv6,
            isExpensive: path.isExpensive,
            isConstrained: path.isConstrained
        )
    }

    // MARK: - Encrypted DNS Hostname Resolution

    /// Resolves a hostname to IP addresses via getaddrinfo.
    /// Used to populate the `servers` parameter of NEDNSOverHTTPSSettings / NEDNSOverTLSSettings
    /// so the system connects to the correct DoH/DoT server IPs (not hardcoded Cloudflare IPs).
    /// Returns nil if the hostname is already an IP literal or resolution fails.
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
