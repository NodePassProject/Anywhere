//
//  PacketTunnelProvider.swift
//  Network Extension
//
//  Created by Argsment Limited on 1/23/26.
//

import NetworkExtension
import Network
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "PacketTunnel")

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let lwipStack = LWIPStack()
    private var remoteAddress: String = ""

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
        } else if let savedData = AWCore.userDefaults.data(forKey: "lastConfigurationData"),
                  let dict = try? JSONSerialization.jsonObject(with: savedData) as? [String: Any] {
            configurationDict = dict
        } else {
            configurationDict = nil
        }

        guard let configurationDict, let configuration = Self.parseConfiguration(from: configurationDict) else {
            logger.error("[VPN] Invalid or missing configuration in options")
            completionHandler(NSError(domain: "com.argsment.Anywhere", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid configuration"]))
            return
        }

        remoteAddress = configuration.connectAddress
        logger.info("[VPN] Starting tunnel to \(configuration.serverAddress, privacy: .public):\(configuration.serverPort, privacy: .public) (connect: \(self.remoteAddress, privacy: .public)), security: \(configuration.security, privacy: .public), transport: \(configuration.transport, privacy: .public)")

        lwipStack.onTunnelSettingsNeedReapply = { [weak self] in
            self?.reapplyTunnelSettings()
        }

        let settings = buildTunnelSettings()

        setTunnelNetworkSettings(settings) { error in
            if let error {
                logger.error("[VPN] Failed to set tunnel settings: \(error.localizedDescription, privacy: .public)")
                completionHandler(error)
                return
            }

            self.lwipStack.start(packetFlow: self.packetFlow,
                                 configuration: configuration)
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
        
        let ipv4Settings = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        ipv4Settings.excludedRoutes = Self.bypassIPv4Routes
        settings.ipv4Settings = ipv4Settings

        let ipv6DNSEnabled = AWCore.userDefaults.bool(forKey: "ipv6DNSEnabled")
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

        let encryptedDNSEnabled = AWCore.userDefaults.bool(forKey: "encryptedDNSEnabled")
        let encryptedDNSProtocol = AWCore.userDefaults.string(forKey: "encryptedDNSProtocol") ?? "doh"
        let encryptedDNSServer = AWCore.userDefaults.string(forKey: "encryptedDNSServer") ?? ""

        if encryptedDNSEnabled, !encryptedDNSServer.isEmpty {
            if encryptedDNSProtocol == "dot" {
                let serverIPs = Self.resolveEncryptedDNSHostname(encryptedDNSServer, includeIPv6: ipv6DNSEnabled)
                let dnsSettings = NEDNSOverTLSSettings(servers: serverIPs ?? dnsServers)
                dnsSettings.serverName = encryptedDNSServer
                settings.dnsSettings = dnsSettings
                logger.info("[VPN] DoT server: \(encryptedDNSServer, privacy: .public), resolved IPs: \(serverIPs ?? dnsServers, privacy: .public)")
            } else if let serverURL = URL(string: encryptedDNSServer) {
                let serverIPs = serverURL.host.flatMap { Self.resolveEncryptedDNSHostname($0, includeIPv6: ipv6DNSEnabled) }
                let dnsSettings = NEDNSOverHTTPSSettings(servers: serverIPs ?? dnsServers)
                dnsSettings.serverURL = serverURL
                settings.dnsSettings = dnsSettings
                logger.info("[VPN] DoH server: \(encryptedDNSServer, privacy: .public), resolved IPs: \(serverIPs ?? dnsServers, privacy: .public)")
            } else {
                settings.dnsSettings = NEDNSSettings(servers: dnsServers)
            }
        } else {
            settings.dnsSettings = NEDNSSettings(servers: dnsServers)
        }
        settings.mtu = 1400

        return settings
    }

    /// Re-applies tunnel network settings with current UserDefaults values.
    /// Called by LWIPStack via onTunnelSettingsNeedReapply when IPv6/encrypted DNS settings change.
    /// Resets the virtual interface and flushes the OS DNS cache.
    private func reapplyTunnelSettings() {
        let settings = buildTunnelSettings()
        setTunnelNetworkSettings(settings) { error in
            if let error {
                logger.error("[VPN] Failed to reapply tunnel settings: \(error.localizedDescription, privacy: .public)")
            } else {
                logger.info("[VPN] Tunnel settings reapplied")
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        lwipStack.stop()
        completionHandler()
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

        logger.info("[VPN] Received configuration switch request")
        lwipStack.switchConfiguration(configuration)
        completionHandler?(nil)
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func wake() {
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
            logger.warning("[VPN] Failed to resolve encrypted DNS server: \(hostname, privacy: .public)")
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
