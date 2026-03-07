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
    // - IPv6 toggle: adds/removes IPv6 routes and IPv6 DNS servers.
    //
    // NOT re-applied when (stack restart is sufficient):
    // - DoH toggle: DDR blocking in LWIPStack controls DoH behavior at the DNS
    //   interception level; no tunnel settings change needed.
    // - Bypass country: only affects per-connection GeoIP checks in LWIPStack.

    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let configurationDict = options?["config"] as? [String: Any],
              let configuration = Self.parseConfiguration(from: configurationDict) else {
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

            let ipv6Enabled = APCore.userDefaults.bool(forKey: "ipv6Enabled")
            self.lwipStack.start(packetFlow: self.packetFlow,
                                 configuration: configuration,
                                 ipv6Enabled: ipv6Enabled)
            completionHandler(nil)
        }
    }

    // MARK: - Tunnel Settings
    //
    // Builds NEPacketTunnelNetworkSettings from current UserDefaults.
    // Reads: ipv6Enabled (for IPv6 routes and DNS servers).
    // DNS servers are always plain UDP (1.1.1.1, 1.0.0.1); DoH auto-upgrade is
    // prevented at the lwIP level by blocking DDR queries, not by DNS settings here.

    // MARK: - Bypass Routes
    //
    // These IP ranges are always excluded from the VPN tunnel (sent directly).
    // Domain-based entries (localhost, *.local, captive.apple.com) are not
    // expressible as packet-level route exclusions:
    //   - localhost   → covered by 127.0.0.0/8
    //   - *.local     → mDNS/Bonjour; addresses fall in private/link-local ranges below
    //   - captive.apple.com → handled by the OS captive-portal detection layer

    private static let bypassIPv4Routes: [NEIPv4Route] = [
        NEIPv4Route(destinationAddress: "127.0.0.0",     subnetMask: "255.0.0.0"),     // 127.0.0.0/8
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
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)

        var sa4 = sockaddr_in()
        let serverIsIPv4 = inet_pton(AF_INET, remoteAddress, &sa4.sin_addr) == 1

        var ipv4Exclusions = Self.bypassIPv4Routes
        if serverIsIPv4 {
            ipv4Exclusions.append(NEIPv4Route(destinationAddress: remoteAddress, subnetMask: "255.255.255.255"))
        }
        logger.info("[VPN] Bypass IPv4: \(Self.bypassIPv4Routes.map { "\($0.destinationAddress)/\($0.destinationSubnetMask)" }.joined(separator: ", "), privacy: .public)")

        let ipv4Settings = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        ipv4Settings.excludedRoutes = ipv4Exclusions
        settings.ipv4Settings = ipv4Settings

        let ipv6Enabled = APCore.userDefaults.bool(forKey: "ipv6Enabled")
        if ipv6Enabled {
            var ipv6Exclusions = Self.bypassIPv6Routes
            if !serverIsIPv4 {
                ipv6Exclusions.append(NEIPv6Route(destinationAddress: remoteAddress, networkPrefixLength: 128))
            }

            let ipv6Settings = NEIPv6Settings(addresses: ["fd00::2"], networkPrefixLengths: [64])
            ipv6Settings.includedRoutes = [NEIPv6Route.default()]
            ipv6Settings.excludedRoutes = ipv6Exclusions
            settings.ipv6Settings = ipv6Settings
        }

        let dnsServers: [String]
        if ipv6Enabled {
            dnsServers = ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
        } else {
            dnsServers = ["1.1.1.1", "1.0.0.1"]
        }
        let dnsSettings = NEDNSSettings(servers: dnsServers)
        settings.dnsSettings = dnsSettings
        settings.mtu = 1400

        return settings
    }

    /// Re-applies tunnel network settings with current UserDefaults values.
    /// Called by LWIPStack via onTunnelSettingsNeedReapply when IPv6 setting changes.
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

    // MARK: - Configuration Parsing

    static func parseConfiguration(from configurationDict: [String: Any]) -> ProxyConfiguration? {
        ProxyConfiguration.parse(from: configurationDict)
    }
}
