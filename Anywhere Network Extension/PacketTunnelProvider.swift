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

    private func buildTunnelSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)

        var sa4 = sockaddr_in()
        let serverIsIPv4 = inet_pton(AF_INET, remoteAddress, &sa4.sin_addr) == 1

        let ipv4Settings = NEIPv4Settings(addresses: ["10.8.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        if serverIsIPv4 {
            ipv4Settings.excludedRoutes = [
                NEIPv4Route(destinationAddress: remoteAddress, subnetMask: "255.255.255.255")
            ]
        }
        settings.ipv4Settings = ipv4Settings

        let ipv6Enabled = APCore.userDefaults.bool(forKey: "ipv6Enabled")
        if ipv6Enabled {
            let ipv6Settings = NEIPv6Settings(addresses: ["fd00::2"], networkPrefixLengths: [64])
            ipv6Settings.includedRoutes = [NEIPv6Route.default()]
            if !serverIsIPv4 {
                ipv6Settings.excludedRoutes = [
                    NEIPv6Route(destinationAddress: remoteAddress, networkPrefixLength: 128)
                ]
            }
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

    static func parseConfiguration(from configurationDict: [String: Any]) -> VLESSConfiguration? {
        VLESSConfiguration.parse(from: configurationDict)
    }
}
