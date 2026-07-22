//
//  PacketTunnelProvider.swift
//  Anywhere
//
//  Created by NodePassProject on 1/23/26.
//

import NetworkExtension
import Network
import Synchronization
#if os(iOS)
import WidgetKit
#endif

nonisolated private let logger = AnywhereLogger(category: "PacketTunnelProvider")

nonisolated class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private let tunnelStack = TunnelStack()
    private let statsRecorder = StatsRecorder()

    private let pathMonitorBridge = PathMonitorConcurrencyBridge()

    private let rootTask = Mutex<Task<Void, Never>?>(nil)

    // MARK: - Tunnel Lifecycle
    
    override func startTunnel(options: [String : NSObject]? = nil) async throws {
        guard let configuration = resolveStartConfiguration(options: options) else {
            let error = AnywhereError.tunnel(.invalidConfiguration)
            logger.report("[VPN] Start failed", error: error)
            throw error
        }

        let settings = buildTunnelSettings()
        
        do {
            try await setTunnelNetworkSettings(settings)
        } catch {
            let wrapped = AnywhereError.tunnel(.settingsApplyFailed(underlying: error))
            logger.report("[VPN]", error: wrapped)
            throw wrapped
        }

#if os(iOS)
        ControlCenter.shared.reloadControls(ofKind: "com.argsment.Anywhere.Widget.VPNToggle")
#endif

        await tunnelStack.start(packetFlow: packetFlow, configuration: configuration)
        
        rootTask.withLock { task in
            guard task == nil else { return }
            task = Task { await self.run() }
        }
        
        statsRecorder.start { [tunnelStack] in
            return StatsRecorder.RawValues(
                byteCounts: tunnelStack.byteCounts.withLock { $0 },
                tcpConnectionCount: FlowGauge.liveTCP,
                udpConnectionCount: FlowGauge.liveUDP,
                memoryBytes: Self.memoryFootprint()
            )
        }
    }
    
    private func resolveStartConfiguration(options: [String: NSObject]?) -> ProxyConfiguration? {
        if let messageData = options?[TunnelMessage.optionKey] as? Data {
            do {
                if case .setConfiguration(let config) = try JSONDecoder().decode(TunnelMessage.self, from: messageData) {
                    return config
                }
            } catch {
                logger.report("[VPN] Start options decode failed", error: AnywhereError.tunnel(.ipcFailed(underlying: error)))
            }
        }
        guard let savedData = AWCore.getLastConfigurationData() else { return nil }
        do {
            return try JSONDecoder().decode(ProxyConfiguration.self, from: savedData)
        } catch {
            logger.report(AnywhereError.store(.corrupted(.configurations, detail: AnywhereError.describe(error))))
            return nil
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
        
        let advertiseIPv6ToApps = AWCore.getAdvertiseIPv6ToApps() && !hideVPNIcon
        if advertiseIPv6ToApps {
            let ipv6Settings = NEIPv6Settings(addresses: [TunnelConstants.tunnelAddressIPv6], networkPrefixLengths: [64])
            ipv6Settings.includedRoutes = [NEIPv6Route.default()] + includedRoutes.ipv6
            ipv6Settings.excludedRoutes = excludedRoutes.ipv6
            settings.ipv6Settings = ipv6Settings
        }
        
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
        return NEIPv6Route(destinationAddress: String(nulTerminated: buffer), networkPrefixLength: NSNumber(value: prefixLength))
    }

    private static func dottedQuad(_ value: UInt32) -> String {
        "\((value >> 24) & 0xFF).\((value >> 16) & 0xFF).\((value >> 8) & 0xFF).\(value & 0xFF)"
    }
    
    private func reapplyTunnelSettings() async {
        let settings = buildTunnelSettings()
        do {
            try await setTunnelNetworkSettings(settings)
            logger.info("[VPN] Tunnel settings reapplied")
        } catch {
            guard !Task.isCancelled else { return }
            logger.report("[VPN] Failed to reapply tunnel settings", error: error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
#if os(iOS)
        ControlCenter.shared.reloadControls(ofKind: "com.argsment.Anywhere.Widget.VPNToggle")
#endif
        
        statsRecorder.stop()
        
        let task = rootTask.withLock { task -> Task<Void, Never>? in
            defer { task = nil }
            return task
        }
        task?.cancel()
        
        logTunnelStop(reason: reason)
        
        await tunnelStack.stop()
    }

    // MARK: - App Messages

    override func handleAppMessage(_ messageData: Data) async -> Data? {
        let message: TunnelMessage
        do {
            message = try JSONDecoder().decode(TunnelMessage.self, from: messageData)
        } catch {
            logger.report("[IPC] App message decode failed", error: AnywhereError.tunnel(.ipcFailed(underlying: error)))
            return nil
        }

        switch message {
        case .setConfiguration(let configuration):
            await tunnelStack.switchConfiguration(configuration)
            return nil

        case .testLatency(let configuration):
            let response = LatencyTestResponse(await LatencyTester.test(configuration))
            return encodeReply(response)

        case .fetchStats:
            return encodeReply(statsRecorder.snapshot())

        case .fetchLogs:
            return encodeReply(LogsResponse(logs: tunnelStack.fetchLogs()))

        case .fetchRequests:
            return encodeReply(RequestsResponse(requests: tunnelStack.requestLog.snapshot()))
        }
    }
    
    private func encodeReply(_ reply: some Encodable) -> Data? {
        do {
            return try JSONEncoder().encode(reply)
        } catch {
            logger.report("[IPC] Reply encode failed", error: AnywhereError.tunnel(.ipcFailed(underlying: error)))
            return nil
        }
    }
    
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
        await tunnelStack.suspendOutbound()
    }

    override func wake() {
        statsRecorder.noteWake()
        Task { await tunnelStack.handleWake() }
    }

    // MARK: - Provider task tree

    private func run() async {
        await withDiscardingTaskGroup { group in
            group.addTask { [reapplySignal = tunnelStack.reapplySettingsSignal] in
                for await _ in reapplySignal {
                    await self.reapplyTunnelSettings()
                }
            }
            group.addTask {
                for await path in self.pathMonitorBridge.paths() {
                    guard path.status == .satisfied else { continue }
                    await self.resolveAndUpdateNetworkContext(path)
                }
            }
        }
    }

    // MARK: - Path Monitoring

    private func resolveAndUpdateNetworkContext(_ path: Network.NWPath) async {
        let primaryType = path.availableInterfaces.first?.type
        let isWiFi = primaryType == .wifi
        let isCellular = primaryType == .cellular
#if os(iOS)
        if isWiFi {
            let ssid = await pathMonitorBridge.currentWiFiSSID()
            await tunnelStack.updateNetworkContext(isWiFi: true, isCellular: false, ssid: ssid)
            return
        }
#endif
        await tunnelStack.updateNetworkContext(isWiFi: isWiFi, isCellular: isCellular, ssid: nil)
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
}
