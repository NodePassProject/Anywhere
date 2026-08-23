//
//  LiveTunnelProvider.swift
//  Anywhere
//
//  Created by NodePassProject on 8/3/26.
//

import Foundation
import NetworkExtension

@MainActor
final class LiveTunnelProvider: TunnelProviding {
    static let providerBundleIdentifier = "com.argsment.Anywhere.Network-Extension"

    private var manager: NETunnelProviderManager?
    private var loadedFromPreferences = false

    var status: NEVPNStatus {
        guard let manager, loadedFromPreferences else { return .disconnected }
        return manager.connection.status
    }

    func prepare() async {
        guard manager == nil else { return }
        let managers = try? await NETunnelProviderManager.loadAllFromPreferences()
        if let existing = managers?.first(where: {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.providerBundleIdentifier
        }) ?? managers?.first {
            manager = existing
            loadedFromPreferences = true
        } else {
            manager = NETunnelProviderManager()
        }
    }

    func statusUpdates() -> AsyncStream<NEVPNStatus> {
        AsyncStream { continuation in
            let task = Task { @MainActor [weak self] in
                for await note in NotificationCenter.default.notifications(named: .NEVPNStatusDidChange) {
                    guard let self else { break }
                    guard let connection = note.object as? NEVPNConnection,
                          connection === self.manager?.connection else { continue }
                    continuation.yield(connection.status)
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    func start(_ request: TunnelStartRequest) async throws {
        guard let manager else { return }

        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = Self.providerBundleIdentifier
        tunnelProtocol.serverAddress = "Anywhere"
        #if !os(tvOS)
        tunnelProtocol.includeAllNetworks = request.includeAllNetworks
        tunnelProtocol.excludeLocalNetworks = request.excludeLocalNetworks
        tunnelProtocol.excludeAPNs = request.excludeAPNs
        tunnelProtocol.excludeCellularServices = request.excludeCellularServices
        tunnelProtocol.excludeDeviceCommunication = request.excludeDeviceCommunication
        #endif

        manager.protocolConfiguration = tunnelProtocol
        manager.localizedDescription = "Anywhere"
        manager.isEnabled = true

        if request.alwaysOn {
            let rule = NEOnDemandRuleConnect()
            rule.interfaceTypeMatch = .any
            manager.onDemandRules = [rule]
            manager.isOnDemandEnabled = true
        } else {
            manager.isOnDemandEnabled = false
            manager.onDemandRules = nil
        }

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        loadedFromPreferences = true
        try manager.connection.startVPNTunnel(options: [TunnelMessage.optionKey: request.startMessage as NSObject])
    }

    func stop(disablingAlwaysOn: Bool) async {
        guard let manager else { return }
        if disablingAlwaysOn, manager.isOnDemandEnabled {
            manager.isOnDemandEnabled = false
            try? await manager.saveToPreferences()
        }
        manager.connection.stopVPNTunnel()
    }

    func send(_ data: Data) async -> Data? {
        guard let session = manager?.connection as? NETunnelProviderSession else { return nil }
        return await ProviderMessageConcurrencyBridge.send(data, over: session)
    }
}
