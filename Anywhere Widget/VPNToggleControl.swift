//
//  VPNToggleControl.swift
//  Anywhere
//
//  Created by NodePassProject on 4/6/26.
//

import AppIntents
import NetworkExtension
import SwiftUI
import WidgetKit

struct VPNToggleControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(
            kind: "com.argsment.Anywhere.Widget.VPNToggle",
            provider: VPNStatusProvider()
        ) { isOn in
            ControlWidgetToggle(
                "VPN",
                isOn: isOn,
                action: ToggleVPNIntent()
            ) { isOn in
                Label(
                    isOn ? "Connected" : "Disconnected",
                    image: "anywhere.fill"
                )
            }
        }
        .displayName("Toggle VPN")
        .description("Toggle VPN connection on or off.")
    }
}

private let anywhereNEBundleIdentifier = "com.argsment.Anywhere.Network-Extension"

private func loadManager() async throws -> NETunnelProviderManager? {
    let managers = try await NETunnelProviderManager.loadAllFromPreferences()
    return managers.first {
        ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == anywhereNEBundleIdentifier
    }
}

struct VPNStatusProvider: ControlValueProvider {
    var previewValue: Bool { false }

    func currentValue() async throws -> Bool {
        guard let manager = try await loadManager() else { return false }
        let status = manager.connection.status
        return status == .connected || status == .connecting
    }
}

struct ToggleVPNIntent: SetValueIntent {
    static let title: LocalizedStringResource = "Toggle VPN"
    static let isDiscoverable = false

    @Parameter(title: "VPN Enabled")
    var value: Bool

    func perform() async throws -> some IntentResult {
        guard let manager = try await loadManager() else { return .result() }

        if value {
            if !manager.isEnabled {
                manager.isEnabled = true
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
            }
            try manager.connection.startVPNTunnel()
        } else {
            manager.connection.stopVPNTunnel()
        }

        return .result()
    }
}
