//
//  VPNToggleControl.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/6/26.
//

import AppIntents
import NetworkExtension
import SwiftUI
import WidgetKit

@available(iOS 18.0, *)
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
                    image: "anywhere"
                )
            }
        }
        .displayName("Toggle VPN")
        .description("Toggle VPN connection on or off.")
    }
}

private let anywhereNEBundleIdentifier = "com.argsment.Anywhere.Network-Extension"

/// Returns the NETunnelProviderManager owned by Anywhere, if any.
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

    @Parameter(title: "VPN Enabled")
    var value: Bool

    func perform() async throws -> some IntentResult {
        guard let manager = try await loadManager() else { return .result() }

        if value {
            // Re-enable the manager in case another VPN app disabled it.
            if !manager.isEnabled {
                manager.isEnabled = true
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
            }
            // The extension reads lastConfigurationData from the App Group.
            try manager.connection.startVPNTunnel()
        } else {
            manager.connection.stopVPNTunnel()
        }

        return .result()
    }
}
