//
//  VPNToggleControl.swift
//  Anywhere Widget
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

struct VPNStatusProvider: ControlValueProvider {
    var previewValue: Bool { false }

    func currentValue() async throws -> Bool {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        guard let manager = managers.first else { return false }
        let status = manager.connection.status
        return status == .connected || status == .connecting
    }
}

struct ToggleVPNIntent: SetValueIntent {
    static let title: LocalizedStringResource = "Toggle VPN"

    @Parameter(title: "VPN Enabled")
    var value: Bool

    func perform() async throws -> some IntentResult {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        guard let manager = managers.first else { return .result() }

        if value {
            // Use the existing configuration saved by the main app.
            // The extension reads lastConfigurationData from the App Group.
            try manager.connection.startVPNTunnel()
        } else {
            manager.connection.stopVPNTunnel()
        }

        return .result()
    }
}
