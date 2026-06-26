//
//  ModeToggleControl.swift
//  Anywhere
//
//  Created by NodePassProject on 6/26/26.
//

import AppIntents
import SwiftUI
import WidgetKit

@available(iOS 18.0, *)
struct ModeToggleControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(
            kind: "com.argsment.Anywhere.Widget.ModeToggle",
            provider: ProxyModeProvider()
        ) { isGlobal in
            ControlWidgetToggle(
                "Mode",
                isOn: isGlobal,
                action: SwitchModeIntent()
            ) { isGlobal in
                Label(
                    isGlobal ? "Global Mode" : "Proxy Mode",
                    image: isGlobal ? "anywhere.global" : "anywhere.proxy"
                )
            }
        }
        .displayName("Switch Mode")
        .description("Switch between Proxy Mode and Global Mode.")
    }
}

struct ProxyModeProvider: ControlValueProvider {
    var previewValue: Bool { false }

    func currentValue() async throws -> Bool {
        AWCore.getProxyMode() == .global
    }
}

struct SwitchModeIntent: SetValueIntent {
    static let title: LocalizedStringResource = "Switch Mode"

    @Parameter(title: "Global Mode")
    var value: Bool

    func perform() async throws -> some IntentResult {
        AWCore.setProxyMode(value ? .global : .rule)
        AWNotificationCenter.notifyTunnelSettingsChanged()
        return .result()
    }
}
