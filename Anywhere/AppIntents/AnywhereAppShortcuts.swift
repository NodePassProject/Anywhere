//
//  AnywhereAppShortcuts.swift
//  Anywhere
//
//  Created by NodePassProject on 11/3/26.
//

import AppIntents
import SwiftUI

struct AnywhereAppShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: ConnectIntent(),
            phrases: [
                "Connect \(.applicationName)",
                "Turn on \(.applicationName)",
                "Start \(.applicationName) VPN"
            ],
            shortTitle: "Connect",
            systemImageName: "power"
        )
        AppShortcut(
            intent: DisconnectIntent(),
            phrases: [
                "Disconnect \(.applicationName)",
                "Turn off \(.applicationName)",
                "Stop \(.applicationName) VPN"
            ],
            shortTitle: "Disconnect",
            systemImageName: "power"
        )
        AppShortcut(
            intent: SelectProxyIntent(),
            phrases: [
                "Switch \(.applicationName) to \(\.$proxy)",
                "Use \(\.$proxy) in \(.applicationName)",
                "Select a proxy in \(.applicationName)"
            ],
            shortTitle: "Select Proxy",
            systemImageName: "circle.fill"
        )
        AppShortcut(
            intent: SetProxyModeIntent(),
            phrases: [
                "Set \(.applicationName) to \(\.$mode)",
                "Switch \(.applicationName) mode"
            ],
            shortTitle: "Set Mode",
            systemImageName: "arrow.triangle.branch"
        )
        AppShortcut(
            intent: RefreshSubscriptionIntent(),
            phrases: [
                "Update \(\.$subscription) in \(.applicationName)",
                "Update a subscription in \(.applicationName)"
            ],
            shortTitle: "Update Subscription",
            systemImageName: "arrow.clockwise"
        )
        AppShortcut(
            intent: RefreshAllSubscriptionsIntent(),
            phrases: [
                "Update all subscriptions in \(.applicationName)",
                "Update \(.applicationName) subscriptions",
                "Refresh \(.applicationName)"
            ],
            shortTitle: "Update All Subscriptions",
            systemImageName: "arrow.clockwise"
        )
    }
}

struct AppShortcutParametersSync: ViewModifier {
    @Environment(ConfigurationStore.self) private var configurationStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(SubscriptionStore.self) private var subscriptionStore

    private var parameterNames: [String] {
        configurationStore.configurations.map(\.name)
            + chainStore.chains.map(\.name)
            + subscriptionStore.subscriptions.map(\.name)
    }

    func body(content: Content) -> some View {
        content.onChange(of: parameterNames, initial: true) { _, _ in
            AnywhereAppShortcuts.updateAppShortcutParameters()
        }
    }
}
