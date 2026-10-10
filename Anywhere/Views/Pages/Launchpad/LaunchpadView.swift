//
//  LaunchpadView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/21/26.
//

import SwiftUI
import NetworkExtension

struct LaunchpadView: View {
    @Environment(TunnelController.self) private var tunnelController
    @Environment(ConnectionStats.self) private var connectionStats

    @State private var connectionEffectsEnabled = false
    @State private var page = 0

    private var isConnected: Bool {
        tunnelController.rawStatus == .connected
    }

    var body: some View {
        PageView(selection: $page) {
            MainControlView(connectionEffectsEnabled: connectionEffectsEnabled)
                .pageIndicator(label: "Main Control")
            
            DashboardView()
                .pageIndicator(label: "Dashboard")
        }
        .background(
            BackgroundGradient()
                .ignoresSafeArea()
        )
        .sensoryFeedback(trigger: isConnected) { _, _ in
            guard connectionEffectsEnabled else { return nil }
            return .impact
        }
        .alert("VPN Error", isPresented: Binding(
            get: { tunnelController.startError != nil },
            set: { if !$0 { tunnelController.startError = nil } }
        )) {
            Button("OK") { tunnelController.startError = nil }
        } message: {
            Text(tunnelController.startError ?? "")
        }
        .onChange(of: tunnelController.isManagerReady, initial: true) { _, ready in
            guard ready, !connectionEffectsEnabled else { return }
            Task { @MainActor in connectionEffectsEnabled = true }
        }
    }
}

// MARK: - Previews

#if DEBUG
#Preview("Connected") {
    let container = AppContainer.preview()
    container.selection.select(ProxyConfiguration(
        name: "🇺🇸 Los Angeles",
        serverAddress: "203.0.113.10",
        serverPort: 443,
        outbound: .socks5(SOCKS5Configuration())
    ))
    container.tunnel.setStatusForPreview(.connected)

    return LaunchpadView()
        .environment(AppSettings())
        .environment(Operations(container: container))
        .environment(container.tunnel)
        .environment(container.selection)
        .environment(container.latency)
        .environment(container.configurationStore)
        .environment(container.chainStore)
        .environment(container.groupStore)
        .environment(container.subscriptionStore)
        .environment(ConnectionStats.previewSeeded())
        .colorScheme(.dark)
}
#endif
