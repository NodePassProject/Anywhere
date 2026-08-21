//
//  HomeView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI
import NetworkExtension

struct HomeView: View {
    private enum Page: Hashable {
        case launchpad
        case missionControl
        case data
        case personalization
        case tunnel
        case purify
        case routing
        case mitm
        case trustedCertificates
        case trustedNetwork
        case diagnosis
        case about
    }
    
    @Environment(AppSettings.self) private var appSettings
    @Environment(TunnelController.self) private var tunnelController

    @State private var selectedPage: Page? = .launchpad
    @State private var preferredColumn = NavigationSplitViewColumn.detail
    
    private var isConnected: Bool {
        tunnelController.rawStatus == .connected
    }

    var body: some View {
        NavigationSplitView(preferredCompactColumn: $preferredColumn) {
            List(selection: $selectedPage) {
                Section {
                    TextWithColorfulIcon(title: "Launchpad", comment: nil, systemName: "power", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                        .tag(Page.launchpad)
                    TextWithColorfulIcon(title: "Mission Control", comment: nil, systemName: "rectangle.3.group.fill", foregroundStyle: .white, backgroundStyle: .black.gradient)
                        .tag(Page.missionControl)
                }
                Section {
                    TextWithColorfulIcon(title: "Data", comment: nil, systemName: "cylinder.split.1x2.fill", foregroundStyle: .white, backgroundStyle: .gray.gradient)
                        .tag(Page.data)
                    TextWithColorfulIcon(title: "Personalization", comment: nil, systemName: "paintpalette.fill", foregroundStyle: .white, backgroundStyle: .pink.gradient)
                        .tag(Page.personalization)
                }
                Section {
                    TextWithColorfulIcon(title: "Tunnel", comment: nil, systemName: "hammer.fill", foregroundStyle: .white, backgroundStyle: .gray.gradient)
                        .tag(Page.tunnel)
                    TextWithColorfulIcon(title: "Purify", comment: nil, systemName: "drop.fill", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                        .tag(Page.purify)
                    TextWithColorfulIcon(title: "Routing", comment: nil, systemName: "arrow.triangle.branch", foregroundStyle: .white, backgroundStyle: .purple.gradient)
                        .tag(Page.routing)
                    TextWithColorfulIcon(title: "MITM", comment: nil, systemName: "key.horizontal.fill", foregroundStyle: .white, backgroundStyle: .teal.gradient)
                        .tag(Page.mitm)
                }
                
                Section {
                    TextWithColorfulIcon(title: "Trusted Certificates", comment: nil, systemName: "checkmark.seal.fill", foregroundStyle: .white, backgroundStyle: .green.gradient)
                        .tag(Page.trustedCertificates)
                    TextWithColorfulIcon(title: "Trusted Network", comment: nil, systemName: "wifi", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                        .tag(Page.trustedNetwork)
                }
                
                Section {
                    TextWithColorfulIcon(title: "Diagnosis", comment: nil, systemName: "stethoscope", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                        .tag(Page.diagnosis)
                    TextWithColorfulIcon(title: "About", comment: nil, systemName: "info.circle.fill", foregroundStyle: .white, backgroundStyle: .gray.gradient)
                        .tag(Page.about)
                }
            }
            .navigationTitle("Anywhere")
        } detail: {
            switch selectedPage {
            case .launchpad:
                LaunchpadView()
            case .missionControl:
                MissionControlView()
            case .data:
                DataView()
            case .personalization:
                PersonalizationView()
            case .tunnel:
                TunnelView()
            case .purify:
                PurifyView()
            case .routing:
                RoutingView()
            case .mitm:
                MITMView()
            case .trustedCertificates:
                TrustedCertificatesView()
            case .trustedNetwork:
                TrustedNetworkView()
            case .diagnosis:
                DiagnosisView()
            case .about:
                AboutView()
            case .none:
                LaunchpadView()
            }
        }
        .navigationSplitViewStyle(.prominentDetail)
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
        outbound: .socks5(username: nil, password: nil)
    ))
    container.tunnel.setStatusForPreview(.connected)

    return HomeView()
        .environment(AppSettings())
        .environment(Operations(container: container))
        .environment(container.tunnel)
        .environment(container.selection)
        .environment(container.latency)
        .environment(container.configurationStore)
        .environment(container.chainStore)
        .environment(container.subscriptionStore)
        .environment(ConnectionStatsModel.previewSeeded())
        .colorScheme(.dark)
}
#endif
