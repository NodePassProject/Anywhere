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
        case toolbox
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
    
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    @Environment(AppSettings.self) private var appSettings
    @Environment(TunnelController.self) private var tunnelController

    @State private var selectedPage: Page? = .launchpad
    @State private var preferredColumn = NavigationSplitViewColumn.detail
    
    private var isConnected: Bool {
        tunnelController.rawStatus == .connected
    }

    var body: some View {
        switch horizontalSizeClass {
        case .regular:
            splitView
        case .compact:
            tabView
        default:
            EmptyView()
        }
    }
    
    @ViewBuilder
    private var splitView: some View {
        NavigationSplitView(preferredCompactColumn: $preferredColumn) {
            List(selection: $selectedPage) {
                Section {
                    TextWithColorfulIconAndCustomImage(title: "Launchpad", imageName: "anywhere", foregroundStyle: .white, backgroundStyle: .anywhere.gradient)
                        .tag(Page.launchpad)
                    if isConnected {
                        TextWithColorfulIcon(title: "Mission Control", systemName: "rectangle.3.group.fill", foregroundStyle: .white, backgroundStyle: .black.gradient)
                            .tag(Page.missionControl)
                    }
                }
                Section {
                    TextWithColorfulIcon(title: "Data", systemName: "cylinder.split.1x2.fill", foregroundStyle: .white, backgroundStyle: .gray.gradient)
                        .tag(Page.data)
                    TextWithColorfulIcon(title: "Personalization", systemName: "paintpalette.fill", foregroundStyle: .white, backgroundStyle: .pink.gradient)
                        .tag(Page.personalization)
                }
                Section {
                    TextWithColorfulIcon(title: "Tunnel", systemName: "hammer.fill", foregroundStyle: .white, backgroundStyle: .gray.gradient)
                        .tag(Page.tunnel)
                    TextWithColorfulIcon(title: "Purify", systemName: "drop.fill", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                        .tag(Page.purify)
                    TextWithColorfulIcon(title: "Routing", systemName: "arrow.triangle.branch", foregroundStyle: .white, backgroundStyle: .purple.gradient)
                        .tag(Page.routing)
                    TextWithColorfulIcon(title: "MITM", systemName: "key.horizontal.fill", foregroundStyle: .white, backgroundStyle: .teal.gradient)
                        .tag(Page.mitm)
                }
                
                Section {
                    TextWithColorfulIcon(title: "Trusted Certificates", systemName: "checkmark.seal.fill", foregroundStyle: .white, backgroundStyle: .green.gradient)
                        .tag(Page.trustedCertificates)
                    TextWithColorfulIcon(title: "Trusted Network", systemName: "wifi", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                        .tag(Page.trustedNetwork)
                }
                
                Section {
                    TextWithColorfulIcon(title: "Diagnosis", systemName: "stethoscope", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                        .tag(Page.diagnosis)
                    TextWithColorfulIcon(title: "About", systemName: "info.circle.fill", foregroundStyle: .white, backgroundStyle: .gray.gradient)
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
            case .toolbox:
                ToolboxView()
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
                EmptyView()
            }
        }
        .navigationSplitViewStyle(.balanced)
    }
    
    @ViewBuilder
    private var tabView: some View {
        TabView(selection: $selectedPage) {
            Tab(value: .launchpad) {
                LaunchpadView()
            } label: {
                Image("anywhere")
            }
            if isConnected {
                Tab(value: .missionControl) {
                    MissionControlView()
                } label: {
                    Image(systemName: "rectangle.3.group.fill")
                }
            }
            if #available(iOS 27.0, *) {
                Tab(value: .toolbox, role: .prominent) {
                    ToolboxView()
                } label: {
                    Image(systemName: "latch.2.case.fill")
                }
            } else {
                Tab(value: .toolbox, role: .search) {
                    ToolboxView()
                } label: {
                    Image(systemName: "latch.2.case.fill")
                }
            }
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
