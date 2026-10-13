//
//  HomeView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI
import NetworkExtension

struct HomeView: View {
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    @State private var selectedPage: Page? = .launchpad
    @State private var preferredColumn = NavigationSplitViewColumn.detail

    var body: some View {
        if horizontalSizeClass != .compact, UIDevice.current.userInterfaceIdiom == .phone {
            // Workaround for buggy .sidebarAdaptable
            // See https://developer.apple.com/forums/thread/848401
            NavigationSplitView(preferredCompactColumn: $preferredColumn) {
                List(selection: $selectedPage) {
                    Section {
                        Label(Page.launchpad.name, image: Page.launchpad.symbol)
                            .tag(Page.launchpad)
                        Label(Page.dashboard.name, systemImage: Page.dashboard.symbol)
                            .tag(Page.dashboard)
                        Label(Page.toolbox.name, systemImage: Page.toolbox.symbol)
                            .tag(Page.toolbox)
                    }

                    Section("App") {
                        Label(Page.data.name, systemImage: Page.data.symbol)
                            .tag(Page.data)
                        Label(Page.personalization.name, systemImage: Page.personalization.symbol)
                            .tag(Page.personalization)
                    }

                    Section("VPN") {
                        Label(Page.tunnel.name, systemImage: Page.tunnel.symbol)
                            .tag(Page.tunnel)
                        Label(Page.purify.name, systemImage: Page.purify.symbol)
                            .tag(Page.purify)
                        Label(Page.routing.name, systemImage: Page.routing.symbol)
                            .tag(Page.routing)
                        Label(Page.mitm.name, systemImage: Page.mitm.symbol)
                            .tag(Page.mitm)
                        Label(Page.modules.name, systemImage: Page.modules.symbol)
                            .tag(Page.modules)
                    }

                    Section("Security") {
                        Label(Page.trustedCertificates.name, systemImage: Page.trustedCertificates.symbol)
                            .tag(Page.trustedCertificates)
                        Label(Page.trustedNetwork.name, systemImage: Page.trustedNetwork.symbol)
                            .tag(Page.trustedNetwork)
                    }

                    Section("More") {
                        Label(Page.diagnosis.name, systemImage: Page.diagnosis.symbol)
                            .tag(Page.diagnosis)
                        Label(Page.about.name, systemImage: Page.about.symbol)
                            .tag(Page.about)
                    }
                }
            } detail: {
                switch selectedPage {
                case .launchpad, nil:
                    LaunchpadView()
                case .dashboard:
                    DashboardView()
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
                case .modules:
                    ModulesView()
                case .trustedCertificates:
                    TrustedCertificatesView()
                case .trustedNetwork:
                    TrustedNetworkView()
                case .diagnosis:
                    DiagnosisView()
                case .about:
                    AboutView()
                }
            }
        } else {
            TabView(selection: $selectedPage) {
                Tab(Page.launchpad.name, image: Page.launchpad.symbol, value: Page.launchpad) {
                    LaunchpadView()
                }
                
                Tab(Page.dashboard.name, systemImage: Page.dashboard.symbol, value: Page.dashboard) {
                    DashboardView()
                }
                
                Tab(Page.toolbox.name, systemImage: Page.toolbox.symbol, value: Page.toolbox) {
                    ToolboxView()
                }
                
                if horizontalSizeClass != .compact {
                    TabSection {
                        Tab(Page.data.name, systemImage: Page.data.symbol, value: Page.data) {
                            DataView()
                        }
                        
                        Tab(Page.personalization.name, systemImage: Page.personalization.symbol, value: Page.personalization) {
                            PersonalizationView()
                        }
                    } header: {
                        Text("App")
                    }
                    .tabPlacement(.sidebarOnly)
                    
                    TabSection {
                        Tab(Page.tunnel.name, systemImage: Page.tunnel.symbol, value: Page.tunnel) {
                            TunnelView()
                        }
                        
                        Tab(Page.purify.name, systemImage: Page.purify.symbol, value: Page.purify) {
                            PurifyView()
                        }
                        
                        Tab(Page.routing.name, systemImage: Page.routing.symbol, value: Page.routing) {
                            RoutingView()
                        }
                        
                        Tab(Page.mitm.name, systemImage: Page.mitm.symbol, value: Page.mitm) {
                            MITMView()
                        }
                        
                        Tab(Page.modules.name, systemImage: Page.modules.symbol, value: Page.modules) {
                            ModulesView()
                        }
                    } header: {
                        Text("VPN")
                    }
                    .tabPlacement(.sidebarOnly)
                    
                    TabSection {
                        Tab(Page.trustedCertificates.name, systemImage: Page.trustedCertificates.symbol, value: Page.trustedCertificates) {
                            TrustedCertificatesView()
                        }
                        
                        Tab(Page.trustedNetwork.name, systemImage: Page.trustedNetwork.symbol, value: Page.trustedNetwork) {
                            TrustedNetworkView()
                        }
                    } header: {
                        Text("Security")
                    }
                    .tabPlacement(.sidebarOnly)
                    
                    TabSection {
                        Tab(Page.diagnosis.name, systemImage: Page.diagnosis.symbol, value: Page.diagnosis) {
                            DiagnosisView()
                        }
                        
                        Tab(Page.about.name, systemImage: Page.about.symbol, value: Page.about) {
                            AboutView()
                        }
                    } header: {
                        Text("More")
                    }
                    .tabPlacement(.sidebarOnly)
                }
            }
            .tabViewStyle(.sidebarAdaptable)
        }
    }
    
    @ViewBuilder
    private var voyagerMemberCard: some View {
        VoyagerMemberCard()
            .listRowInsets(EdgeInsets())
            .listRowBackground(
                VoyagerCardBackground()
                    .clipShape(RoundedRectangle(cornerRadius: 24))
            )
            .tag(nil as Page?)
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

    return HomeView()
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
}
#endif
