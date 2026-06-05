//
//  ContentView.swift
//  Anywhere
//
//  Created by NodePassProject on 1/23/26.
//

import SwiftUI

struct ContentView: View {
    @Environment(VPNViewModel.self) private var viewModel
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(RoutingRuleSetStore.self) private var ruleSetStore
    @Environment(DeepLinkManager.self) private var deepLinkManager
    @State private var selectedTab: AppTab = .home
    @State private var showingDeepLinkAddSheet = false
    @State private var showingManualAddSheet = false
    @State private var pendingDeepLinkURL: String?

    private var showOrphanedAlert: Binding<Bool> {
        Binding(
            get: { !ruleSetStore.orphanedRuleSetNames.isEmpty },
            set: { if !$0 { ruleSetStore.acknowledgeOrphans() } }
        )
    }

    var body: some View {
        tabView
            .onChange(of: deepLinkManager.url) { _, newValue in
                if let url = newValue {
                    selectedTab = .proxies
                    pendingDeepLinkURL = url
                    deepLinkManager.url = nil
                    showingDeepLinkAddSheet = true
                }
            }
            .sheet(isPresented: $showingDeepLinkAddSheet, onDismiss: { pendingDeepLinkURL = nil }) {
                DynamicSheet(animation: .snappy(duration: 0.3, extraBounce: 0)) {
                    AddProxyView(showingManualAddSheet: $showingManualAddSheet, deepLinkURL: pendingDeepLinkURL)
                }
            }
            .sheet(isPresented: $showingManualAddSheet) {
                ProxyEditorView { configuration in
                    configStore.add(configuration)
                    viewModel.selectIfNone(configuration)
                }
            }
            .alert(String(localized: "Routing Rules Updated"), isPresented: showOrphanedAlert) {
                Button(String(localized: "OK")) {}
            } message: {
                let names = ruleSetStore.orphanedRuleSetNames.joined(separator: ", ")
                Text("The proxy used by the following routing rules was deleted. They have been reset to Default: \(names)")
            }
    }

    @ViewBuilder
    private var tabView: some View {
        if #available(iOS 18.0, *) {
            TabView(selection: $selectedTab) {
                Tab("Home", systemImage: "house", value: .home) {
                    NavigationStack {
                        HomeView()
                    }
                    .colorScheme(.dark)
                }

                Tab("Proxies", systemImage: "network", value: .proxies) {
                    NavigationStack {
                        ProxyListView()
                    }
                }

                Tab("Chains", systemImage: "point.bottomleft.forward.to.point.topright.scurvepath.fill", value: .chains) {
                    NavigationStack {
                        ChainListView()
                    }
                }

                Tab("Settings", systemImage: "gearshape", value: .settings) {
                    NavigationStack {
                        SettingsView()
                    }
                }
            }
            .tabViewStyle(.sidebarAdaptable)
        } else {
            TabView(selection: $selectedTab) {
                NavigationStack {
                    HomeView()
                }
                .tabItem { Label("Home", systemImage: "house") }
                .tag(AppTab.home)

                NavigationStack {
                    ProxyListView()
                }
                .tabItem { Label("Proxies", systemImage: "network") }
                .tag(AppTab.proxies)

                NavigationStack {
                    ChainListView()
                }
                .tabItem { Label("Chains", systemImage: "point.bottomleft.forward.to.point.topright.scurvepath.fill") }
                .tag(AppTab.chains)

                NavigationStack {
                    SettingsView()
                }
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag(AppTab.settings)
            }
        }
    }
}

private enum AppTab: Hashable {
    case home, proxies, chains, settings
}
