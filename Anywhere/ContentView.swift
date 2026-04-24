//
//  ContentView.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/23/26.
//

import SwiftUI

struct ContentView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared
    @EnvironmentObject private var deepLinkManager: DeepLinkManager
    @State private var selectedTab: AppTab = .home
    @State private var showingDeepLinkAddSheet = false
    @State private var showingManualAddSheet = false
    @State private var pendingDeepLinkURL: String?

    private var showOrphanedAlert: Binding<Bool> {
        Binding(
            get: { !viewModel.orphanedRuleSetNames.isEmpty },
            set: { if !$0 { viewModel.orphanedRuleSetNames = [] } }
        )
    }

    var body: some View {
        Group {
            if #available(iOS 18.0, *) {
                TabView(selection: $selectedTab) {
                    Tab("Home", systemImage: "house", value: .home) {
                        NavigationStack {
                            HomeView()
                        }
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
                viewModel.addConfiguration(configuration)
            }
        }
        .alert(String(localized: "Routing Rules Updated"), isPresented: showOrphanedAlert) {
            Button(String(localized: "OK")) {}
        } message: {
            let names = viewModel.orphanedRuleSetNames.joined(separator: ", ")
            Text("The proxy used by the following routing rules was deleted. They have been reset to Default: \(names)")
        }
    }
}

private enum AppTab: Hashable {
    case home, proxies, chains, settings
}
