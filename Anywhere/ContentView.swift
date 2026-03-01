//
//  ContentView.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/23/26.
//

import SwiftUI

struct ContentView: View {
    @Environment(VPNViewModel.self) private var viewModel: VPNViewModel

    private var showOrphanedAlert: Binding<Bool> {
        Binding(
            get: { !viewModel.orphanedRuleSetNames.isEmpty },
            set: { if !$0 { viewModel.orphanedRuleSetNames = [] } }
        )
    }

    var body: some View {
        Group {
            if #available(iOS 18.0, *) {
                TabView {
                    Tab("Home", systemImage: "house") {
                        NavigationStack {
                            HomeView()
                        }
                    }

                    Tab("Proxies", systemImage: "network") {
                        NavigationStack {
                            ProxyListView()
                        }
                    }

                    Tab("Settings", systemImage: "gearshape") {
                        NavigationStack {
                            SettingsView()
                        }
                    }
                }
            } else {
                TabView {
                    NavigationStack {
                        HomeView()
                    }
                    .tabItem { Label("Home", systemImage: "house") }

                    NavigationStack {
                        ProxyListView()
                    }
                    .tabItem { Label("Proxies", systemImage: "network") }

                    NavigationStack {
                        SettingsView()
                    }
                    .tabItem { Label("Settings", systemImage: "gearshape") }
                }
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
