//
//  ContentView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/14/26.
//

import SwiftUI

struct ContentView: View {
    var body: some View {
        if #available(tvOS 18.0, *) {
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
}
