//
//  AdvancedSettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/26/26.
//

import SwiftUI

struct AdvancedSettingsView: View {
    @Environment(AppSettings.self) private var settings
    
    @State private var showHideVPNIconAlert = false

    var body: some View {
        @Bindable var settings = settings
        List {
            Section {
                Toggle("Experimental Features", isOn: $settings.experimentalEnabled)
                NavigationLink("Public Beta") {
                    JoinBetaView()
                }
            }

            Section {
                Toggle("Hide VPN Icon", isOn: Binding(
                    get: { settings.hideVPNIcon },
                    set: { newValue in
                        if newValue {
                            showHideVPNIconAlert = true
                        } else {
                            settings.hideVPNIcon = false
                        }
                    }
                ))
            }
            
            Section {
                NavigationLink("Reflection") {
                    ReflectionSettingsView()
                }
            }

            Section {
                NavigationLink("DNS") {
                    DNSSettingsView()
                }
                NavigationLink("IPv6") {
                    IPv6SettingsView()
                }
            }

            Section {
                // Remnawave is a self-hosting proxy panel
                Toggle("Remnawave HWID", isOn: $settings.remnawaveHWIDEnabled)
            }
        }
        .navigationTitle("Advanced Settings")
        .alert("Hide VPN Icon", isPresented: $showHideVPNIconAlert) {
            Button("Enable Anyway", role: .destructive) {
                settings.hideVPNIcon = true
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Enabling Hide VPN Icon may cause connection instability and will disable IPv6.")
        }
    }
}
