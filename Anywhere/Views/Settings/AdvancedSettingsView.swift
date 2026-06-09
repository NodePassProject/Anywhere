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
            Section("App") {
                Toggle("Experimental Features", isOn: $settings.experimentalEnabled)
            }

            Section("VPN") {
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
                NavigationLink("Tunnel") {
                    TunnelSettingsView()
                }
            }

            Section("Network") {
                Picker("Block QUIC", selection: $settings.quicPolicy) {
                    ForEach(QUICPolicy.allCases, id: \.self) { policy in
                        Text(policy.title).tag(policy)
                    }
                }
                Toggle("Block WebRTC", isOn: $settings.blockWebRTC)
                NavigationLink("IPv6") {
                    IPv6SettingsView()
                }
                NavigationLink("Encrypted DNS") {
                    EncryptedDNSSettingsView()
                }
                NavigationLink("Reflection") {
                    ReflectionSettingsView()
                }
            }

            Section("Other") {
                // Remnawave is a self-hosting proxy panel
                Toggle("Remnawave HWID", isOn: $settings.remnawaveHWIDEnabled)
            }

            Section("Diagnostics") {
                NavigationLink("Logs") {
                    LogListView()
                }
                NavigationLink("Requests") {
                    RequestsView()
                }
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
