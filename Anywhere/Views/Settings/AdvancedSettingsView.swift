//
//  AdvancedSettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/26/26.
//

import SwiftUI

struct AdvancedSettingsView: View {
    @State private var experimentalEnabled = AWCore.getExperimentalEnabled()
    @State private var hideVPNIcon = AWCore.getHideVPNIcon()
    @State private var showHideVPNIconAlert = false
    @State private var remnawaveHWIDEnabled = AWCore.getRemnawaveHWIDEnabled()

    var body: some View {
        List {
            Section("App") {
                Toggle("Experimental Features", isOn: Binding(
                    get: { experimentalEnabled },
                    set: { newValue in
                        experimentalEnabled = newValue
                        AWCore.setExperimentalEnabled(newValue)
                    }
                ))
            }

            Section("VPN") {
                // Only applicable on iOS
                Toggle("Hide VPN Icon", isOn: Binding(
                    get: { hideVPNIcon },
                    set: { newValue in
                        if newValue {
                            showHideVPNIconAlert = true
                        } else {
                            hideVPNIcon = false
                            AWCore.setHideVPNIcon(false)
                            AWCore.notifyTunnelSettingsChanged()
                        }
                    }
                ))
            }

            Section("Network") {
                NavigationLink("IPv6") {
                    IPv6SettingsView()
                }
                NavigationLink("Encrypted DNS") {
                    EncryptedDNSSettingsView()
                }
            }
            
            Section("Other") {
                // Remnawave is a self-hosting proxy panel
                Toggle("Remnawave HWID", isOn: Binding(
                    get: { remnawaveHWIDEnabled },
                    set: { newValue in
                        remnawaveHWIDEnabled = newValue
                        AWCore.setRemnawaveHWIDEnabled(newValue)
                    }
                ))
            }

            Section("Diagnostics") {
                NavigationLink("Logs") {
                    LogListView()
                }
            }
        }
        .navigationTitle("Advanced Settings")
        .onAppear {
            experimentalEnabled = AWCore.getExperimentalEnabled()
            hideVPNIcon = AWCore.getHideVPNIcon()
        }
        .alert("Hide VPN Icon", isPresented: $showHideVPNIconAlert) {
            Button("Enable Anyway", role: .destructive) {
                hideVPNIcon = true
                AWCore.setHideVPNIcon(true)
                AWCore.setIPv6DNSEnabled(false)
                AWCore.notifyTunnelSettingsChanged()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Enabling Hide VPN Icon may cause connection instability and will disable IPv6.")
        }
    }
}
