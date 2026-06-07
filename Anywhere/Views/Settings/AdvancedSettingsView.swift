//
//  AdvancedSettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/26/26.
//

import SwiftUI

struct AdvancedSettingsView: View {
    @State private var experimentalEnabled = AWCore.getExperimentalEnabled()
    @State private var hideVPNIcon = AWCore.getHideVPNIcon()
    @State private var quicPolicy = AWCore.getQUICPolicy()
    @State private var blockWebRTC = AWCore.getBlockWebRTC()
    @State private var remnawaveHWIDEnabled = AWCore.getRemnawaveHWIDEnabled()
    
    @State private var showHideVPNIconAlert = false

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
                NavigationLink("Tunnel") {
                    TunnelSettingsView()
                }
            }

            Section("Network") {
                Picker("Block QUIC", selection: Binding(
                    get: { quicPolicy },
                    set: { newValue in
                        quicPolicy = newValue
                        AWCore.setQUICPolicy(newValue)
                        AWCore.notifyTunnelSettingsChanged()
                    }
                )) {
                    ForEach(QUICPolicy.allCases, id: \.self) { policy in
                        Text(policy.title).tag(policy)
                    }
                }
                Toggle("Block WebRTC", isOn: Binding(
                    get: { blockWebRTC },
                    set: { newValue in
                        blockWebRTC = newValue
                        AWCore.setBlockWebRTC(newValue)
                        AWCore.notifyTunnelSettingsChanged()
                    }
                ))
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
                NavigationLink("Requests") {
                    RequestsView()
                }
            }
        }
        .navigationTitle("Advanced Settings")
        .onAppear {
            experimentalEnabled = AWCore.getExperimentalEnabled()
            hideVPNIcon = AWCore.getHideVPNIcon()
            quicPolicy = AWCore.getQUICPolicy()
        }
        .alert("Hide VPN Icon", isPresented: $showHideVPNIconAlert) {
            Button("Enable Anyway", role: .destructive) {
                hideVPNIcon = true
                AWCore.setHideVPNIcon(true)
                AWCore.setAdvertiseIPv6ToApps(false)
                AWCore.notifyTunnelSettingsChanged()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Enabling Hide VPN Icon may cause connection instability and will disable IPv6.")
        }
    }
}
