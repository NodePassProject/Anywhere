//
//  IPv6SettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/10/26.
//

import SwiftUI

struct IPv6SettingsView: View {
    @AppStorage("ipv6DNSEnabled", store: AWCore.userDefaults)
    private var dnsEnabled = false

    @AppStorage("ipv6ConnectionsEnabled", store: AWCore.userDefaults)
    private var connectionsEnabled = false

    var body: some View {
        Form {
            Section {
                Toggle(isOn: $connectionsEnabled) {
                    TextWithColorfulIcon(titleKey: "IPv6 Connections", systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                }
            } footer: {
                Text("Route IPv6 connections through the tunnel.")
            }

            if connectionsEnabled {
                Section {
                    Toggle(isOn: $dnsEnabled) {
                        TextWithColorfulIcon(titleKey: "IPv6 DNS Lookup", systemName: "magnifyingglass", foregroundColor: .white, backgroundColor: .blue)
                    }
                } footer: {
                    Text("Respond to AAAA DNS queries with IPv6 addresses.")
                }
            }
        }
        .navigationTitle("IPv6")
        .onChange(of: connectionsEnabled) {
            if connectionsEnabled {
                dnsEnabled = true
            }
            notifySettingsChanged()
        }
        .onChange(of: dnsEnabled) { notifySettingsChanged() }
    }

    private func notifySettingsChanged() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName("com.argsment.Anywhere.settingsChanged" as CFString),
            nil, nil, true
        )
    }
}
