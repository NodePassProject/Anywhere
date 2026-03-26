//
//  IPv6SettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/10/26.
//

import SwiftUI

struct IPv6SettingsView: View {
    @AppStorage("ipv6DNSEnabled", store: AWCore.userDefaults)
    private var ipv6DNSEnabled = false

    var body: some View {
        Form {
            Section {
                Toggle("IPv6 DNS Lookup", isOn: $ipv6DNSEnabled)
            } footer: {
                Text("Send and respond to AAAA DNS queries.")
            }
        }
        .navigationTitle("IPv6")
        .onChange(of: ipv6DNSEnabled) { notifySettingsChanged() }
    }

    private func notifySettingsChanged() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName("com.argsment.Anywhere.settingsChanged" as CFString),
            nil, nil, true
        )
    }
}
