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
            }
        }
        .navigationTitle("IPv6")
        .onChange(of: ipv6DNSEnabled) { AWCore.notifySettingsChanged() }
    }
}
