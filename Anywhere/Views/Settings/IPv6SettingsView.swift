//
//  IPv6SettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/10/26.
//

import SwiftUI

struct IPv6SettingsView: View {
    @State private var ipv6DNSEnabled = AWCore.getIPv6DNSEnabled()

    var body: some View {
        Form {
            Section {
                Toggle("IPv6 DNS Lookup", isOn: $ipv6DNSEnabled)
            }
        }
        .navigationTitle("IPv6")
        .onChange(of: ipv6DNSEnabled) { _, newValue in
            AWCore.setIPv6DNSEnabled(newValue)
            AWCore.notifyTunnelSettingsChanged()
        }
    }
}
