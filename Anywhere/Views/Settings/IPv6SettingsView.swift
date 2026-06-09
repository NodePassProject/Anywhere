//
//  IPv6SettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/10/26.
//

import SwiftUI

struct IPv6SettingsView: View {
    var body: some View {
        @Bindable var settings = AppSettings.shared
        Form {
            Section {
                Toggle("Advertise IPv6 to Apps", isOn: $settings.advertiseIPv6ToApps)
            }
        }
        .navigationTitle("IPv6")
    }
}
