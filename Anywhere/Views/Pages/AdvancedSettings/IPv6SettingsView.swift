//
//  IPv6SettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/10/26.
//

import SwiftUI

struct IPv6SettingsView: View {
    @Environment(AppSettings.self) private var settings

    var body: some View {
        @Bindable var settings = settings
        Form {
            Section {
                Toggle("Advertise IPv6 to Apps", isOn: $settings.advertiseIPv6ToApps)
            }
        }
        .navigationTitle("IPv6")
    }
}
