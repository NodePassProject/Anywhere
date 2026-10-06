//
//  ReflectionSettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/31/26.
//

import SwiftUI

struct ReflectionSettingsView: View {
    @Environment(AppSettings.self) private var settings

    @State private var showReflectionAlert = false

    var body: some View {
        Form {
            Section {
                Toggle("Reflection", isOn: Binding(
                    get: { settings.reflectionEnabled },
                    set: { newValue in
                        if newValue {
                            showReflectionAlert = true
                        } else {
                            settings.reflectionEnabled = false
                        }
                    }
                ))
            } footer: {
                Text("Packets sent to \(TunnelAddress.reflection) are returned to their sender instead of being routed or proxied.")
            }
        }
        .navigationTitle("Reflection")
        .alert("Reflection", isPresented: $showReflectionAlert) {
            Button("Enable Anyway", role: .destructive) {
                settings.reflectionEnabled = true
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Enabling Reflection may reduce performance.")
        }
    }
}
