//
//  SettingsView.swift
//  Anywhere TV
//
//  Created by Argsment Limited on 3/15/26.
//

import SwiftUI

struct SettingsView: View {
    @AppStorage("allowInsecure", store: AWCore.userDefaults)
    private var allowInsecure = false

    @State private var showInsecureAlert = false

    var body: some View {
        Form {
            Section("Security") {
                Toggle(isOn: Binding(
                    get: { allowInsecure },
                    set: { newValue in
                        if newValue {
                            showInsecureAlert = true
                        } else {
                            allowInsecure = false
                            notifySettingsChanged()
                        }
                    }
                )) {
                    Label("Allow Insecure", systemImage: "exclamationmark.shield.fill")
                }
            }
        }
        .navigationTitle("Settings")
        .alert("Allow Insecure", isPresented: $showInsecureAlert) {
            Button("Allow Anyway", role: .destructive) {
                allowInsecure = true
                notifySettingsChanged()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will skip TLS certificate validation, making your connections vulnerable to MITM attacks.")
        }
    }

    private func notifySettingsChanged() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName("com.argsment.Anywhere.settingsChanged" as CFString),
            nil, nil, true
        )
    }
}
