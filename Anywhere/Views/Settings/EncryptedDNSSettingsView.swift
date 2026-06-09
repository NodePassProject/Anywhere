//
//  EncryptedDNSSettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/10/26.
//

import SwiftUI

struct EncryptedDNSSettingsView: View {
    @State private var showEnableAlert = false
    @State private var serverBuffer = ""

    var body: some View {
        @Bindable var settings = AppSettings.shared
        Form {
            Section {
                Toggle("Encrypted DNS", isOn: Binding(
                    get: { settings.encryptedDNSEnabled },
                    set: { newValue in
                        if newValue {
                            showEnableAlert = true
                        } else {
                            settings.encryptedDNSEnabled = false
                        }
                    }
                ))
            }

            if settings.encryptedDNSEnabled {
                Section {
                    Picker("Protocol", selection: $settings.encryptedDNSProtocol) {
                        Text("DNS over HTTPS").tag("doh")
                        Text("DNS over TLS").tag("dot")
                    }
                }

                Section {
                    TextField("DNS Server", text: $serverBuffer)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .onSubmit { commitServer() }
                } footer: {
                    Text("Leave empty to automatically discover and upgrade to encrypted DNS servers.")
                }
            }
        }
        .navigationTitle("Encrypted DNS")
        .onAppear { serverBuffer = settings.encryptedDNSServer }
        .onDisappear { commitServer() }
        .alert("Encrypted DNS", isPresented: $showEnableAlert) {
            Button("Enable Anyway", role: .destructive) {
                settings.encryptedDNSEnabled = true
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Enabling Encrypted DNS will increase connection wait time and prevent routing rules from working.")
        }
    }

    private func commitServer() {
        AppSettings.shared.encryptedDNSServer = serverBuffer.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
