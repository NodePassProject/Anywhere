//
//  EncryptedDNSSettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/10/26.
//

import SwiftUI

struct EncryptedDNSSettingsView: View {
    @AppStorage("encryptedDNSEnabled", store: AWCore.userDefaults)
    private var enabled = false

    @AppStorage("encryptedDNSProtocol", store: AWCore.userDefaults)
    private var dnsProtocol = "doh"

    @AppStorage("encryptedDNSServer", store: AWCore.userDefaults)
    private var storedServer = ""

    @State private var editingServer = ""
    @State private var showEnableAlert = false

    var body: some View {
        Form {
            Section {
                Toggle("Encrypted DNS", isOn: Binding(
                    get: { enabled },
                    set: { newValue in
                        if newValue {
                            showEnableAlert = true
                        } else {
                            enabled = false
                            notifySettingsChanged()
                        }
                    }
                ))
            } footer: {
                Text("Not recommended.")
            }

            if enabled {
                Section {
                    Picker("Protocol", selection: $dnsProtocol) {
                        Text("DNS over HTTPS").tag("doh")
                        Text("DNS over TLS").tag("dot")
                    }
                }
                
                Section {
                    TextField("DNS Server", text: $editingServer)
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
        .onAppear { editingServer = storedServer }
        .onDisappear { commitServer() }
        .onChange(of: dnsProtocol) {
            commitServer()
            notifySettingsChanged()
        }
        .alert("Encrypted DNS", isPresented: $showEnableAlert) {
            Button("Enable Anyway", role: .destructive) {
                enabled = true
                notifySettingsChanged()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Enabling Encrypted DNS will increase connection wait time and prevent routing rules from working.")
        }
    }
    
    private func commitServer() {
        let trimmed = editingServer.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed != storedServer else { return }
        storedServer = trimmed
        notifySettingsChanged()
    }

    private func notifySettingsChanged() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName("com.argsment.Anywhere.settingsChanged" as CFString),
            nil, nil, true
        )
    }
}
