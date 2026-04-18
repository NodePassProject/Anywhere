//
//  EncryptedDNSSettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/10/26.
//

import SwiftUI

struct EncryptedDNSSettingsView: View {
    @State private var enabled = AWCore.getEncryptedDNSEnabled()
    @State private var dnsProtocol = AWCore.getEncryptedDNSProtocol()
    @State private var storedServer = AWCore.getEncryptedDNSServer()

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
                            AWCore.setEncryptedDNSEnabled(false)
                            AWCore.notifyTunnelSettingsChanged()
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
        .onChange(of: dnsProtocol) { _, newValue in
            AWCore.setEncryptedDNSProtocol(newValue)
            commitServer()
            AWCore.notifyTunnelSettingsChanged()
        }
        .alert("Encrypted DNS", isPresented: $showEnableAlert) {
            Button("Enable Anyway", role: .destructive) {
                enabled = true
                AWCore.setEncryptedDNSEnabled(true)
                AWCore.notifyTunnelSettingsChanged()
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
        AWCore.setEncryptedDNSServer(trimmed)
        AWCore.notifyTunnelSettingsChanged()
    }
}
