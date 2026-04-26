//
//  EncryptedDNSSettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/10/26.
//

import SwiftUI

struct EncryptedDNSSettingsView: View {
    @State private var enabled = AWCore.getEncryptedDNSEnabled()
    @State private var `protocol` = AWCore.getEncryptedDNSProtocol()
    @State private var server = AWCore.getEncryptedDNSServer()
    
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
                    Picker("Protocol", selection: $protocol) {
                        Text("DNS over HTTPS").tag("doh")
                        Text("DNS over TLS").tag("dot")
                    }
                }

                Section {
                    TextField("DNS Server", text: $server)
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
        .onAppear {
            enabled = AWCore.getEncryptedDNSEnabled()
            `protocol` = AWCore.getEncryptedDNSProtocol()
            server = AWCore.getEncryptedDNSServer()
        }
        .onDisappear { commitServer() }
        .onChange(of: `protocol`) { _, newValue in
            AWCore.setEncryptedDNSProtocol(newValue)
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
        AWCore.setEncryptedDNSServer(server.trimmingCharacters(in: .whitespacesAndNewlines))
        AWCore.notifyTunnelSettingsChanged()
    }
}
