//
//  TrustedCertificatesView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/10/26.
//

import SwiftUI

struct TrustedCertificatesView: View {
    @Environment(AppSettings.self) private var appSettings
    @Environment(Operations.self) private var operations
    @Environment(CertificateStore.self) private var certificateStore
    
    @State private var showAddAlert = false
    @State private var newFingerprint = ""
    @State private var showError = false
    @State private var errorMessage = ""
    @State private var showInsecureAlert = false
    
    var body: some View {
        List {
            Section {
                Toggle(isOn: Binding(
                    get: { appSettings.allowInsecure },
                    set: { newValue in
                        if newValue {
                            showInsecureAlert = true
                        } else {
                            appSettings.allowInsecure = false
                        }
                    }
                )) {
                    TextWithColorfulIcon(title: "Allow Insecure", comment: nil, systemName: "exclamationmark.shield.fill", foregroundStyle: .white, backgroundStyle: .red.gradient)
                }
                .tint(.red)
            }
            
            if certificateStore.fingerprints.isEmpty {
                Section {
                    Text("No trusted certificates")
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                ForEach(certificateStore.fingerprints, id: \.self) { fingerprint in
                    Text(fingerprint)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .contextMenu {
                            Button {
                                UIPasteboard.general.string = fingerprint
                            } label: {
                                Label("Copy", systemImage: "doc.on.doc")
                            }
                            Button(role: .destructive) {
                                operations.certificates.remove(fingerprint)
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                }
                .onDelete { offsets in
                    operations.certificates.remove(atOffsets: offsets)
                }
            }
        }
        .navigationTitle("Trusted Certificates")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    newFingerprint = ""
                    showAddAlert = true
                } label: {
                    Image(systemName: "plus")
                }
            }
        }
        .alert("Allow Insecure", isPresented: $showInsecureAlert) {
            Button("Allow Anyway", role: .destructive) {
                appSettings.allowInsecure = true
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will skip TLS certificate validation, making your connections vulnerable to MITM attacks.")
        }
        .alert(String(localized: "Add Certificate"), isPresented: $showAddAlert) {
            TextField("SHA-256 Fingerprint", text: $newFingerprint)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
            Button("Add") {
                let trimmed = newFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
                if !operations.certificates.add(trimmed) {
                    errorMessage = String(localized: "Invalid fingerprint. Must be a 64-character hex string, or it already exists.")
                    showError = true
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Enter the SHA-256 fingerprint (64 hex characters) of the certificate to trust.")
        }
        .alert("Invalid Fingerprint", isPresented: $showError) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(errorMessage)
        }
    }
}
