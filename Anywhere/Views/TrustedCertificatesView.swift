//
//  TrustedCertificatesView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/10/26.
//

import SwiftUI

struct TrustedCertificatesView: View {
    @StateObject private var store = CertificateStore.shared

    @State private var showAddAlert = false
    @State private var newFingerprint = ""
    @State private var showError = false
    @State private var errorMessage = ""

    var body: some View {
        List {
            if store.fingerprints.isEmpty {
                Section {
                    Text("No trusted certificates")
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                ForEach(store.fingerprints, id: \.self) { fingerprint in
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
                                store.remove(fingerprint)
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                }
                .onDelete { offsets in
                    store.remove(atOffsets: offsets)
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
        .alert(String(localized: "Add Certificate"), isPresented: $showAddAlert) {
            TextField("SHA-256 Fingerprint", text: $newFingerprint)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
            Button("Add") {
                let trimmed = newFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
                if !store.add(trimmed) {
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
