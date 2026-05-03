//
//  MITMCertificateView.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import SwiftUI
import Combine
import UIKit
import UniformTypeIdentifiers

@MainActor
final class MITMCertificateController: ObservableObject {
    static let shared = MITMCertificateController()

    private let store = MITMCertificateStore()

    @Published private(set) var hasCA: Bool = false
    @Published private(set) var trusted: Bool = false

    private init() {
        refresh()
    }

    func refresh() {
        let exists = store.exportCertificateDER() != nil
        hasCA = exists
        trusted = exists ? store.isCATrusted() : false
    }

    func ensureCA() throws {
        _ = try store.loadOrCreateCA()
        refresh()
    }

    func regenerate() throws {
        _ = try store.regenerate()
        refresh()
    }

    func delete() {
        store.delete()
        refresh()
    }

    func certificateData() -> Data? {
        store.exportCertificateDER()
    }

    func mobileConfigData() -> Data? {
        store.exportMobileConfig()
    }
}

struct MITMCertificateView: View {
    @StateObject private var controller = MITMCertificateController.shared

    @State private var exportingCer = false
    @State private var showRegenerateConfirm = false
    @State private var showDeleteConfirm = false
    @State private var errorMessage: String?
    @State private var profileServerStarted = false

    var body: some View {
        Form {
            Section("Status") {
                HStack {
                    Image(systemName: badgeIcon)
                        .foregroundStyle(badgeColor)
                    VStack(alignment: .leading) {
                        Text(badgeTitle)
                            .font(.headline)
                        Text(badgeSubtitle)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            if controller.hasCA {
                Section("Install") {
                    Text("1. Tap “Install Profile” — the system will prompt you to download and install the profile.\n2. Open Settings → General → VPN & Device Management → install the profile.\n3. Open Settings → General → About → Certificate Trust Settings → enable “Anywhere MITM Root”.")
                        .font(.callout)

                    Button {
                        installProfile()
                    } label: {
                        Label("Install Profile", systemImage: "lock.shield")
                    }

                    Button {
                        prepareCerExport()
                    } label: {
                        Label("Export Certificate (.cer)", systemImage: "doc.badge.arrow.up")
                    }
                }

                Section {
                    Button {
                        showRegenerateConfirm = true
                    } label: {
                        Label("Regenerate Root", systemImage: "arrow.clockwise")
                    }
                    .tint(.orange)

                    Button(role: .destructive) {
                        showDeleteConfirm = true
                    } label: {
                        Label("Delete Root", systemImage: "trash")
                    }
                } footer: {
                    Text("Regenerating or deleting the root invalidates any previously installed MITM profile.")
                }
            } else {
                Section {
                    Button {
                        do { try controller.ensureCA() }
                        catch { errorMessage = String(describing: error) }
                    } label: {
                        Label("Generate Root", systemImage: "lock.shield")
                    }
                } footer: {
                    Text("Generate a CA root certificate stored in this device's keychain. The private key never leaves the device.")
                }
            }
        }
        .navigationTitle("Root Certificate")
        .alert("Regenerate Root?", isPresented: $showRegenerateConfirm) {
            Button("Regenerate", role: .destructive) {
                do { try controller.regenerate() }
                catch { errorMessage = String(describing: error) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Any previously installed MITM profile will stop working until you re-install the new root.")
        }
        .alert("Delete Root?", isPresented: $showDeleteConfirm) {
            Button("Delete", role: .destructive) {
                controller.delete()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Removes both the certificate and its private key. You'll need to regenerate to use MITM again.")
        }
        .alert("Error", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(errorMessage ?? "")
        }
        .sheet(isPresented: $exportingCer) {
            if let url = certificateURL() {
                ShareSheet(items: [url])
            }
        }
        .onAppear { controller.refresh() }
        .onDisappear { MITMProfileServer.shared.stop() }
    }

    // MARK: - Status badge

    private var badgeIcon: String {
        if !controller.hasCA { return "exclamationmark.shield" }
        return controller.trusted ? "checkmark.shield.fill" : "exclamationmark.shield.fill"
    }

    private var badgeColor: Color {
        if !controller.hasCA { return .gray }
        return controller.trusted ? .green : .orange
    }

    private var badgeTitle: String {
        if !controller.hasCA { return String(localized: "No Root Yet") }
        return controller.trusted ? String(localized: "Trusted") : String(localized: "Not Trusted")
    }

    private var badgeSubtitle: String {
        if !controller.hasCA {
            return String(localized: "Generate a root to begin.")
        }
        return controller.trusted
            ? String(localized: "Apps will accept the MITM certificate.")
            : String(localized: "Install the profile and enable trust to use MITM.")
    }

    // MARK: - Export

    private func prepareCerExport() {
        guard certificateURL() != nil else {
            errorMessage = String(localized: "Failed to export certificate.")
            return
        }
        exportingCer = true
    }

    /// Hosts the .mobileconfig over a one-shot HTTP server bound to
    /// 127.0.0.1 and opens the URL — only Safari and the system profile
    /// installer recognise the `application/x-apple-aspen-config` MIME
    /// type, so a regular share-sheet hand-off won't trigger the install
    /// flow.
    private func installProfile() {
        guard let plist = controller.mobileConfigData() else {
            errorMessage = String(localized: "Failed to export profile.")
            return
        }
        Task { @MainActor in
            do {
                let url = try await MITMProfileServer.shared.start(payload: plist)
                UIApplication.shared.open(url) { success in
                    if !success {
                        Task { @MainActor in
                            errorMessage = String(localized: "Failed to open profile installer.")
                        }
                    }
                }
            } catch {
                errorMessage = String(describing: error)
            }
        }
    }

    private func certificateURL() -> URL? {
        guard let der = controller.certificateData() else { return nil }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("AnywhereMITMRoot.cer")
        do {
            try der.write(to: url, options: .atomic)
            return url
        } catch {
            errorMessage = String(describing: error)
            return nil
        }
    }
}

private struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
