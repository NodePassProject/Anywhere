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
    @Environment(\.scenePhase) private var scenePhase

    @StateObject private var controller = MITMCertificateController.shared

    @State private var exportingCer = false
    @State private var showRegenerateConfirm = false
    @State private var showDeleteConfirm = false
    @State private var errorMessage: String?
    @State private var profileServerStarted = false

    var body: some View {
        Form {
            Section {
                HStack {
                    Image("certificate")
                        .resizable()
                        .scaledToFit()
                        .frame(width: 60)
                    VStack(alignment: .leading) {
                        HStack {
                            Image(systemName: badgeIcon)
                                .foregroundStyle(badgeColor)
                                .animation(.default, value: badgeIcon)
                                .animation(.default, value: badgeColor)
                            Text(badgeTitle)
                                .font(.headline)
                                .animation(.default, value: badgeTitle)
                        }
                        Text(badgeSubtitle)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .animation(.default, value: badgeSubtitle)
                    }
                }
                .frame(minHeight: 80)
            }

            if controller.hasCA {
                Section {
                    HStack {
                        TextWithColorfulIcon(title: "Install Certificate", comment: nil, systemName: "square.and.arrow.down", foregroundColor: .white, backgroundColor: .blue)
                        Spacer()
                        Image(systemName: "chevron.right")
                            .font(.footnote.bold())
                            .foregroundStyle(.tertiary)
                    }
                    .contentShape(Rectangle())
                    .onTapGesture {
                        installProfile()
                    }
                }

                Section {
                    Button {
                        prepareCerExport()
                    } label: {
                        Text("Export Certificate")
                    }

                    Button {
                        showRegenerateConfirm = true
                    } label: {
                        Text("Regenerate Certificate")
                    }

                    Button(role: .destructive) {
                        showDeleteConfirm = true
                    } label: {
                        Text("Delete Certificate")
                    }
                }
            } else {
                Section {
                    Button {
                        do {
                            try controller.ensureCA()
                        } catch {
                            errorMessage = String(describing: error)
                        }
                    } label: {
                        Label("Generate Certificate", systemImage: "plus")
                    }
                }
            }
        }
        .navigationTitle("Root Certificate")
        .alert("Regenerate Certificate", isPresented: $showRegenerateConfirm) {
            Button("Regenerate", role: .destructive) {
                do {
                    try controller.regenerate()
                } catch {
                    errorMessage = String(describing: error)
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Any previously installed MITM profile will stop working until you re-install the new certificate.")
        }
        .alert("Delete Certificate", isPresented: $showDeleteConfirm) {
            Button("Delete", role: .destructive) {
                controller.delete()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("You'll need to regenerate a certificate to use MITM again.")
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
        .onAppear {
            controller.refresh()
        }
        .onDisappear {
            MITMProfileServer.shared.stop()
        }
        .onChange(of: scenePhase) { _, newValue in
            if newValue == .active {
                controller.refresh()
            }
        }
    }

    // MARK: - Status badge

    private var badgeIcon: String {
        if !controller.hasCA { return "xmark.circle.fill" }
        return controller.trusted ? "checkmark.circle.fill" : "exclamationmark.circle.fill"
    }

    private var badgeColor: Color {
        if !controller.hasCA { return .red }
        return controller.trusted ? .green : .orange
    }

    private var badgeTitle: String {
        if !controller.hasCA { return String(localized: "No Certificate") }
        return controller.trusted ? String(localized: "Trusted") : String(localized: "Not Trusted")
    }

    private var badgeSubtitle: String {
        if !controller.hasCA {
            return String(localized: "Generate a certificate to begin.")
        }
        return controller.trusted
            ? String(localized: "Anywhere Root Certificate is installed and trusted.")
            : String(localized: "Install the profile and trust in Settings to use MITM.")
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
