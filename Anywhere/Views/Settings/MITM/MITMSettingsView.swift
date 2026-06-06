//
//  MITMSettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import SwiftUI
import UniformTypeIdentifiers

struct MITMSettingsView: View {
    @Environment(MITMCertificateController.self) private var certificateController
    @Environment(MITMRuleSetStore.self) private var ruleSetStore

    private static let importAllowedContentTypes: [UTType] = [UTType(filenameExtension: "amrs") ?? .data]

    @State private var showAddSheet = false
    @State private var newRuleSetName = ""

    @State private var showFileImporter = false
    @State private var importError: String?

    @State private var showSubscribeAlert = false
    @State private var subscribeURL = ""
    @State private var subscribeError: String?

    var body: some View {
        @Bindable var ruleSetStore = ruleSetStore
        Form {
            Section {
                Toggle(isOn: $ruleSetStore.enabled) {
                    TextWithColorfulIcon(title: "MITM", comment: nil, systemName: "key.horizontal.fill", foregroundColor: .white, backgroundColor: .indigo)
                }
            }

            Section {
                NavigationLink {
                    MITMCertificateView()
                } label: {
                    HStack {
                        TextWithColorfulIcon(title: "Root Certificate", comment: nil, systemName: "lock.rectangle.fill", foregroundColor: .white, backgroundColor: .green)
                        Spacer()
                        Image(systemName: certificateStatusBadgeIcon)
                            .foregroundStyle(certificateStatusBadgeColor)
                    }
                }
            }

            if !ruleSetStore.ruleSets.isEmpty {
                Section("Rule Sets") {
                    ForEach(ruleSetStore.ruleSets) { ruleSet in
                        NavigationLink {
                            MITMRuleSetDetailView(ruleSet: ruleSet)
                        } label: {
                            ruleSetRow(for: ruleSet)
                        }
                    }
                    .onDelete { offsets in
                        ruleSetStore.removeRuleSets(atOffsets: offsets)
                    }
                    .onMove { source, destination in
                        ruleSetStore.moveRuleSets(fromOffsets: source, toOffset: destination)
                    }
                }
            }
        }
        .navigationTitle("MITM")
        .toolbar {
            ToolbarItem {
                EditButton()
            }
            ToolbarItem {
                Menu("More", systemImage: "ellipsis") {
                    Button {
                        showAddSheet = true
                    } label: {
                        Label("Add Rule Set", systemImage: "plus")
                    }
                    Button {
                        importError = nil
                        showFileImporter = true
                    } label: {
                        Label("Import Rule Set", systemImage: "square.and.arrow.down")
                    }
                    Button {
                        subscribeURL = ""
                        showSubscribeAlert = true
                    } label: {
                        Label("Subscribe Rule Set", systemImage: "link")
                    }
                }
            }
        }
        .alert("Add Rule Set", isPresented: $showAddSheet) {
            TextField("Name", text: $newRuleSetName)
            Button("Add") {
                let name = newRuleSetName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty else { return }
                ruleSetStore.addRuleSet(MITMRuleSet(name: name))
                newRuleSetName = ""
            }
            Button("Cancel", role: .cancel) {
                newRuleSetName = ""
            }
        }
        .fileImporter(
            isPresented: $showFileImporter,
            allowedContentTypes: Self.importAllowedContentTypes
        ) { result in
            handleFileImport(result)
        }
        .alert("Import Failed", isPresented: Binding(
            get: { importError != nil },
            set: { if !$0 { importError = nil } }
        )) {
            Button("OK") { importError = nil }
        } message: {
            Text(importError ?? "")
        }
        .alert("Subscribe Rule Set", isPresented: $showSubscribeAlert) {
            TextField("Anywhere MITM Rule Set URL", text: $subscribeURL)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .keyboardType(.URL)
            Button("Subscribe") {
                subscribe(to: subscribeURL)
            }
            Button("Cancel", role: .cancel) {}
        }
        .alert("Subscription Failed", isPresented: Binding(
            get: { subscribeError != nil },
            set: { if !$0 { subscribeError = nil } }
        )) {
            Button("OK") { subscribeError = nil }
        } message: {
            Text(subscribeError ?? "")
        }
    }

    @ViewBuilder
    private func ruleSetRow(for ruleSet: MITMRuleSet) -> some View {
        HStack {
            Image(systemName: "list.bullet.rectangle")
                .foregroundStyle(.secondary)
                .frame(width: 32, height: 32)
            VStack(alignment: .leading) {
                Text(ruleSet.name)
                    .foregroundStyle(.primary)
                Text(summary(for: ruleSet))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .truncationMode(.middle)
                    .lineLimit(1)
            }
            Spacer()
            if ruleSet.enabled {
                Text("Enabled")
                    .foregroundStyle(.secondary)
            } else {
                Text("Disabled")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func handleFileImport(_ result: Result<URL, Error>) {
        do {
            let url = try result.get()
            guard url.pathExtension.lowercased() == "amrs" else {
                importError = String(localized: "Invalid Anywhere MITM Rule Set File.")
                return
            }
            let accessing = url.startAccessingSecurityScopedResource()
            defer { if accessing { url.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: url)
            guard let body = String(data: data, encoding: .utf8) else {
                importError = String(localized: "Unknown content.")
                return
            }
            let parsed = MITMRuleSetParser.parse(body)
            guard parsed.rules.count <= MITMRuleSet.maxRuleCount else {
                importError = String(localized: "Rule set is too large.")
                return
            }
            let name = parsed.name.isEmpty
                ? (url.deletingPathExtension().lastPathComponent.isEmpty ? "Imported" : url.deletingPathExtension().lastPathComponent)
                : parsed.name
            let ruleSet = MITMRuleSet(
                name: name,
                domainSuffixes: parsed.domainSuffixes,
                rules: parsed.rules
            )
            ruleSetStore.addRuleSet(ruleSet)
        } catch {
            importError = error.localizedDescription
        }
    }

    private func subscribe(to rawValue: String) {
        guard let url = MITMRuleSet.validSubscriptionURL(from: rawValue) else {
            subscribeError = String(localized: "Invalid Anywhere MITM Rule Set URL.")
            return
        }
        Task {
            do {
                let (data, response) = try await URLSession.shared.data(from: url)
                if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                    subscribeError = "HTTP \(http.statusCode)"
                    return
                }
                guard let body = String(data: data, encoding: .utf8) else {
                    subscribeError = String(localized: "Unknown content.")
                    return
                }
                let parsed = MITMRuleSetParser.parse(body)
                guard parsed.rules.count <= MITMRuleSet.maxRuleCount else {
                    subscribeError = String(localized: "Rule set is too large.")
                    return
                }
                let name = parsed.name.isEmpty
                    ? (url.deletingPathExtension().lastPathComponent.isEmpty ? "Subscription" : url.deletingPathExtension().lastPathComponent)
                    : parsed.name
                let ruleSet = MITMRuleSet(
                    name: name,
                    domainSuffixes: parsed.domainSuffixes,
                    rules: parsed.rules,
                    subscriptionURL: url
                )
                ruleSetStore.addRuleSet(ruleSet)
            } catch {
                subscribeError = error.localizedDescription
            }
        }
    }
    
    private var certificateStatusBadgeIcon: String {
        if !certificateController.hasCA { return "xmark.circle.fill" }
        return certificateController.trusted ? "checkmark.circle.fill" : "exclamationmark.circle.fill"
    }

    private var certificateStatusBadgeColor: Color {
        if !certificateController.hasCA { return .red }
        return certificateController.trusted ? .green : .orange
    }

    private func summary(for ruleSet: MITMRuleSet) -> String {
        let count = ruleSet.rules.count
        return String(localized: "\(count) rule(s)")
    }
}
