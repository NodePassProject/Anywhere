//
//  MITMSettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import SwiftUI
import UniformTypeIdentifiers

struct MITMSettingsView: View {
    @StateObject private var store = MITMRuleSetStore.shared

    private static let importAllowedContentTypes: [UTType] = [UTType(filenameExtension: "amrs") ?? .data]

    @State private var showAddSheet = false
    @State private var newRuleSetName = ""

    @State private var showFileImporter = false
    @State private var importError: String?

    @State private var showSubscribeAlert = false
    @State private var subscribeURL = ""
    @State private var subscribeError: String?

    var body: some View {
        Form {
            Section {
                Toggle(isOn: $store.enabled) {
                    TextWithColorfulIcon(title: "MITM", comment: nil, systemName: "key.horizontal.fill", foregroundColor: .white, backgroundColor: .indigo)
                }
            }

            Section {
                NavigationLink {
                    MITMCertificateView()
                } label: {
                    TextWithColorfulIcon(title: "Root Certificate", comment: nil, systemName: "lock.rectangle.fill", foregroundColor: .white, backgroundColor: .green)
                }
            }

            if !store.ruleSets.isEmpty {
                Section("Rule Sets") {
                    ForEach(store.ruleSets) { ruleSet in
                        NavigationLink {
                            MITMRuleSetDetailView(ruleSet: ruleSet)
                        } label: {
                            ruleSetRow(for: ruleSet)
                        }
                    }
                    .onDelete { offsets in
                        store.removeRuleSets(atOffsets: offsets)
                    }
                    .onMove { source, destination in
                        store.moveRuleSets(fromOffsets: source, toOffset: destination)
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
                store.addRuleSet(MITMRuleSet(name: name))
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
                rewriteTarget: parsed.rewriteTarget,
                rules: parsed.rules
            )
            store.addRuleSet(ruleSet)
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
                    rewriteTarget: parsed.rewriteTarget,
                    rules: parsed.rules,
                    subscriptionURL: url
                )
                store.addRuleSet(ruleSet)
            } catch {
                subscribeError = error.localizedDescription
            }
        }
    }

    private func summary(for ruleSet: MITMRuleSet) -> String {
        let count = ruleSet.rules.count
        let rulesPart = String(localized: "\(count) rule(s)")
        guard let target = ruleSet.rewriteTarget else {
            return rulesPart
        }
        switch target.action {
        case .transparent:
            let authority = target.port.map { "\(target.host):\($0)" } ?? target.host
            return "→ \(authority) · \(rulesPart)"
        case .redirect302:
            let authority = target.port.map { "\(target.host):\($0)" } ?? target.host
            return "302 → \(authority) · \(rulesPart)"
        case .reject200:
            return "Reject 200 · \(rulesPart)"
        }
    }
}
