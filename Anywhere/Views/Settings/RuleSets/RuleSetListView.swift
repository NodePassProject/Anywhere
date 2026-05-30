//
//  RuleSetListView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI
import UniformTypeIdentifiers

struct RuleSetListView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared

    private static let importAllowedContentTypes: [UTType] = [UTType(filenameExtension: "arrs") ?? .data]

    @State var builtInServiceRuleSets: [RoutingRuleSet] = RoutingRuleSetStore.shared.builtInServiceRuleSets
    @State var customRuleSets: [CustomRoutingRuleSet] = RoutingRuleSetStore.shared.customRuleSets

    @State private var showAddSheet = false
    @State private var newRuleSetName = ""

    @State private var showFileImporter = false
    @State private var importError: String?

    @State private var showSubscribeAlert = false
    @State private var subscribeURL = ""
    @State private var subscribeError: String?
    
    var body: some View {
        List {
            Section {
                ForEach($builtInServiceRuleSets) { $ruleSet in
                    if !ruleSet.isCustom {
                        assignmentPicker(for: $ruleSet)
                    }
                }
            }
            if !customRuleSets.isEmpty {
                Section("Custom") {
                    ForEach(customRuleSets) { customRuleSet in
                        NavigationLink {
                            CustomRuleSetDetailView(customRuleSetId: customRuleSet.id)
                        } label: {
                            ruleSetRow(for: customRuleSet)
                        }
                    }
                    .onDelete { offsets in
                        let customRuleSets = RoutingRuleSetStore.shared.customRuleSets
                        for offset in offsets {
                            RoutingRuleSetStore.shared.removeCustomRuleSet(customRuleSets[offset].id)
                        }
                        self.customRuleSets = RoutingRuleSetStore.shared.customRuleSets
                        Task { await viewModel.syncRoutingConfigurationToNE() }
                    }
                }
            }
        }
        .listRowSpacing(8)
        .navigationTitle("Routing Rules")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
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
                    Button {
                        RoutingRuleSetStore.shared.resetAssignments()
                        builtInServiceRuleSets = RoutingRuleSetStore.shared.builtInServiceRuleSets
                        Task { await viewModel.syncRoutingConfigurationToNE() }
                    } label: {
                        Label("Reset", systemImage: "arrow.clockwise")
                    }
                }
            }
        }
        .onChange(of: builtInServiceRuleSets) { oldValue, newValue in
            var routingChanged: Bool = false
            for currentRuleSet in newValue {
                let previousRuleSet = oldValue.first(where: { $0.id == currentRuleSet.id })
                if currentRuleSet.assignedConfigurationId != previousRuleSet?.assignedConfigurationId {
                    RoutingRuleSetStore.shared.updateAssignment(currentRuleSet, configurationId: currentRuleSet.assignedConfigurationId)
                    routingChanged = true
                }
            }
            if routingChanged {
                Task { await viewModel.syncRoutingConfigurationToNE() }
            }
        }
        .onAppear {
            builtInServiceRuleSets = RoutingRuleSetStore.shared.builtInServiceRuleSets
            customRuleSets = RoutingRuleSetStore.shared.customRuleSets
        }
        .fileImporter(
            isPresented: $showFileImporter,
            allowedContentTypes: Self.importAllowedContentTypes
        ) { result in
            handleFileImport(result)
        }
        .alert("Add Rule Set", isPresented: $showAddSheet) {
            TextField("Name", text: $newRuleSetName)
            Button("Add") {
                let name = newRuleSetName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty else { return }
                _ = RoutingRuleSetStore.shared.addCustomRuleSet(name: name)
                customRuleSets = RoutingRuleSetStore.shared.customRuleSets
                newRuleSetName = ""
            }
            Button("Cancel", role: .cancel) {
                newRuleSetName = ""
            }
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
            TextField("Anywhere Routing Rule Set URL", text: $subscribeURL)
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
    private func ruleSetRow(for ruleSet: CustomRoutingRuleSet) -> some View {
        HStack {
            Image(systemName: "list.bullet.rectangle")
                .foregroundStyle(.secondary)
                .frame(width: 32, height: 32)
            VStack(alignment: .leading) {
                Text(ruleSet.name)
                Text("\(ruleSet.rules.count) rule(s)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if let ruleSet = builtInServiceRuleSets.first(where: { $0.id == ruleSet.id.uuidString }) {
                assignmentLabel(for: ruleSet)
            }
        }
    }

    private func handleFileImport(_ result: Result<URL, Error>) {
        do {
            let url = try result.get()
            guard url.pathExtension.lowercased() == "arrs" else {
                importError = String(localized: "Invalid Anywhere Routing Rule Set File.")
                return
            }
            let accessing = url.startAccessingSecurityScopedResource()
            defer { if accessing { url.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: url)
            guard let body = String(data: data, encoding: .utf8) else {
                importError = String(localized: "Unknown content.")
                return
            }
            let parsed = RoutingRuleSetParser.parse(body)
            guard parsed.rules.count <= CustomRoutingRuleSet.maxRuleCount else {
                importError = String(localized: "Rule set is too large.")
                return
            }
            let name = parsed.name.isEmpty
                ? (url.deletingPathExtension().lastPathComponent.isEmpty ? "Imported" : url.deletingPathExtension().lastPathComponent)
                : parsed.name
            let ruleSet = CustomRoutingRuleSet(name: name, rules: parsed.rules)
            RoutingRuleSetStore.shared.addCustomRuleSet(ruleSet)
            customRuleSets = RoutingRuleSetStore.shared.customRuleSets
            Task { await viewModel.syncRoutingConfigurationToNE() }
        } catch {
            importError = error.localizedDescription
        }
    }

    private func subscribe(to rawValue: String) {
        guard let url = CustomRoutingRuleSet.validSubscriptionURL(from: rawValue) else {
            subscribeError = String(localized: "Invalid Anywhere Routing Rule Set URL.")
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
                let parsed = RoutingRuleSetParser.parse(body)
                guard parsed.rules.count <= CustomRoutingRuleSet.maxRuleCount else {
                    subscribeError = String(localized: "Rule set is too large.")
                    return
                }
                let name = parsed.name.isEmpty
                    ? (url.deletingPathExtension().lastPathComponent.isEmpty ? "Subscription" : url.deletingPathExtension().lastPathComponent)
                    : parsed.name
                let ruleSet = CustomRoutingRuleSet(name: name, rules: parsed.rules, subscriptionURL: url)
                RoutingRuleSetStore.shared.addCustomRuleSet(ruleSet)
                customRuleSets = RoutingRuleSetStore.shared.customRuleSets
                await viewModel.syncRoutingConfigurationToNE()
            } catch {
                subscribeError = error.localizedDescription
            }
        }
    }
    
    @ViewBuilder
    private func assignmentPicker(for ruleSet: Binding<RoutingRuleSet>) -> some View {
        Picker(selection: ruleSet.assignedConfigurationId) {
            Text("Default").tag(nil as String?)
            Text("DIRECT").tag("DIRECT" as String?)
            Text("REJECT").tag("REJECT" as String?)
            ForEach(viewModel.standalonePickerItems) { item in
                Text(item.name).tag(item.id.uuidString as String?)
            }
            if !viewModel.chainPickerItems.isEmpty {
                Section {
                    ForEach(viewModel.chainPickerItems) { item in
                        Text(item.name).tag(item.id.uuidString as String?)
                    }
                } header: {
                    Text("Chains")
                }
            }
            ForEach(viewModel.subscriptionPickerSections) { section in
                Section {
                    ForEach(section.items) { item in
                        Text(item.name).tag(item.id.uuidString as String?)
                    }
                } header: {
                    Text(section.header ?? "")
                }
            }
        } label: {
            HStack {
                AppIconView(ruleSet.wrappedValue.name)
                Text(ruleSet.wrappedValue.name)
            }
        }
    }

    @ViewBuilder
    private func assignmentLabel(for ruleSet: RoutingRuleSet) -> some View {
        HStack {
            if let assignedId = ruleSet.assignedConfigurationId {
                if assignedId == "DIRECT" {
                    Text("DIRECT")
                } else if assignedId == "REJECT" {
                    Text("REJECT")
                } else if let config = viewModel.configurations.first(where: { $0.id.uuidString == assignedId }) {
                    Text(config.name)
                } else if let chain = viewModel.chains.first(where: { $0.id.uuidString == assignedId }) {
                    Text(chain.name)
                } else {
                    Text("Default")
                }
            } else {
                Text("Default")
            }
        }
        .foregroundStyle(.secondary)
    }
}
