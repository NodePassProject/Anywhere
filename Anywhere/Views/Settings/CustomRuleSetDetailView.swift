//
//  CustomRuleSetDetailView.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/5/26.
//

import SwiftUI

struct CustomRuleSetDetailView: View {
    let customRuleSetId: UUID
    @ObservedObject private var ruleSetStore = RuleSetStore.shared
    @ObservedObject private var viewModel = VPNViewModel.shared

    @State private var showAddRuleSheet = false
    @State private var showImportSheet = false
    @State private var showRenameAlert = false
    @State private var renameText = ""

    private var customRuleSet: RuleSetStore.CustomRuleSet? {
        ruleSetStore.customRuleSet(for: customRuleSetId)
    }

    private var ruleSet: RuleSetStore.RuleSet? {
        ruleSetStore.ruleSets.first { $0.id == customRuleSetId.uuidString }
    }

    private var standaloneConfigurations: [ProxyConfiguration] {
        viewModel.configurations.filter { $0.subscriptionId == nil }
    }

    private var subscribedGroups: [(Subscription, [ProxyConfiguration])] {
        viewModel.subscriptions.compactMap { subscription in
            let configurations = viewModel.configurations(for: subscription)
            return configurations.isEmpty ? nil : (subscription, configurations)
        }
    }

    var body: some View {
        List {
            if let ruleSet {
                Section {
                    assignmentPicker(for: ruleSet)
                }
            }

            if let customRuleSet, !customRuleSet.rules.isEmpty {
                Section("Rules") {
                    ForEach(Array(customRuleSet.rules.enumerated()), id: \.offset) { _, rule in
                        ruleRow(rule)
                    }
                    .onDelete { offsets in
                        ruleSetStore.removeRules(from: customRuleSetId, at: Array(offsets))
                        Task { await viewModel.syncRoutingConfigurationToNE() }
                    }
                }
            }
        }
        .navigationTitle(customRuleSet?.name ?? String(localized: "Rule Set"))
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu("More", systemImage: "ellipsis") {
                    Button {
                        showAddRuleSheet = true
                    } label: {
                        Label("Add Rule", systemImage: "plus")
                    }
                    Button {
                        showImportSheet = true
                    } label: {
                        Label("Import Rules", systemImage: "square.and.arrow.down")
                    }
                    Button {
                        renameText = customRuleSet?.name ?? ""
                        showRenameAlert = true
                    } label: {
                        Label("Rename", systemImage: "pencil")
                    }
                }
            }
        }
        .sheet(isPresented: $showAddRuleSheet) {
            AddRuleView(customRuleSetId: customRuleSetId)
        }
        .sheet(isPresented: $showImportSheet) {
            ImportRulesView(customRuleSetId: customRuleSetId)
        }
        .alert("Rename Rule Set", isPresented: $showRenameAlert) {
            TextField("Name", text: $renameText)
            Button("Rename") {
                let name = renameText.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty else { return }
                ruleSetStore.updateCustomRuleSet(customRuleSetId, name: name)
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    private func ruleRow(_ rule: DomainRule) -> some View {
        HStack {
            Image(systemName: iconName(for: rule.type))
                .foregroundStyle(.secondary)
                .frame(width: 24)
            VStack(alignment: .leading) {
                Text(rule.value)
                    .font(.system(size: 14).monospaced())
                    .minimumScaleFactor(0.1)
                    .lineLimit(1)
                Text(ruleTypeLabel(rule.type))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func assignmentPicker(for ruleSet: RuleSetStore.RuleSet) -> some View {
        Picker("Route To", selection: Binding(
            get: { ruleSet.assignedConfigurationId },
            set: { newValue in
                ruleSetStore.updateAssignment(ruleSet, configurationId: newValue)
                Task { await viewModel.syncRoutingConfigurationToNE() }
            }
        )) {
            Text("Default").tag(nil as String?)
            Text("DIRECT").tag("DIRECT" as String?)
            Text("REJECT").tag("REJECT" as String?)
            ForEach(standaloneConfigurations) { configuration in
                Text(configuration.name).tag(configuration.id.uuidString as String?)
            }
            ForEach(subscribedGroups, id: \.0.id) { subscription, configurations in
                Section {
                    ForEach(configurations) { configuration in
                        Text(configuration.name).tag(configuration.id.uuidString as String?)
                    }
                } header: {
                    Text(subscription.name)
                }
            }
        }
    }

    private func ruleTypeLabel(_ type: DomainRuleType) -> String {
        switch type {
        case .domainSuffix: return String(localized: "Domain Suffix")
        case .domainKeyword: return String(localized: "Domain Keyword")
        case .ipCIDR: return String(localized: "IPv4 CIDR")
        case .ipCIDR6: return String(localized: "IPv6 CIDR")
        }
    }

    private func iconName(for type: DomainRuleType) -> String {
        switch type {
        case .domainSuffix: return "globe"
        case .domainKeyword: return "magnifyingglass"
        case .ipCIDR, .ipCIDR6: return "network"
        }
    }
}

// MARK: - Add Rule Sheet

private struct AddRuleView: View {
    let customRuleSetId: UUID
    @ObservedObject private var ruleSetStore = RuleSetStore.shared
    @ObservedObject private var viewModel = VPNViewModel.shared
    @Environment(\.dismiss) private var dismiss

    @State private var ruleValue = ""
    @State private var ruleType: DomainRuleType = .domainSuffix

    var body: some View {
        NavigationStack {
            Form {
                Picker("Type", selection: $ruleType) {
                    Text("Domain Suffix").tag(DomainRuleType.domainSuffix)
                    Text("Domain Keyword").tag(DomainRuleType.domainKeyword)
                    Text("IPv4 CIDR").tag(DomainRuleType.ipCIDR)
                    Text("IPv6 CIDR").tag(DomainRuleType.ipCIDR6)
                }
                TextField(placeholder, text: $ruleValue)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .font(.body.monospaced())
            }
            .navigationTitle("Add Rule")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    CancelButton("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    ConfirmButton("Add") {
                        let value = ruleValue.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !value.isEmpty else { return }
                        ruleSetStore.addRule(to: customRuleSetId, rule: DomainRule(type: ruleType, value: value))
                        Task { await viewModel.syncRoutingConfigurationToNE() }
                        dismiss()
                    }
                    .disabled(ruleValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
        .presentationDetents([.medium])
    }

    private var placeholder: String {
        switch ruleType {
        case .domainSuffix: return "example.com"
        case .domainKeyword: return "example"
        case .ipCIDR: return "10.0.0.0/8"
        case .ipCIDR6: return "2001:db8::/32"
        }
    }
}

// MARK: - Import Rules Sheet

private struct ImportRulesView: View {
    let customRuleSetId: UUID
    @ObservedObject private var ruleSetStore = RuleSetStore.shared
    @ObservedObject private var viewModel = VPNViewModel.shared
    @Environment(\.dismiss) private var dismiss

    @State private var text = ""
    @State private var url = ""
    @State private var isDownloading = false
    @State private var downloadError: String?

    private var parsedRules: [DomainRule] {
        RuleParser.parse(text)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Rules") {
                    TextEditor(text: $text)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .font(.system(size: 12).monospaced())
                        .frame(minHeight: 200)
                }
                
                Section {
                    HStack {
                        TextField("Anywhere Rule List URL", text: $url)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .keyboardType(.URL)
                            .textFieldStyle(.plain)
                        if #available(iOS 26.0, *) {
                            Button {
                                Task { await download() }
                            } label: {
                                VStack {
                                    if isDownloading {
                                        ProgressView()
                                    } else {
                                        Image(systemName: "checkmark")
                                            .accessibilityLabel("Download")
                                    }
                                }
                            }
                            .buttonBorderShape(.circle)
                            .buttonStyle(.glassProminent)
                            .disabled(url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isDownloading)
                        } else {
                            Button {
                                Task { await download() }
                            } label: {
                                ZStack {
                                    Text("Download")
                                    if isDownloading {
                                        ProgressView()
                                    }
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isDownloading)
                        }
                    }
                    
                } header: {
                    Text("Download From Internet")
                } footer: {
                    if let downloadError {
                        Text(downloadError)
                            .foregroundStyle(.red)
                            .font(.caption)
                    }
                }

                let parsedRuleCount = parsedRules.count
                if parsedRuleCount > 0 {
                    Section {
                        Text("\(parsedRules.count) rule(s)")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Import Rules")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    CancelButton("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    ConfirmButton("Import") {
                        ruleSetStore.addRules(to: customRuleSetId, rules: parsedRules)
                        Task { await viewModel.syncRoutingConfigurationToNE() }
                        dismiss()
                    }
                    .disabled(parsedRules.isEmpty)
                }
            }
        }
    }

    private func download() async {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let requestURL = URL(string: trimmed) else {
            downloadError = String(localized: "Invalid URL.")
            return
        }
        isDownloading = true
        downloadError = nil
        do {
            let (data, response) = try await URLSession.shared.data(from: requestURL)
            if let httpResponse = response as? HTTPURLResponse,
               !(200...299).contains(httpResponse.statusCode) {
                downloadError = "HTTP \(httpResponse.statusCode)"
            } else if let body = String(data: data, encoding: .utf8) {
                text = body
            } else {
                downloadError = String(localized: "Unknown content.")
            }
        } catch {
            downloadError = error.localizedDescription
        }
        isDownloading = false
    }
}

// MARK: - Rule Parser

enum RuleParser {

    static func parse(_ text: String) -> [DomainRule] {
        text
            .components(separatedBy: .newlines)
            .compactMap { parseLine($0) }
    }

    private static func parseLine(_ line: String) -> DomainRule? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        // Skip comment lines
        if trimmed.hasPrefix("#") || trimmed.hasPrefix("//") { return nil }

        // Try comma-separated formats: "type, value"
        if let commaIndex = trimmed.firstIndex(of: ",") {
            let prefix = trimmed[trimmed.startIndex..<commaIndex].trimmingCharacters(in: .whitespaces)
            let value = trimmed[trimmed.index(after: commaIndex)...].trimmingCharacters(in: .whitespaces)
            guard !value.isEmpty else { return nil }

            // Anywhere format:
            // "0, ..."(IPv4 CIDR)
            // "1, ..."(IPv6 CIDR)
            // "2, ..."(Domain Suffix)
            // "3, ..."(Domain Keyword)
            if let typeInt = Int(prefix), let type = DomainRuleType(rawValue: typeInt) {
                return DomainRule(type: type, value: normalizeValue(value, type: type))
            }
        }

        // No comma — unrecognized format
        return nil
    }

    private static func normalizeValue(_ value: String, type: DomainRuleType) -> String {
        switch type {
        case .ipCIDR:
            // Single IPv4 (no slash) → append /32
            if !value.contains("/") {
                return value + "/32"
            }
            return value
        case .ipCIDR6:
            // Single IPv6 (no slash) → append /128
            if !value.contains("/") {
                return value + "/128"
            }
            return value
        case .domainSuffix, .domainKeyword:
            return value
        }
    }
}
