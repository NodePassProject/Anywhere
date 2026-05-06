//
//  CustomRuleSetDetailView.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/5/26.
//

import SwiftUI

struct CustomRuleSetDetailView: View {
    let customRuleSetId: UUID
    @ObservedObject private var ruleSetStore = RoutingRuleSetStore.shared
    @ObservedObject private var viewModel = VPNViewModel.shared

    @State private var showAddRuleSheet = false
    @State private var showImportSheet = false
    @State private var showRenameAlert = false
    @State private var renameText = ""

    private var customRuleSet: CustomRoutingRuleSet? {
        ruleSetStore.customRuleSet(for: customRuleSetId)
    }

    private var ruleSet: RoutingRuleSet? {
        ruleSetStore.ruleSets.first { $0.id == customRuleSetId.uuidString }
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
            AddRoutingRuleView(customRuleSetId: customRuleSetId)
        }
        .sheet(isPresented: $showImportSheet) {
            ImportRoutingRulesView(customRuleSetId: customRuleSetId)
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

    private func ruleRow(_ rule: RoutingRule) -> some View {
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

    private func assignmentPicker(for ruleSet: RoutingRuleSet) -> some View {
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
        }
    }

    private func ruleTypeLabel(_ type: RoutingRuleType) -> String {
        switch type {
        case .domainSuffix: return String(localized: "Domain Suffix")
        case .domainKeyword: return String(localized: "Domain Keyword")
        case .ipCIDR: return String(localized: "IPv4 CIDR")
        case .ipCIDR6: return String(localized: "IPv6 CIDR")
        }
    }

    private func iconName(for type: RoutingRuleType) -> String {
        switch type {
        case .domainSuffix: return "globe"
        case .domainKeyword: return "magnifyingglass"
        case .ipCIDR, .ipCIDR6: return "network"
        }
    }
}

// MARK: - Add Rule Sheet

private struct AddRoutingRuleView: View {
    let customRuleSetId: UUID
    @ObservedObject private var ruleSetStore = RoutingRuleSetStore.shared
    @ObservedObject private var viewModel = VPNViewModel.shared
    @Environment(\.dismiss) private var dismiss

    @State private var routingRuleValue = ""
    @State private var routingRuleType: RoutingRuleType = .domainSuffix

    var body: some View {
        NavigationStack {
            Form {
                Picker("Type", selection: $routingRuleType) {
                    Text("Domain Suffix").tag(RoutingRuleType.domainSuffix)
                    Text("Domain Keyword").tag(RoutingRuleType.domainKeyword)
                    Text("IPv4 CIDR").tag(RoutingRuleType.ipCIDR)
                    Text("IPv6 CIDR").tag(RoutingRuleType.ipCIDR6)
                }
                TextField(placeholder, text: $routingRuleValue)
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
                        let value = routingRuleValue.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !value.isEmpty else { return }
                        ruleSetStore.addRule(to: customRuleSetId, rule: RoutingRule(type: routingRuleType, value: RoutingRuleParser.normalizeValue(value, type: routingRuleType)))
                        Task { await viewModel.syncRoutingConfigurationToNE() }
                        dismiss()
                    }
                    .disabled(routingRuleValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
        .presentationDetents([.medium])
    }

    private var placeholder: String {
        switch routingRuleType {
        case .domainSuffix: return "example.com"
        case .domainKeyword: return "example"
        case .ipCIDR: return "10.0.0.0/8"
        case .ipCIDR6: return "2001:db8::/32"
        }
    }
}

// MARK: - Import Rules Sheet

private struct ImportRoutingRulesView: View {
    let customRuleSetId: UUID
    @ObservedObject private var ruleSetStore = RoutingRuleSetStore.shared
    @ObservedObject private var viewModel = VPNViewModel.shared
    @Environment(\.dismiss) private var dismiss

    @State private var text = ""
    @State private var url = ""
    @State private var isDownloading = false
    @State private var downloadError: String?

    private var parsedRoutingRules: [RoutingRule] {
        RoutingRuleParser.parse(text)
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

                let parsedRuleCount = parsedRoutingRules.count
                if parsedRuleCount > 0 {
                    Section {
                        Text("\(parsedRoutingRules.count) rule(s)")
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
                        ruleSetStore.addRules(to: customRuleSetId, rules: parsedRoutingRules)
                        Task { await viewModel.syncRoutingConfigurationToNE() }
                        dismiss()
                    }
                    .disabled(parsedRoutingRules.isEmpty)
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

/// Text-based importer for ``RoutingRule``s.
///
/// Each non-empty, non-comment line becomes one rule. Fields are separated
/// by `,`; whitespace around them is trimmed.
///
///     <type>, <value>
///
/// Type IDs match ``RoutingRuleType``'s raw values:
///
/// | ID  | Type           | Value                                         |
/// | --- | -------------- | --------------------------------------------- |
/// | `0` | IPv4 CIDR      | `10.0.0.0/8` (`/32` appended if no prefix)    |
/// | `1` | IPv6 CIDR      | `2001:db8::/32` (`/128` appended if no prefix) |
/// | `2` | Domain Suffix  | `example.com`                                 |
/// | `3` | Domain Keyword | `example`                                     |
///
/// Comment lines start with `#` or `//`. Lines that fail validation are
/// skipped silently so a partially-valid file imports the rules it can.
enum RoutingRuleParser {
    static func parse(_ text: String) -> [RoutingRule] {
        text
            .components(separatedBy: .newlines)
            .compactMap { parseLine($0) }
    }

    private static func parseLine(_ line: String) -> RoutingRule? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        if trimmed.hasPrefix("#") || trimmed.hasPrefix("//") { return nil }

        guard let commaIndex = trimmed.firstIndex(of: ",") else { return nil }
        let prefix = trimmed[trimmed.startIndex..<commaIndex].trimmingCharacters(in: .whitespaces)
        let value = trimmed[trimmed.index(after: commaIndex)...].trimmingCharacters(in: .whitespaces)
        guard !value.isEmpty else { return nil }

        guard let typeInt = Int(prefix), let type = RoutingRuleType(rawValue: typeInt) else { return nil }
        return RoutingRule(type: type, value: normalizeValue(value, type: type))
    }

    static func normalizeValue(_ value: String, type: RoutingRuleType) -> String {
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
