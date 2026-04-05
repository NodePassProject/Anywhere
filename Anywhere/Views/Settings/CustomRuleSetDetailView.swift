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
    @State private var showRenameAlert = false
    @State private var renameText = ""

    private var customRuleSet: CustomRuleSet? {
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
        .navigationTitle(customRuleSet?.name ?? "Rule Set")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu("More", systemImage: "ellipsis") {
                    Button {
                        showAddRuleSheet = true
                    } label: {
                        Label("Add Rule", systemImage: "plus")
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
            Image(systemName: rule.type == .domainSuffix ? "globe" : "network")
                .foregroundStyle(.secondary)
                .frame(width: 24)
            VStack(alignment: .leading) {
                Text(rule.value)
                    .font(.body.monospaced())
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
        case .domainSuffix: return "Domain Suffix"
        case .ipCIDR: return "IPv4 CIDR"
        case .ipCIDR6: return "IPv6 CIDR"
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
        case .ipCIDR: return "10.0.0.0/8"
        case .ipCIDR6: return "2001:db8::/32"
        }
    }
}
