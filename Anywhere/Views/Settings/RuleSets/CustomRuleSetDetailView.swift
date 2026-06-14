//
//  CustomRuleSetDetailView.swift
//  Anywhere
//
//  Created by NodePassProject on 4/5/26.
//

import SwiftUI

struct CustomRuleSetDetailView: View {
    let customRuleSetId: UUID
    @Environment(\.editMode) private var editMode
    @Environment(RoutingRuleSetStore.self) private var ruleSetStore
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(SubscriptionStore.self) private var subscriptionStore

    @State private var rules: [RoutingRule] = []

    @State private var showAddRuleSheet = false
    @State private var showRenameAlert = false
    @State private var renameText = ""

    @State private var isUpdating = false
    @State private var updateError: String?

    private var isEditing: Bool? { editMode?.wrappedValue.isEditing }

    private var customRuleSet: CustomRoutingRuleSet? {
        ruleSetStore.customRuleSet(for: customRuleSetId)
    }

    private var ruleSet: RoutingRuleSet? {
        ruleSetStore.ruleSets.first { $0.id == customRuleSetId.uuidString }
    }

    private var isSubscribed: Bool { customRuleSet?.subscriptionURL != nil }

    var body: some View {
        List {
            if let ruleSet {
                Section {
                    assignmentPicker(for: ruleSet)
                }
            }

            if let subscriptionURL = customRuleSet?.subscriptionURL {
                subscriptionSection(url: subscriptionURL)
            }

            if !rules.isEmpty {
                Section("Rules") {
                    ForEach(rules) { rule in
                        ruleRow(rule)
                    }
                    .onDelete(perform: isSubscribed ? nil : { offsets in
                        rules.remove(atOffsets: offsets)
                        if isEditing != true {
                            save()
                        }
                    })
                    .onMove(perform: isSubscribed ? nil : { source, destination in
                        rules.move(fromOffsets: source, toOffset: destination)
                        if isEditing != true {
                            save()
                        }
                    })
                }
            }
        }
        .navigationTitle(customRuleSet?.name ?? String(localized: "Rule Set"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if !isSubscribed {
                ToolbarItem {
                    EditButton()
                }
            }
            ToolbarItem {
                Menu("More", systemImage: "ellipsis") {
                    if !isSubscribed {
                        Button {
                            showAddRuleSheet = true
                        } label: {
                            Label("Add Rule", systemImage: "plus")
                        }
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
            AddRoutingRuleView { rule in
                rules.append(rule)
                if isEditing != true {
                    save()
                }
            }
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
        .alert("Update Failed", isPresented: Binding(
            get: { updateError != nil },
            set: { if !$0 { updateError = nil } }
        )) {
            Button("OK") { updateError = nil }
        } message: {
            Text(updateError ?? "")
        }
        .onAppear { loadInitial() }
        .onChange(of: isEditing) { _, newValue in
            if newValue == false {
                save()
            }
        }
    }

    private func loadInitial() {
        guard let customRuleSet else { return }
        rules = customRuleSet.rules
    }
    
    private func save() {
        guard rules != customRuleSet?.rules else { return }
        ruleSetStore.updateCustomRuleSet(customRuleSetId, rules: rules)
    }

    @ViewBuilder
    private func subscriptionSection(url: URL) -> some View {
        Section("Subscription") {
            Text(url.absoluteString)
                .font(.system(size: 14).monospaced())
                .foregroundStyle(.secondary)
                .minimumScaleFactor(0.5)
                .truncationMode(.middle)
                .lineLimit(3)
            Button {
                refresh()
            } label: {
                HStack {
                    Label("Update", systemImage: "arrow.clockwise")
                    if isUpdating {
                        Spacer()
                        ProgressView()
                    }
                }
            }
            .disabled(isUpdating)
        }
    }

    private func refresh() {
        isUpdating = true
        Task {
            defer { isUpdating = false }
            do {
                try await ruleSetStore.refreshCustomRuleSet(customRuleSetId)
                loadInitial()
            } catch {
                updateError = error.localizedDescription
            }
        }
    }

    private func ruleRow(_ rule: RoutingRule) -> some View {
        HStack {
            Image(systemName: rule.type.iconName)
                .foregroundStyle(.secondary)
                .frame(width: 24)
            VStack(alignment: .leading) {
                Text(rule.value)
                    .font(.system(size: 14).monospaced())
                    .minimumScaleFactor(0.1)
                    .lineLimit(1)
                Text(rule.type.displayLabel)
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
            }
        )) {
            Text("Default").tag(nil as String?)
            Text("DIRECT").tag("DIRECT" as String?)
            Text("REJECT").tag("REJECT" as String?)
            ForEach(configStore.standalonePickerItems) { item in
                Text(item.name).tag(item.id.uuidString as String?)
            }
            if !chainStore.pickerItems.isEmpty {
                Section {
                    ForEach(chainStore.pickerItems) { item in
                        Text(item.name).tag(item.id.uuidString as String?)
                    }
                } header: {
                    Text("Chains")
                }
            }
            ForEach(subscriptionStore.pickerSections) { section in
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
}

// MARK: - Add Rule Sheet

private struct AddRoutingRuleView: View {
    let onAdd: (RoutingRule) -> Void
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
                        onAdd(RoutingRule(type: routingRuleType, value: routingRuleType.normalized(value)))
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
