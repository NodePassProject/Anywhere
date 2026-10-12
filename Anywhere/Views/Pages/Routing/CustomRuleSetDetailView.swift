//
//  CustomRuleSetDetailView.swift
//  Anywhere
//
//  Created by NodePassProject on 4/5/26.
//

import SwiftUI

enum RoutingRuleSetTarget: Hashable {
    case custom(UUID)
    case module(moduleId: UUID, ruleSetId: UUID)
}

struct CustomRuleSetDetailView: View {
    @Environment(\.editMode) private var editMode
    @Environment(Operations.self) private var operations
    @Environment(RoutingRuleSetStore.self) private var ruleSetStore
    @Environment(ModuleStore.self) private var moduleStore
    
    let target: RoutingRuleSetTarget

    @State private var rules: [RoutingRule] = []

    @State private var showAddRuleSheet = false
    @State private var showRenameAlert = false
    @State private var renameText = ""

    @State private var isUpdating = false
    @State private var updateSucceeded = false
    @State private var updateError: String?

    init(customRuleSetId: UUID) {
        target = .custom(customRuleSetId)
    }

    init(target: RoutingRuleSetTarget) {
        self.target = target
    }

    private var isEditing: Bool? { editMode?.wrappedValue.isEditing }

    // MARK: - Target resolution

    private var customRuleSet: CustomRoutingRuleSet? {
        guard case .custom(let id) = target else { return nil }
        return ruleSetStore.customRuleSet(for: id)
    }

    private var moduleRuleSet: ModuleRoutingRuleSet? {
        guard case .module(let moduleId, let ruleSetId) = target else { return nil }
        return moduleStore.routingRuleSet(ruleSetId, in: moduleId)
    }

    private var owningModule: Module? {
        guard case .module(let moduleId, _) = target else { return nil }
        return moduleStore.module(id: moduleId)
    }

    private var name: String? { customRuleSet?.name ?? moduleRuleSet?.name }

    private var storedRules: [RoutingRule]? { customRuleSet?.rules ?? moduleRuleSet?.rules }
    
    private var subscriptionURL: URL? { customRuleSet?.subscriptionURL }
    
    private var isReadOnly: Bool {
        switch target {
        case .custom: return customRuleSet?.subscriptionURL != nil
        case .module: return owningModule?.isSubscribed ?? true
        }
    }

    /// A subscribed module's set names are the keys that keep its ids stable
    /// across refreshes, so they stay as the file names them.
    private var canRename: Bool {
        switch target {
        case .custom: return true
        case .module: return !isReadOnly
        }
    }

    private var assignment: String? {
        switch target {
        case .custom(let id):
            return ruleSetStore.ruleSets.first { $0.id == id.uuidString }?.assignedConfigurationId
        case .module(_, let ruleSetId):
            return moduleStore.routingAssignment(for: ruleSetId)
        }
    }

    var body: some View {
        List {
            if name != nil {
                Section {
                    assignmentMenu
                }
            }

            if let subscriptionURL {
                subscriptionSection(url: subscriptionURL)
            }

            if !rules.isEmpty {
                Section("Rules") {
                    ForEach(rules) { rule in
                        ruleRow(rule)
                    }
                    .onDelete(perform: isReadOnly ? nil : { offsets in
                        rules.remove(atOffsets: offsets)
                        if isEditing != true {
                            save()
                        }
                    })
                    .onMove(perform: isReadOnly ? nil : { source, destination in
                        rules.move(fromOffsets: source, toOffset: destination)
                        if isEditing != true {
                            save()
                        }
                    })
                }
            }
        }
        .navigationTitle(name ?? String(localized: "Rule Set"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if !isReadOnly {
                ToolbarItem {
                    EditButton()
                }
            }
            if !isReadOnly || canRename {
                if #available(iOS 27.0, *),
                   !ProcessInfo.processInfo.isiOSAppOnMac /* Workaround */ {
                    ToolbarOverflowMenu {
                        menuItems
                    }
                } else {
                    ToolbarItem {
                        Menu("More", systemImage: "ellipsis") {
                            menuItems
                        }
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
                rename(to: name)
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

    @ViewBuilder
    private var menuItems: some View {
        if !isReadOnly {
            Button {
                showAddRuleSheet = true
            } label: {
                Label("Add Rule", systemImage: "plus")
            }
        }
        if canRename {
            Button {
                renameText = name ?? ""
                showRenameAlert = true
            } label: {
                Label("Rename", systemImage: "pencil")
            }
        }
    }

    // MARK: - Persistence

    private func loadInitial() {
        guard let storedRules else { return }
        rules = storedRules
    }

    private func save() {
        guard !isReadOnly, let storedRules, rules != storedRules else { return }
        switch target {
        case .custom(let id):
            operations.routingRuleSets.updateCustomRuleSet(id, rules: rules)
        case .module(let moduleId, let ruleSetId):
            operations.modules.updateRoutingRuleSet(ruleSetId, in: moduleId, rules: rules)
        }
    }

    private func rename(to name: String) {
        switch target {
        case .custom(let id):
            operations.routingRuleSets.updateCustomRuleSet(id, name: name)
        case .module(let moduleId, let ruleSetId):
            operations.modules.updateRoutingRuleSet(ruleSetId, in: moduleId, name: name)
        }
    }

    private func setAssignment(_ configurationId: String?) {
        switch target {
        case .custom(let id):
            guard let ruleSet = ruleSetStore.ruleSets.first(where: { $0.id == id.uuidString }) else { return }
            operations.routingRuleSets.updateAssignment(ruleSet, configurationId: configurationId)
        case .module(_, let ruleSetId):
            operations.modules.setRoutingRuleSetAssignment(configurationId, for: ruleSetId)
        }
    }

    @ViewBuilder
    private func subscriptionSection(url: URL) -> some View {
        Section("Subscription") {
            URLText(urlString: url.absoluteString)
            Button {
                refresh()
            } label: {
                HStack {
                    Label("Update", systemImage: updateSucceeded ? "checkmark" : "arrow.clockwise")
                        .contentTransition(.symbolEffect(.replace))
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
        guard case .custom(let id) = target else { return }
        isUpdating = true
        Task {
            do {
                try await operations.routingRuleSets.refresh(id)
                loadInitial()
                isUpdating = false
                updateSucceeded = true
                try? await Task.sleep(for: .seconds(2))
                updateSucceeded = false
            } catch {
                isUpdating = false
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

    @ViewBuilder
    private var assignmentMenu: some View {
        HStack {
            Text("Route To")
            Spacer()
            AssignmentMenuButton(selection: Binding(
                get: { assignment },
                set: { newValue in
                    setAssignment(newValue)
                }
            ))
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
