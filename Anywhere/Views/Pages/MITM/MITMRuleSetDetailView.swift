//
//  MITMRuleSetDetailView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/4/26.
//

import SwiftUI

private struct MITMDomainSuffixDraft: Identifiable, Equatable {
    let id = UUID()
    var value: String
}

enum MITMRuleSetTarget: Hashable {
    case standalone(UUID)
    case module(moduleId: UUID, ruleSetId: UUID)
}

struct MITMRuleSetDetailView: View {
    @Environment(\.editMode) private var editMode
    
    @Environment(Operations.self) private var operations
    @Environment(MITMRuleSetStore.self) private var mitmRuleSetStore
    @Environment(ModuleStore.self) private var moduleStore
    
    let target: MITMRuleSetTarget

    @State private var enabled: Bool = true
    @State private var suffixDrafts: [MITMDomainSuffixDraft] = []

    @State private var rules: [MITMRule] = []
    
    @State private var parameters: [MITMParameter] = []
    @State private var parameterValues: [String: String] = [:]

    @State private var showAddSheet: Bool = false
    @State private var editingRule: MITMRule?

    @State private var validationError: String?

    @State private var isUpdating = false
    @State private var updateSucceeded = false
    @State private var updateError: String?

    init(ruleSet: MITMRuleSet) {
        target = .standalone(ruleSet.id)
    }

    init(target: MITMRuleSetTarget) {
        self.target = target
    }

    private var isEditing: Bool? { editMode?.wrappedValue.isEditing }
    
    private var currentRuleSet: MITMRuleSet? {
        switch target {
        case .standalone(let id):
            return mitmRuleSetStore.ruleSet(id: id)
        case .module(let moduleId, let ruleSetId):
            return moduleStore.mitmRuleSet(ruleSetId, in: moduleId)?.asMITMRuleSet()
        }
    }
    
    private var subscriptionURL: URL? {
        guard case .standalone = target else { return nil }
        return currentRuleSet?.subscriptionURL
    }
    
    private var isReadOnly: Bool {
        guard case .module(let moduleId, _) = target else { return false }
        return moduleStore.module(id: moduleId)?.isSubscribed ?? true
    }

    var body: some View {
        Form {
            Section {
                Toggle("Enable", isOn: Binding(
                    get: { enabled },
                    set: { newValue in
                        enabled = newValue
                        setEnabled(newValue)
                    }
                ))
            }

            if let subscriptionURL {
                subscriptionSection(url: subscriptionURL)
            }

            if !parameters.isEmpty {
                parametersSection
            }

            if isEditing == true || !suffixDrafts.isEmpty {
                domainSuffixesSection
            }

            if isEditing == true || !rules.isEmpty {
                rulesSection
            }
        }
        .navigationTitle(currentRuleSet?.name ?? String(localized: "Rule Set"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if !isReadOnly {
                ToolbarItem {
                    EditButton()
                }
            }
        }
        .sheet(isPresented: $showAddSheet) {
            NavigationStack {
                MITMRuleEditorView(rule: nil) { rule in
                    if let rule { rules.append(rule) }
                }
            }
        }
        .sheet(item: $editingRule) { rule in
            NavigationStack {
                MITMRuleEditorView(rule: rule) { updated in
                    guard let updated else { return }
                    if let index = rules.firstIndex(where: { $0.id == rule.id }) {
                        rules[index] = updated
                    }
                }
            }
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
            if newValue == true {
                ensureTrailingBlankDraft()
            } else if newValue == false {
                save()
            }
        }
        .onChange(of: suffixDrafts) {
            if isEditing == true {
                ensureTrailingBlankDraft()
            }
        }
    }
    
    private func ensureTrailingBlankDraft() {
        if suffixDrafts.last?.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != true {
            suffixDrafts.append(MITMDomainSuffixDraft(value: ""))
        }
    }

    // MARK: - Persistence

    private func save() {
        guard !isReadOnly else { return }
        suffixDrafts = suffixDrafts
            .filter { !$0.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        let suffixes = suffixDrafts
            .map { $0.value.trimmingCharacters(in: .whitespacesAndNewlines) }
        switch target {
        case .standalone(let id):
            operations.mitmRuleSets.updateRuleSet(id, domainSuffixes: suffixes, rules: rules)
        case .module(let moduleId, let ruleSetId):
            operations.modules.updateMITMRuleSet(ruleSetId, in: moduleId, domainSuffixes: suffixes, rules: rules)
        }
    }

    private func setEnabled(_ value: Bool) {
        switch target {
        case .standalone(let id):
            operations.mitmRuleSets.setRuleSet(id, enabled: value)
        case .module(let moduleId, let ruleSetId):
            operations.modules.setMITMRuleSet(ruleSetId, in: moduleId, enabled: value)
        }
    }

    private func setParameterValue(name: String, value: String) {
        guard case .standalone(let id) = target else { return }
        operations.mitmRuleSets.setParameterValue(id, name: name, value: value)
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

    // MARK: - Parameters
    
    @ViewBuilder
    private var parametersSection: some View {
        ForEach(parameters) { parameter in
            Section {
                parameterRow(parameter)
            } footer: {
                if let description = parameter.description, !description.isEmpty {
                    Text(description)
                }
            }
        }
    }

    @ViewBuilder
    private func parameterRow(_ parameter: MITMParameter) -> some View {
        let parameterLabel = parameter.label ?? parameter.name
        if isEditing != true {
            HStack {
                Text(parameterLabel)
                Spacer()
                Text(parameterValues[parameter.name] ?? parameter.defaultValue)
                    .foregroundStyle(.secondary)
            }
        } else {
            switch parameter.type {
            case .input:
                HStack {
                    Text(parameterLabel)
                    Spacer()
                    TextField(parameter.defaultValue, text: parameterBinding(parameter))
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.trailing)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }
            case .picker:
                Picker(parameterLabel, selection: parameterBinding(parameter)) {
                    ForEach(parameter.options, id: \.self) { option in
                        Text(option).tag(option)
                    }
                }
            }
        }
    }
    
    private func parameterBinding(_ parameter: MITMParameter) -> Binding<String> {
        Binding(
            get: { parameterValues[parameter.name] ?? parameter.defaultValue },
            set: { newValue in
                parameterValues[parameter.name] = newValue
                setParameterValue(name: parameter.name, value: newValue)
            }
        )
    }
    
    // MARK: - Domain Suffixes
    
    @ViewBuilder
    private var domainSuffixesSection: some View {
        Section("Domain Suffixes") {
            ForEach($suffixDrafts) { $draft in
                TextField(String("anywhere.com"), text: $draft.value)
                    .keyboardType(.URL)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .disabled(isEditing != true)
            }
            .onDelete(perform: isReadOnly ? nil : { offsets in
                suffixDrafts.remove(atOffsets: offsets)
                if isEditing != true {
                    save()
                }
            })
            .onMove(perform: isReadOnly ? nil : { source, destination in
                suffixDrafts.move(fromOffsets: source, toOffset: destination)
                if isEditing != true {
                    save()
                }
            })
        }
    }
    
    // MARK: - Rules
    
    @ViewBuilder
    private var rulesSection: some View {
        Section("Rules") {
            ForEach(rules) { rule in
                VStack(alignment: .leading) {
                    Text(rule.summaryTitle)
                    Text(rule.summarySubtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .truncationMode(.middle)
                        .lineLimit(1)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
                .onTapGesture {
                    guard !isReadOnly else { return }
                    // Scripts and native JSON-body edits are import-only.
                    switch rule.operation {
                    case .script, .streamScript, .bodyJSON: return
                    default: break
                    }
                    editingRule = rule
                }
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
            if isEditing == true {
                Button {
                    showAddSheet = true
                } label: {
                    Label("Add", systemImage: "plus")
                }
            }
        }
    }

    private func refresh() {
        guard case .standalone(let id) = target else { return }
        isUpdating = true
        Task {
            do {
                let updated = try await operations.mitmRuleSets.refresh(id: id)
                loadState(from: updated)
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

    private func loadInitial() {
        guard let ruleSet = currentRuleSet else { return }
        loadState(from: ruleSet)
    }
    
    private func loadState(from ruleSet: MITMRuleSet) {
        enabled = ruleSet.enabled
        suffixDrafts = ruleSet.domainSuffixes.map { MITMDomainSuffixDraft(value: $0) }
        rules = ruleSet.rules
        guard case .standalone = target else { return }
        parameters = ruleSet.parameters
        parameterValues = Dictionary(
            uniqueKeysWithValues: ruleSet.parameters.map {
                ($0.name, $0.effectiveValue(ruleSet.parameterValues[$0.name]))
            }
        )
    }
}
