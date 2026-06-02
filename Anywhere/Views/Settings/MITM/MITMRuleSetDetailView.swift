//
//  MITMRuleSetDetailView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/4/26.
//

import SwiftUI

/// A single draft row in the suffix editor. The id is per-row so SwiftUI
/// keeps focus and deletion stable while the user types — using the
/// string itself as the id would collapse rows whenever two are momentarily
/// equal (e.g. both empty).
private struct MITMDomainSuffixDraft: Identifiable, Equatable {
    let id = UUID()
    var value: String
}

struct MITMRuleSetDetailView: View {
    @Environment(\.editMode) private var editMode

    @StateObject private var store = MITMRuleSetStore.shared

    let ruleSet: MITMRuleSet?

    @State private var name: String = ""
    @State private var enabled: Bool = true
    @State private var suffixDrafts: [MITMDomainSuffixDraft] = []

    @State private var rules: [MITMRule] = []

    @State private var showAddSheet: Bool = false
    @State private var editingRule: MITMRule?

    @State private var validationError: String?

    @State private var isUpdating = false
    @State private var updateError: String?

    private var isEditing: Bool? { editMode?.wrappedValue.isEditing }

    /// The live rule set from the store. The ``ruleSet`` passed in is a
    /// snapshot that goes stale after a subscription refresh, so reads that
    /// must reflect the latest content — the subscription URL, and whether
    /// the set is read-only — go through the store by id.
    private var currentRuleSet: MITMRuleSet? {
        guard let id = ruleSet?.id else { return ruleSet }
        return store.ruleSet(id: id) ?? ruleSet
    }

    private var subscriptionURL: URL? { currentRuleSet?.subscriptionURL }
    private var isSubscribed: Bool { subscriptionURL != nil }

    var body: some View {
        Form {
            Section {
                Toggle("Enable", isOn: Binding(
                    get: { enabled },
                    set: { newValue in
                        enabled = newValue
                        if let id = ruleSet?.id {
                            store.setRuleSet(id, enabled: newValue)
                        }
                    }
                ))
            }

            if let subscriptionURL {
                subscriptionSection(url: subscriptionURL)
            }

            if isEditing == true || !suffixDrafts.isEmpty {
                Section("Domain Suffixes") {
                    ForEach($suffixDrafts) { $draft in
                        TextField(String("anywhere.com"), text: $draft.value)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .disabled(isEditing != true)
                    }
                    .onDelete(perform: isSubscribed ? nil : { offsets in
                        suffixDrafts.remove(atOffsets: offsets)
                        if isEditing != true {
                            save()
                        }
                    })
                    .onMove(perform: isSubscribed ? nil : { source, destination in
                        suffixDrafts.move(fromOffsets: source, toOffset: destination)
                        if isEditing != true {
                            save()
                        }
                    })
                    if isEditing == true {
                        Button {
                            withAnimation {
                                suffixDrafts.append(MITMDomainSuffixDraft(value: ""))
                            }
                        } label: {
                            Label("Add", systemImage: "plus")
                        }
                    }
                }
            }

            if isEditing == true || !rules.isEmpty {
                Section("Rules") {
                    ForEach(rules) { rule in
                        VStack(alignment: .leading) {
                            Text(MITMRuleSummary.title(for: rule))
                            Text(MITMRuleSummary.subtitle(for: rule))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .truncationMode(.middle)
                                .lineLimit(1)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            // Subscribed sets are remote-managed and read-only.
                            guard !isSubscribed else { return }
                            // Scripts and native JSON-body edits are
                            // import-only; no in-app editor for them.
                            // body-replace is editable, so it falls through.
                            switch rule.operation {
                            case .script, .streamScript, .bodyJSON: return
                            default: break
                            }
                            editingRule = rule
                        }
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
                    if isEditing == true {
                        Button {
                            showAddSheet = true
                        } label: {
                            Label("Add", systemImage: "plus")
                        }
                    }
                }
            }
        }
        .navigationTitle(ruleSet?.name ?? String(localized: "Rule Set"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if !isSubscribed {
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
            if newValue == false {
                save()
            }
        }
    }

    private func save() {
        suffixDrafts = suffixDrafts
            .filter { !$0.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        let suffixes = suffixDrafts
            .map { $0.value.trimmingCharacters(in: .whitespacesAndNewlines) }

        let result = MITMRuleSet(
            id: ruleSet?.id ?? UUID(),
            name: name.trimmingCharacters(in: .whitespacesAndNewlines),
            enabled: enabled,
            domainSuffixes: suffixes,
            rules: rules,
            subscriptionURL: currentRuleSet?.subscriptionURL
        )
        store.updateRuleSet(result)
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
        guard let id = ruleSet?.id else { return }
        isUpdating = true
        Task {
            defer { isUpdating = false }
            do {
                let updated = try await store.refreshRuleSet(id: id)
                loadState(from: updated)
            } catch {
                updateError = error.localizedDescription
            }
        }
    }

    private func loadInitial() {
        guard let ruleSet = currentRuleSet else { return }
        loadState(from: ruleSet)
    }

    /// Populates the editor's local @State from a rule set. Used on appear
    /// and again after a subscription refresh replaces the content.
    private func loadState(from ruleSet: MITMRuleSet) {
        name = ruleSet.name
        enabled = ruleSet.enabled
        suffixDrafts = ruleSet.domainSuffixes.map { MITMDomainSuffixDraft(value: $0) }
        rules = ruleSet.rules
    }
}

/// Centralized label generation so the rule list and editor agree.
enum MITMRuleSummary {
    static func title(for rule: MITMRule) -> String {
        return "\(rule.phase.description) \(rule.operation.description)"
    }

    static func subtitle(for rule: MITMRule) -> String {
        switch rule.operation {
        case .rewrite(let action):
            switch action {
            case .transparent(let url), .redirect302(let url):
                return url
            case .reject200Text:
                return String(localized: "Reject Text")
            case .reject200Gif:
                return String(localized: "Reject GIF")
            case .reject200Data:
                return String(localized: "Reject Data")
            }
        case .headerAdd(let name, _):
            return name
        case .headerDelete(let name):
            return name
        case .headerReplace(let name, _):
            return name
        case .script(let scriptBase64),
             .streamScript(let scriptBase64):
            let bytes = Data(base64Encoded: scriptBase64)?.count ?? 0
            return String(localized: "\(bytes) byte(s)")
        case .bodyReplace(let search, _):
            return search
        case .bodyJSON(let operation):
            return operation.description
        }
    }
}
