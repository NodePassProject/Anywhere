//
//  MITMRuleSetEditorView.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/4/26.
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

struct MITMRuleSetEditorView: View {
    @Environment(\.dismiss) private var dismiss

    let ruleSet: MITMRuleSet?
    let onCommit: (MITMRuleSet?) -> Void

    @State private var name: String = ""
    @State private var suffixDrafts: [MITMDomainSuffixDraft] = []
    @State private var redirectEnabled: Bool = false
    @State private var redirectHost: String = ""
    @State private var redirectPort: String = ""


    @State private var rules: [MITMRule] = []

    @State private var addingRule: Bool = false
    @State private var editMode: EditMode = .inactive
    @State private var editingRule: MITMRule?

    @State private var validationError: String?

    var body: some View {
        Form {
            Section("Name") {
                TextField("Name", text: $name)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
            }

            Section {
                ForEach($suffixDrafts) { $draft in
                    TextField(String("anywhere.com"), text: $draft.value)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }
                .onDelete { offsets in
                    suffixDrafts.remove(atOffsets: offsets)
                }
                .onMove { source, destination in
                    suffixDrafts.move(fromOffsets: source, toOffset: destination)
                }
                Button {
                    suffixDrafts.append(MITMDomainSuffixDraft(value: ""))
                } label: {
                    Label("Add", systemImage: "plus")
                }
            } header: {
                Text("Domain Suffixes")
            }

            Section {
                Toggle(isOn: $redirectEnabled) {
                    TextWithColorfulIcon(title: "Redirect", comment: nil, systemName: "arrow.trianglehead.turn.up.right.circle", foregroundColor: .white, backgroundColor: .blue)
                }
                if redirectEnabled {
                    LabeledContent {
                        TextField(String("everywhere.com"), text: $redirectHost)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Host", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField(String("443"), text: $redirectPort)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Port", comment: nil, systemName: "123.rectangle", foregroundColor: .white, backgroundColor: .cyan)
                    }
                }
            }

            Section {
                ForEach(rules) { rule in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(MITMRuleSummary.title(for: rule))
                            .foregroundStyle(.primary)
                        Text(MITMRuleSummary.subtitle(for: rule))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .truncationMode(.middle)
                            .lineLimit(1)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
                    .onTapGesture {
                        editingRule = rule
                    }
                }
                .onDelete { offsets in
                    rules.remove(atOffsets: offsets)
                }
                .onMove { source, destination in
                    rules.move(fromOffsets: source, toOffset: destination)
                }
                Button {
                    addingRule = true
                } label: {
                    Label("Add", systemImage: "plus")
                }
            } header: {
                HStack {
                    Text("Rules")
                    Spacer()
                    Button(editMode == .active ? "Done" : "Edit") {
                        if editMode == .active {
                            editMode = .inactive
                        } else {
                            editMode = .active
                        }
                    }
                }
            }

            if let validationError {
                Section {
                    Text(validationError)
                        .foregroundStyle(.red)
                }
            }
        }
        .environment(\.editMode, $editMode)
        .navigationTitle(ruleSet?.name ?? String(localized: "Rule Set"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                ConfirmButton("Done", action: save)
                    .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            ToolbarItem(placement: .cancellationAction) {
                CancelButton("Cancel") {
                    onCommit(nil)
                    dismiss()
                }
            }
        }
        .sheet(isPresented: $addingRule) {
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
        .onAppear { loadInitial() }
    }

    private func save() {
        // Empty suffixes are dropped silently — a set with zero suffixes is
        // legal (it just won't match anything until the user adds some), so
        // we don't refuse to save here.
        let suffixes = suffixDrafts
            .map { $0.value.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        var target: MITMRewriteTarget?
        if redirectEnabled {
            let host = redirectHost.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty else {
                validationError = String(localized: "Redirect host is required when redirect is enabled.")
                return
            }
            var port: UInt16?
            let portTrimmed = redirectPort.trimmingCharacters(in: .whitespacesAndNewlines)
            if !portTrimmed.isEmpty {
                guard let parsed = UInt16(portTrimmed) else {
                    validationError = String(localized: "Port must be a number between 1 and 65535.")
                    return
                }
                port = parsed
            }
            target = MITMRewriteTarget(host: host, port: port)
        }

        let result = MITMRuleSet(
            id: ruleSet?.id ?? UUID(),
            name: name.trimmingCharacters(in: .whitespacesAndNewlines),
            domainSuffixes: suffixes,
            rewriteTarget: target,
            rules: rules
        )
        onCommit(result)
        dismiss()
    }

    private func loadInitial() {
        guard let ruleSet else { return }
        name = ruleSet.name
        suffixDrafts = ruleSet.domainSuffixes.map { MITMDomainSuffixDraft(value: $0) }
        rules = ruleSet.rules
        if let target = ruleSet.rewriteTarget {
            redirectEnabled = true
            redirectHost = target.host
            if let port = target.port {
                redirectPort = String(port)
            }
        }
    }
}

/// Centralized label generation so the rule list and editor agree.
enum MITMRuleSummary {
    static func title(for rule: MITMRule) -> String {
        switch rule.operation {
        case .urlReplace:                   return "URL Replace"
        case .headerAdd(let name, _):       return "Header Add: \(name)"
        case .headerDelete(let name):       return "Header Delete: \(name)"
        case .headerReplace:                return "Header Replace"
        case .bodyReplace:                  return "Body Replace"
        }
    }

    static func subtitle(for rule: MITMRule) -> String {
        let phaseLabel: String
        switch rule.phase {
        case .httpRequest:  phaseLabel = String(localized: "Request")
        case .httpResponse: phaseLabel = String(localized: "Response")
        }
        return phaseLabel
    }
}
