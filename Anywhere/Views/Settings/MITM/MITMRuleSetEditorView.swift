//
//  MITMRuleSetEditorView.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/4/26.
//

import SwiftUI

struct MITMRuleSetEditorView: View {
    @Environment(\.dismiss) private var dismiss

    let ruleSet: MITMRuleSet?
    let onCommit: (MITMRuleSet?) -> Void

    @State private var domainSuffix: String = ""
    @State private var redirectEnabled: Bool = false
    @State private var redirectHost: String = ""
    @State private var redirectPort: String = ""
    @State private var rules: [MITMRule] = []

    @State private var validationError: String?
    @State private var addingRule: Bool = false
    @State private var editingRule: MITMRule?

    var body: some View {
        Form {
            Section("Domain Suffix") {
                TextField("example.com", text: $domainSuffix)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
            }

            Section {
                Toggle("Redirect Upstream", isOn: $redirectEnabled)
                if redirectEnabled {
                    TextField("Host (e.g. staging.example.com)", text: $redirectHost)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    TextField("Port (optional)", text: $redirectPort)
                        .keyboardType(.numberPad)
                }
            } footer: {
                Text("When set, every connection matched by this rule set is redirected to the target host. The Host / :authority header is auto-rewritten to match.")
            }

            Section("Rules") {
                if rules.isEmpty {
                    Text("No rules")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(rules) { rule in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(MITMRuleSummary.title(for: rule))
                                .foregroundStyle(.primary)
                            Text(MITMRuleSummary.subtitle(for: rule))
                                .font(.caption)
                                .foregroundStyle(.secondary)
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
                }
                Button {
                    addingRule = true
                } label: {
                    Label("Add Rule", systemImage: "plus")
                }
            }

            if let validationError {
                Section {
                    Text(validationError)
                        .foregroundStyle(.red)
                }
            }
        }
        .navigationTitle(ruleSet == nil ? "Add Rule Set" : "Edit Rule Set")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") { save() }
            }
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") {
                    onCommit(nil)
                    dismiss()
                }
            }
            ToolbarItem(placement: .automatic) {
                if !rules.isEmpty {
                    EditButton()
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
        let suffix = domainSuffix.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !suffix.isEmpty else {
            validationError = String(localized: "Domain suffix is required.")
            return
        }

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
            domainSuffix: suffix,
            rewriteTarget: target,
            rules: rules
        )
        onCommit(result)
        dismiss()
    }

    private func loadInitial() {
        guard let ruleSet else { return }
        domainSuffix = ruleSet.domainSuffix
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
