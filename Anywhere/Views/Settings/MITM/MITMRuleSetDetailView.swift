//
//  MITMRuleSetDetailView.swift
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

struct MITMRuleSetDetailView: View {
    @Environment(\.editMode) private var editMode
    
    @StateObject private var store = MITMRuleSetStore.shared

    let ruleSet: MITMRuleSet?

    @State private var name: String = ""
    @State private var suffixDrafts: [MITMDomainSuffixDraft] = []
    @State private var redirectEnabled: Bool = false
    @State private var redirectHost: String = ""
    @State private var redirectPort: String = ""


    @State private var rules: [MITMRule] = []

    @State private var showAddSheet: Bool = false
    @State private var editingRule: MITMRule?

    @State private var validationError: String?
    
    private var isEditing: Bool? { editMode?.wrappedValue.isEditing }

    var body: some View {
        Form {
            Section {
                if isEditing == true {
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
                } else {
                    LabeledContent {
                        if redirectHost == "" {
                            Text("Disabled")
                        } else {
                            if redirectPort == "" {
                                Text(redirectHost)
                            } else {
                                Text("\(redirectHost):\(redirectPort)")
                            }
                        }
                    } label: {
                        TextWithColorfulIcon(title: "Redirect", comment: nil, systemName: "arrow.trianglehead.turn.up.right.circle", foregroundColor: .white, backgroundColor: .blue)
                    }
                }
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
                if isEditing == true {
                    Button {
                        withAnimation {
                            suffixDrafts.append(MITMDomainSuffixDraft(value: ""))
                        }
                    } label: {
                        Label("Add", systemImage: "plus")
                    }
                }
            } header: {
                Text("Domain Suffixes")
            }

            Section("Rules") {
                ForEach(rules) { rule in
                    VStack(alignment: .leading) {
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
                if isEditing == true {
                    Button {
                        showAddSheet = true
                    } label: {
                        Label("Add", systemImage: "plus")
                    }
                }
            }
        }
        .navigationTitle(ruleSet?.name ?? String(localized: "Rule Set"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem {
                EditButton()
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

        var target: MITMRewriteTarget?
        if redirectEnabled {
            let host = redirectHost.trimmingCharacters(in: .whitespacesAndNewlines)
            var port: UInt16?
            let portTrimmed = redirectPort.trimmingCharacters(in: .whitespacesAndNewlines)
            if !portTrimmed.isEmpty {
                port = UInt16(portTrimmed)
            } else {
                port = nil
            }
            if !host.isEmpty {
                target = MITMRewriteTarget(host: host, port: port)
            }
        }

        let result = MITMRuleSet(
            id: ruleSet?.id ?? UUID(),
            name: name.trimmingCharacters(in: .whitespacesAndNewlines),
            domainSuffixes: suffixes,
            rewriteTarget: target,
            rules: rules
        )
        store.updateRuleSet(result)
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
        return "\(rule.phase.description) \(rule.operation.description)"
    }

    static func subtitle(for rule: MITMRule) -> String {
        switch rule.operation {
        case .urlReplace(let pattern, _):
            return pattern
        case .headerAdd(let name, _):
            return name
        case .headerDelete(let name):
            return name
        case .headerReplace(let pattern, _, _):
            return pattern
        case .bodyReplace(let pattern, _):
            return pattern
        }
    }
}
