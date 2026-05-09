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

/// Local picker state. ``disabled`` means "no rewriteTarget"; the other
/// cases mirror ``MITMRewriteAction`` one-to-one. Kept separate so the
/// ``Disabled`` choice has somewhere to live without leaking nil into
/// the model layer.
private enum MITMRewriteActionChoice: String, Hashable, CaseIterable, Identifiable {
    case disabled
    case transparent
    case redirect302
    case reject200

    var id: String { rawValue }

    var label: String {
        switch self {
        case .disabled:    return String(localized: "Disabled")
        case .transparent: return String(localized: "Transparent Redirect")
        case .redirect302: return String(localized: "302 Redirect")
        case .reject200:   return String(localized: "200 Reject")
        }
    }
}

private extension MITMRejectBody.Kind {
    var label: String {
        switch self {
        case .text: return String(localized: "Text")
        case .gif:  return String(localized: "Tiny GIF")
        case .data: return String(localized: "Data")
        }
    }
}

struct MITMRuleSetDetailView: View {
    @Environment(\.editMode) private var editMode

    @StateObject private var store = MITMRuleSetStore.shared

    let ruleSet: MITMRuleSet?

    @State private var name: String = ""
    @State private var suffixDrafts: [MITMDomainSuffixDraft] = []
    @State private var actionChoice: MITMRewriteActionChoice = .disabled
    @State private var redirectHost: String = ""
    @State private var redirectPort: String = ""
    @State private var rejectBodyKind: MITMRejectBody.Kind = .text
    @State private var rejectBodyContents: String = ""


    @State private var rules: [MITMRule] = []

    @State private var showAddSheet: Bool = false
    @State private var editingRule: MITMRule?

    @State private var validationError: String?

    private var isEditing: Bool? { editMode?.wrappedValue.isEditing }

    var body: some View {
        Form {
            Section {
                if isEditing == true {
                    actionEditor
                } else {
                    LabeledContent {
                        Text(actionChoice.label)
                    } label: {
                        TextWithColorfulIcon(title: "Rewrite", comment: "MITM rewrite action", systemName: "arrow.trianglehead.turn.up.right", foregroundColor: .white, backgroundColor: .purple)
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
                    save()
                }
                .onMove { source, destination in
                    suffixDrafts.move(fromOffsets: source, toOffset: destination)
                    save()
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
                    save()
                }
                .onMove { source, destination in
                    rules.move(fromOffsets: source, toOffset: destination)
                    save()
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

    @ViewBuilder
    private var actionEditor: some View {
        actionPicker
        switch actionChoice {
        case .disabled:
            EmptyView()
        case .transparent, .redirect302:
            authorityFields
        case .reject200:
            rejectFields
        }
    }

    private var actionPicker: some View {
        LabeledContent {
            Picker(String(localized: "Rewrite", comment: "MITM rewrite action"), selection: $actionChoice) {
                ForEach(MITMRewriteActionChoice.allCases) { choice in
                    Text(choice.label).tag(choice)
                }
            }
            .labelsHidden()
        } label: {
            TextWithColorfulIcon(title: "Rewrite", comment: "MITM rewrite action", systemName: "arrow.trianglehead.turn.up.right", foregroundColor: .white, backgroundColor: .purple)
        }
    }

    @ViewBuilder
    private var authorityFields: some View {
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

    @ViewBuilder
    private var rejectFields: some View {
        LabeledContent {
            Picker("Body Type", selection: $rejectBodyKind) {
                Text(MITMRejectBody.Kind.text.label).tag(MITMRejectBody.Kind.text)
                Text(MITMRejectBody.Kind.gif.label).tag(MITMRejectBody.Kind.gif)
                Text(MITMRejectBody.Kind.data.label).tag(MITMRejectBody.Kind.data)
            }
            .labelsHidden()
        } label: {
            TextWithColorfulIcon(title: "Body Type", comment: nil, systemName: "doc.badge.gearshape", foregroundColor: .white, backgroundColor: .purple)
        }
        if rejectBodyKind != .gif {
            LabeledContent {
                TextField(rejectBodyKind.defaultContents, text: $rejectBodyContents)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .multilineTextAlignment(.trailing)
            } label: {
                TextWithColorfulIcon(title: "Content", comment: nil, systemName: "text.alignleft", foregroundColor: .white, backgroundColor: .gray)
            }
        }
    }

    private func save() {
        suffixDrafts = suffixDrafts
            .filter { !$0.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        let suffixes = suffixDrafts
            .map { $0.value.trimmingCharacters(in: .whitespacesAndNewlines) }

        let target = buildRewriteTarget()

        let result = MITMRuleSet(
            id: ruleSet?.id ?? UUID(),
            name: name.trimmingCharacters(in: .whitespacesAndNewlines),
            domainSuffixes: suffixes,
            rewriteTarget: target,
            rules: rules
        )
        store.updateRuleSet(result)
    }

    /// Translates the editor's local fields into a ``MITMRewriteTarget``,
    /// or nil when the user picked Disabled / left the required fields
    /// empty.
    private func buildRewriteTarget() -> MITMRewriteTarget? {
        switch actionChoice {
        case .disabled:
            return nil
        case .transparent, .redirect302:
            let host = redirectHost.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty else { return nil }
            let portTrimmed = redirectPort.trimmingCharacters(in: .whitespacesAndNewlines)
            let port: UInt16? = portTrimmed.isEmpty ? nil : UInt16(portTrimmed)
            let action: MITMRewriteAction = actionChoice == .redirect302 ? .redirect302 : .transparent
            return MITMRewriteTarget(action: action, host: host, port: port)
        case .reject200:
            let body = MITMRejectBody(
                kind: rejectBodyKind,
                contents: rejectBodyKind == .gif ? "" : rejectBodyContents,
                contentType: nil
            )
            return MITMRewriteTarget(action: .reject200, rejectBody: body)
        }
    }

    private func loadInitial() {
        guard let ruleSet else { return }
        name = ruleSet.name
        suffixDrafts = ruleSet.domainSuffixes.map { MITMDomainSuffixDraft(value: $0) }
        rules = ruleSet.rules
        guard let target = ruleSet.rewriteTarget else {
            actionChoice = .disabled
            return
        }
        switch target.action {
        case .transparent:
            actionChoice = .transparent
            redirectHost = target.host
            redirectPort = target.port.map(String.init) ?? ""
        case .redirect302:
            actionChoice = .redirect302
            redirectHost = target.host
            redirectPort = target.port.map(String.init) ?? ""
        case .reject200:
            actionChoice = .reject200
            if let body = target.rejectBody {
                rejectBodyKind = body.kind
                rejectBodyContents = body.contents
            }
        }
    }

    private func defaultContentTypePlaceholder(for kind: MITMRejectBody.Kind) -> String {
        switch kind {
        case .text: return "text/plain; charset=utf-8"
        case .gif:  return "image/gif"
        case .data: return "application/octet-stream"
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
