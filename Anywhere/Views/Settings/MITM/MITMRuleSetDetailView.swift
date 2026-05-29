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
    @State private var enabled: Bool = true
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

            Section {
                if isEditing == true {
                    actionEditor
                } else {
                    LabeledContent {
                        Text(actionChoice.label)
                    } label: {
                        TextWithColorfulIcon(title: "Rewrite", comment: "MITM rewrite action", systemName: "arrow.triangle.turn.up.right.circle", foregroundColor: .white, backgroundColor: .purple)
                    }
                }
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
                            // Script editor not implemented
                            switch rule.operation {
                            case .script, .streamScript: return
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
            enabled: enabled,
            domainSuffixes: suffixes,
            rewriteTarget: target,
            rules: rules,
            subscriptionURL: currentRuleSet?.subscriptionURL
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

    @ViewBuilder
    private func subscriptionSection(url: URL) -> some View {
        Section("Subscription") {
            Text(url.absoluteString)
                .font(.system(size: 14).monospaced())
                .foregroundStyle(.secondary)
                .minimumScaleFactor(0.5)
                .lineLimit(1)
                .truncationMode(.middle)
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
    /// and again after a subscription refresh replaces the content, so it
    /// resets the action-specific fields rather than assuming defaults.
    private func loadState(from ruleSet: MITMRuleSet) {
        name = ruleSet.name
        enabled = ruleSet.enabled
        suffixDrafts = ruleSet.domainSuffixes.map { MITMDomainSuffixDraft(value: $0) }
        rules = ruleSet.rules
        redirectHost = ""
        redirectPort = ""
        rejectBodyKind = .text
        rejectBodyContents = ""
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
        case .urlReplace:
            return rule.pattern
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
        }
    }
}
