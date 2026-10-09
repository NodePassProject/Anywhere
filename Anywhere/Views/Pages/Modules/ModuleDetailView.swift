//
//  ModuleDetailView.swift
//  Anywhere
//
//  Created by NodePassProject on 10/9/26.
//

import SwiftUI

struct ModuleDetailView: View {
    @Environment(Operations.self) private var operations
    @Environment(ModuleStore.self) private var moduleStore
    @Environment(MITMRuleSetStore.self) private var mitmStore
    
    let moduleId: UUID

    @State private var showRenameAlert = false
    @State private var renameText = ""

    @State private var showAddRoutingAlert = false
    @State private var newRoutingName = ""

    @State private var showAddMITMAlert = false
    @State private var newMITMName = ""

    @State private var isUpdating = false
    @State private var updateSucceeded = false
    @State private var updateError: String?

    private var module: Module? { moduleStore.module(id: moduleId) }
    private var isSubscribed: Bool { module?.isSubscribed ?? false }
    private var canAddRuleSet: Bool { !isSubscribed && (module?.ruleSetCount ?? 0) < Module.maxRuleSetCount }
    private var showsEditButton: Bool { !isSubscribed && (module?.ruleSetCount ?? 0) > 0 }

    var body: some View {
        List {
            if let module {
                Section {
                    Toggle("Enable", isOn: Binding(
                        get: { module.enabled },
                        set: { operations.modules.setEnabled(id: moduleId, enabled: $0) }
                    ))
                }

                if let subscriptionURL = module.subscriptionURL {
                    subscriptionSection(url: subscriptionURL)
                }

                if !module.routingRuleSets.isEmpty {
                    Section("Routing Rule Sets") {
                        ForEach(module.routingRuleSets) { ruleSet in
                            NavigationLink {
                                CustomRuleSetDetailView(target: .module(moduleId: moduleId, ruleSetId: ruleSet.id))
                            } label: {
                                routingRow(for: ruleSet)
                            }
                        }
                        .onDelete(perform: isSubscribed ? nil : { offsets in
                            operations.modules.removeRoutingRuleSets(atOffsets: offsets, in: moduleId)
                        })
                        .onMove(perform: isSubscribed ? nil : { source, destination in
                            operations.modules.moveRoutingRuleSets(fromOffsets: source, toOffset: destination, in: moduleId)
                        })
                    }
                }

                if !module.mitmRuleSets.isEmpty {
                    Section {
                        ForEach(module.mitmRuleSets) { ruleSet in
                            NavigationLink {
                                MITMRuleSetDetailView(target: .module(moduleId: moduleId, ruleSetId: ruleSet.id))
                            } label: {
                                mitmRow(for: ruleSet)
                            }
                        }
                        .onDelete(perform: isSubscribed ? nil : { offsets in
                            operations.modules.removeMITMRuleSets(atOffsets: offsets, in: moduleId)
                        })
                        .onMove(perform: isSubscribed ? nil : { source, destination in
                            operations.modules.moveMITMRuleSets(fromOffsets: source, toOffset: destination, in: moduleId)
                        })
                    } header: {
                        Text("MITM Rule Sets")
                    } footer: {
                        if !mitmStore.enabled {
                            Text("MITM rule sets won't take effect until MITM is enabled.")
                        }
                    }
                }
            }
        }
        .navigationTitle(module?.name ?? String(localized: "Module"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if showsEditButton {
                ToolbarItem {
                    EditButton()
                }
            }
            if #available(iOS 27.0, *) {
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
        .alert("Rename Module", isPresented: $showRenameAlert) {
            TextField("Name", text: $renameText)
            Button("Rename") {
                let name = renameText.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty else { return }
                operations.modules.rename(id: moduleId, name: name)
            }
            Button("Cancel", role: .cancel) {}
        }
        .alert("Add Routing Rule Set", isPresented: $showAddRoutingAlert) {
            TextField("Name", text: $newRoutingName)
            Button("Add") {
                let name = newRoutingName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty else { return }
                operations.modules.addRoutingRuleSet(name: name, to: moduleId)
                newRoutingName = ""
            }
            Button("Cancel", role: .cancel) {
                newRoutingName = ""
            }
        }
        .alert("Add MITM Rule Set", isPresented: $showAddMITMAlert) {
            TextField("Name", text: $newMITMName)
            Button("Add") {
                let name = newMITMName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty else { return }
                operations.modules.addMITMRuleSet(name: name, to: moduleId)
                newMITMName = ""
            }
            Button("Cancel", role: .cancel) {
                newMITMName = ""
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
    }

    @ViewBuilder
    private var menuItems: some View {
        if canAddRuleSet {
            Button {
                newRoutingName = ""
                showAddRoutingAlert = true
            } label: {
                Label("Add Routing Rule Set", systemImage: "plus")
            }
            Button {
                newMITMName = ""
                showAddMITMAlert = true
            } label: {
                Label("Add MITM Rule Set", systemImage: "plus")
            }
        }
        Button {
            renameText = module?.name ?? ""
            showRenameAlert = true
        } label: {
            Label("Rename", systemImage: "pencil")
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

    @ViewBuilder
    private func routingRow(for ruleSet: ModuleRoutingRuleSet) -> some View {
        HStack {
            VStack(alignment: .leading) {
                Text(ruleSet.name)
                    .foregroundStyle(.primary)
                Text("\(ruleSet.rules.count) rule(s)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            AssignmentLabel(assignedConfigurationId: moduleStore.routingAssignment(for: ruleSet.id))
        }
    }

    @ViewBuilder
    private func mitmRow(for ruleSet: ModuleMITMRuleSet) -> some View {
        HStack {
            VStack(alignment: .leading) {
                Text(ruleSet.name)
                    .foregroundStyle(.primary)
                Text(summary(for: ruleSet))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .truncationMode(.middle)
                    .lineLimit(1)
            }
            Spacer()
            statusDot(enabled: ruleSet.enabled)
        }
    }

    @ViewBuilder
    private func statusDot(enabled: Bool) -> some View {
        if enabled {
            Image(systemName: "circle.fill")
                .foregroundStyle(.green)
                .font(.caption)
                .accessibilityLabel("Enabled")
        } else {
            Image(systemName: "circle.fill")
                .foregroundStyle(.red)
                .font(.caption)
                .accessibilityLabel("Disabled")
        }
    }

    private func summary(for ruleSet: ModuleMITMRuleSet) -> String {
        var parts = [String(localized: "\(ruleSet.rules.count) rule(s)")]
        if !ruleSet.parameters.isEmpty {
            parts.append(String(localized: "\(ruleSet.parameters.count) parameter(s)"))
        }
        return parts.joined(separator: " · ")
    }

    private func refresh() {
        isUpdating = true
        Task {
            do {
                try await operations.modules.refresh(id: moduleId)
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
}
