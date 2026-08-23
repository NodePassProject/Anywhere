//
//  RoutingView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI
import UniformTypeIdentifiers
import WidgetKit

struct RoutingView: View {
    @Environment(\.editMode) private var editMode
    @Environment(AppSettings.self) private var appSettings
    @Environment(Operations.self) private var operations
    @Environment(RoutingRuleSetStore.self) private var routingRuleSetStore

    @State private var showAddSheet = false
    @State private var newRuleSetName = ""

    @State private var showFileImporter = false
    @State private var importError: String?

    @State private var showSubscribeAlert = false
    @State private var subscribeURL = ""
    @State private var subscribeError: String?

    @State private var showResetConfirmAlert = false
    
    private var isEditing: Bool? { editMode?.wrappedValue.isEditing }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Toggle(isOn: Binding(
                        get: { appSettings.isGlobalMode },
                        set: {
                            appSettings.isGlobalMode = $0
                            ControlCenter.shared.reloadControls(ofKind: "com.argsment.Anywhere.Widget.VPNToggle")
                        }
                    )) {
                        TextWithColorfulIcon(title: "Global Mode", systemName: "arrow.merge", foregroundStyle: .white, backgroundStyle: .orange.gradient)
                    }
                    Picker(selection: Binding(
                        get: { routingRuleSetStore.bypassCountryCode },
                        set: { operations.routingRuleSets.setBypassCountryCode($0) }
                    )) {
                        Text("Disable").tag("")
                        ForEach(CountryBypassCatalog.shared.supportedCountryCodes, id: \.self) { code in
                            Text(countryLabel(for: code)).tag(code)
                        }
                    } label: {
                        TextWithColorfulIcon(title: "Country Bypass", systemName: "globe.americas.fill", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                    }
                    .disabled(appSettings.isGlobalMode)
                }
                Section {
                    ForEach(routingRuleSetStore.builtInServiceRuleSets) { ruleSet in
                        if !ruleSet.isCustom {
                            builtInRuleSetRow(for: ruleSet)
                        }
                    }
                }
                .disabled(appSettings.isGlobalMode)
                if !routingRuleSetStore.customRuleSets.isEmpty {
                    Section {
                        ForEach(routingRuleSetStore.customRuleSets) { customRuleSet in
                            customRuleSetLink(for: customRuleSet)
                        }
                        .onDelete { offsets in
                            operations.routingRuleSets.removeCustomRuleSets(atOffsets: offsets)
                        }
                        .onMove { source, destination in
                            operations.routingRuleSets.moveCustomRuleSets(fromOffsets: source, toOffset: destination)
                        }
                    }
                    .disabled(appSettings.isGlobalMode)
                }
            }
            .listRowSpacing(8)
            .navigationTitle("Routing")
            .toolbar {
                if isEditing == true || !routingRuleSetStore.customRuleSets.isEmpty {
                    ToolbarItem {
                        EditButton()
                    }
                }
                ToolbarItem {
                    Menu("More", systemImage: "ellipsis") {
                        Button {
                            showAddSheet = true
                        } label: {
                            Label("Add Rule Set", systemImage: "plus")
                        }
                        Button {
                            importError = nil
                            showFileImporter = true
                        } label: {
                            Label("Import Rule Set", systemImage: "square.and.arrow.down")
                        }
                        Button {
                            subscribeURL = ""
                            showSubscribeAlert = true
                        } label: {
                            Label("Subscribe Rule Set", systemImage: "link")
                        }
                        Button(role: .destructive) {
                            showResetConfirmAlert = true
                        } label: {
                            Label("Reset", systemImage: "arrow.clockwise")
                        }
                    }
                }
            }
            .fileImporter(
                isPresented: $showFileImporter,
                allowedContentTypes: [UTType(filenameExtension: "arrs") ?? .data]
            ) { result in
                handleFileImport(result)
            }
            .alert("Add Rule Set", isPresented: $showAddSheet) {
                TextField("Name", text: $newRuleSetName)
                Button("Add") {
                    let name = newRuleSetName.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !name.isEmpty else { return }
                    operations.routingRuleSets.addCustomRuleSet(name: name)
                    newRuleSetName = ""
                }
                Button("Cancel", role: .cancel) {
                    newRuleSetName = ""
                }
            }
            .alert("Import Failed", isPresented: Binding(
                get: { importError != nil },
                set: { if !$0 { importError = nil } }
            )) {
                Button("OK") { importError = nil }
            } message: {
                Text(importError ?? "")
            }
            .alert("Subscribe Rule Set", isPresented: $showSubscribeAlert) {
                TextField("Anywhere Routing Rule Set URL", text: $subscribeURL)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                Button("Subscribe") {
                    subscribe(to: subscribeURL)
                }
                Button("Cancel", role: .cancel) {}
            }
            .alert("Subscription Failed", isPresented: Binding(
                get: { subscribeError != nil },
                set: { if !$0 { subscribeError = nil } }
            )) {
                Button("OK") { subscribeError = nil }
            } message: {
                Text(subscribeError ?? "")
            }
            .alert("Reset Assignments", isPresented: $showResetConfirmAlert) {
                Button("Reset", role: .destructive) {
                    operations.routingRuleSets.resetAssignments()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Reset all rule set assignments to Default.")
            }
        }
    }

    private func customRuleSetLink(for customRuleSet: CustomRoutingRuleSet) -> some View {
        NavigationLink {
            CustomRuleSetDetailView(customRuleSetId: customRuleSet.id)
        } label: {
            customRuleSetRow(for: customRuleSet)
        }
    }
    
    @ViewBuilder
    private func builtInRuleSetRow(for ruleSet: RoutingRuleSet) -> some View {
        HStack {
            AppIconView(ruleSet.name)
            Text(ruleSet.name)
            Spacer()
            AssignmentMenuButton(selection: Binding(
                get: { ruleSet.assignedConfigurationId },
                set: { operations.routingRuleSets.updateAssignment(ruleSet, configurationId: $0) }
            ))
        }
    }

    @ViewBuilder
    private func customRuleSetRow(for ruleSet: CustomRoutingRuleSet) -> some View {
        HStack {
            RuleSetIconView(iconLight: ruleSet.iconLight, iconDark: ruleSet.iconDark)
            VStack(alignment: .leading) {
                Text(ruleSet.name)
                Text("\(ruleSet.rules.count) rule(s)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if let ruleSet = routingRuleSetStore.ruleSets.first(where: { $0.id == ruleSet.id.uuidString }) {
                AssignmentLabel(assignedConfigurationId: ruleSet.assignedConfigurationId)
            }
        }
    }

    private func handleFileImport(_ result: Result<URL, Error>) {
        do {
            let url = try result.get()
            guard url.pathExtension.lowercased() == "arrs" else {
                importError = String(localized: "Invalid Anywhere Routing Rule Set File.")
                return
            }
            let accessing = url.startAccessingSecurityScopedResource()
            defer { if accessing { url.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: url)
            guard let body = String(data: data, encoding: .utf8) else {
                importError = String(localized: "Unknown content.")
                return
            }
            let parsed = RoutingRuleSetParser.parse(body)
            guard parsed.rules.count <= CustomRoutingRuleSet.maxRuleCount else {
                importError = String(localized: "Rule set is too large.")
                return
            }
            let name = parsed.name.isEmpty
                ? (url.deletingPathExtension().lastPathComponent.isEmpty ? "Imported" : url.deletingPathExtension().lastPathComponent)
                : parsed.name
            let ruleSet = CustomRoutingRuleSet(name: name, rules: parsed.rules, iconLight: parsed.iconLight, iconDark: parsed.iconDark)
            operations.routingRuleSets.addCustomRuleSet(ruleSet, initialAssignment: parsed.routing.assignmentId)
        } catch {
            importError = error.localizedDescription
        }
    }

    private func subscribe(to rawValue: String) {
        guard let url = CustomRoutingRuleSet.validSubscriptionURL(from: rawValue) else {
            subscribeError = String(localized: "Invalid Anywhere Routing Rule Set URL.")
            return
        }
        Task {
            do {
                let (data, response) = try await URLSession.shared.data(from: url)
                if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                    subscribeError = "HTTP \(http.statusCode)"
                    return
                }
                guard let body = String(data: data, encoding: .utf8) else {
                    subscribeError = String(localized: "Unknown content.")
                    return
                }
                let parsed = RoutingRuleSetParser.parse(body)
                guard parsed.rules.count <= CustomRoutingRuleSet.maxRuleCount else {
                    subscribeError = String(localized: "Rule set is too large.")
                    return
                }
                let name = parsed.name.isEmpty
                    ? (url.deletingPathExtension().lastPathComponent.isEmpty ? "Subscription" : url.deletingPathExtension().lastPathComponent)
                    : parsed.name
                let ruleSet = CustomRoutingRuleSet(name: name, rules: parsed.rules, subscriptionURL: url, iconLight: parsed.iconLight, iconDark: parsed.iconDark)
                operations.routingRuleSets.addCustomRuleSet(ruleSet, initialAssignment: parsed.routing.assignmentId)
            } catch {
                subscribeError = error.localizedDescription
            }
        }
    }
    
    private func flag(for countryCode: String) -> String {
        String(countryCode.unicodeScalars.compactMap {
            UnicodeScalar(127397 + $0.value)
        }.map(Character.init))
    }

    private func countryLabel(for code: String) -> String {
        let name = Locale.current.localizedString(forRegionCode: code) ?? code
        return "\(flag(for: code)) \(name)"
    }
}
