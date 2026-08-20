//
//  RuleSetListView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI
import UniformTypeIdentifiers

struct RuleSetListView: View {
    @Environment(\.editMode) private var editMode
    @Environment(Operations.self) private var operations
    @Environment(RoutingRuleSetStore.self) private var routingRuleSetStore

    @State var adBlockEnabled = false
    @State var builtInServiceRuleSets: [RoutingRuleSet] = []
    @State var customRuleSets: [CustomRoutingRuleSet] = []

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
        List {
            Section {
                Toggle(isOn: $adBlockEnabled) {
                    TextWithColorfulIcon(title: "Block Advertisements", comment: nil, systemName: "shield.checkered", foregroundStyle: .white, backgroundStyle: .red.gradient)
                }
                .onChange(of: adBlockEnabled) { _, newValue in
                    guard let adBlockRuleSet = routingRuleSetStore.adBlockRuleSet else { return }
                    operations.routingRuleSets.updateAssignment(adBlockRuleSet, configurationId: newValue ? "REJECT" : nil)
                }
            }
            Section {
                Picker(selection: Binding(
                    get: { routingRuleSetStore.bypassCountryCode },
                    set: { operations.routingRuleSets.setBypassCountryCode($0) }
                )) {
                    Text("Disable").tag("")
                    ForEach(CountryBypassCatalog.shared.supportedCountryCodes, id: \.self) { code in
                        Text(countryLabel(for: code)).tag(code)
                    }
                } label: {
                    TextWithColorfulIcon(title: "Country Bypass", comment: nil, systemName: "globe.americas.fill", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                }
            }
            Section {
                ForEach($builtInServiceRuleSets) { $ruleSet in
                    if !ruleSet.isCustom {
                        builtInRuleSetRow(for: $ruleSet)
                    }
                }
            }
            if !customRuleSets.isEmpty {
                Section {
                    ForEach(customRuleSets) { customRuleSet in
                        customRuleSetLink(for: customRuleSet)
                    }
                    .onDelete { offsets in
                        customRuleSets.remove(atOffsets: offsets)
                        if isEditing != true {
                            save()
                        }
                    }
                    .onMove { source, destination in
                        customRuleSets.move(fromOffsets: source, toOffset: destination)
                        if isEditing != true {
                            save()
                        }
                    }
                }
            }
        }
        .listRowSpacing(8)
        .navigationTitle("Routing Rules")
        .toolbar {
            if isEditing == true || !customRuleSets.isEmpty {
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
        .onChange(of: builtInServiceRuleSets) { oldValue, newValue in
            for currentRuleSet in newValue {
                let previousRuleSet = oldValue.first(where: { $0.id == currentRuleSet.id })
                if currentRuleSet.assignedConfigurationId != previousRuleSet?.assignedConfigurationId {
                    operations.routingRuleSets.updateAssignment(currentRuleSet, configurationId: currentRuleSet.assignedConfigurationId)
                }
            }
        }
        .onChange(of: isEditing) { _, newValue in
            if newValue == false {
                save()
            }
        }
        .onAppear {
            adBlockEnabled = routingRuleSetStore.adBlockRuleSet?.assignedConfigurationId == "REJECT"
            builtInServiceRuleSets = routingRuleSetStore.builtInServiceRuleSets
            customRuleSets = routingRuleSetStore.customRuleSets
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
                customRuleSets = routingRuleSetStore.customRuleSets
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
                builtInServiceRuleSets = routingRuleSetStore.builtInServiceRuleSets
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Reset all rule set assignments to Default.")
        }
    }
    
    private func save() {
        let store = routingRuleSetStore
        let localIds = customRuleSets.map(\.id)
        guard localIds != store.customRuleSets.map(\.id) else { return }
        
        let surviving = Set(localIds)
        for removed in store.customRuleSets where !surviving.contains(removed.id) {
            operations.routingRuleSets.removeCustomRuleSet(removed.id)
        }
        if store.customRuleSets.map(\.id) != localIds {
            operations.routingRuleSets.reorderCustomRuleSets(customRuleSets)
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
    private func builtInRuleSetRow(for ruleSet: Binding<RoutingRuleSet>) -> some View {
        HStack {
            AppIconView(ruleSet.wrappedValue.name)
            Text(ruleSet.wrappedValue.name)
            Spacer()
            AssignmentMenuButton(selection: ruleSet.assignedConfigurationId)
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
            if let ruleSet = builtInServiceRuleSets.first(where: { $0.id == ruleSet.id.uuidString }) {
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
            customRuleSets = routingRuleSetStore.customRuleSets
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
                customRuleSets = routingRuleSetStore.customRuleSets
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
