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
    
    let moduleId: UUID

    @State private var showRenameAlert = false
    @State private var renameText = ""

    @State private var isUpdating = false
    @State private var updateSucceeded = false
    @State private var updateError: String?

    private var module: Module? { moduleStore.module(id: moduleId) }

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
                
                ForEach(module.mitmParameters) { parameter in
                    Section {
                        parameterRow(parameter)
                    } footer: {
                        if let description = parameter.description, !description.isEmpty {
                            Text(description)
                        }
                    }
                }

                Section {
                    NavigationLink("Module Content") {
                        ModuleContentView(moduleId: moduleId)
                    }
                }
            }
        }
        .navigationTitle(module?.name ?? String(localized: "Module"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if #available(iOS 27.0, *),
               !ProcessInfo.processInfo.isiOSAppOnMac /* Workaround */ {
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

    // MARK: - Parameters

    @ViewBuilder
    private func parameterRow(_ parameter: MITMParameter) -> some View {
        let parameterLabel = parameter.label ?? parameter.name
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

    private func parameterBinding(_ parameter: MITMParameter) -> Binding<String> {
        Binding(
            get: { module?.mitmParameterValue(name: parameter.name) ?? parameter.defaultValue },
            set: { operations.modules.setMITMParameterValue(in: moduleId, name: parameter.name, value: $0) }
        )
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
