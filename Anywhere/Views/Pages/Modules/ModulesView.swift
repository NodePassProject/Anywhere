//
//  ModulesView.swift
//  Anywhere
//
//  Created by NodePassProject on 10/9/26.
//

import SwiftUI
import UniformTypeIdentifiers

nonisolated private let importAllowedContentTypes: [UTType] = [UTType(filenameExtension: "amod") ?? .data]

struct ModulesView: View {
    @Environment(Operations.self) private var operations
    @Environment(ModuleStore.self) private var moduleStore

    @State private var showAddAlert = false
    @State private var newModuleName = ""

    @State private var showFileImporter = false
    @State private var importError: String?

    @State private var showSubscribeAlert = false
    @State private var subscribeURL = ""
    @State private var subscribeError: String?

    var body: some View {
        NavigationStack {
            List {
                if !moduleStore.modules.isEmpty {
                    Section {
                        ForEach(moduleStore.modules) { module in
                            NavigationLink {
                                ModuleDetailView(moduleId: module.id)
                            } label: {
                                row(for: module)
                            }
                        }
                        .onDelete { offsets in
                            operations.modules.remove(atOffsets: offsets)
                        }
                        .onMove { source, destination in
                            operations.modules.move(fromOffsets: source, toOffset: destination)
                        }
                    }
                }
            }
            .overlay {
                if moduleStore.modules.isEmpty {
                    ContentUnavailableView {
                        Label("No Modules", systemImage: "shippingbox")
                    }
                }
            }
            .navigationTitle("Modules")
            .toolbar {
                if !moduleStore.modules.isEmpty {
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
            .alert("Add Module", isPresented: $showAddAlert) {
                TextField("Name", text: $newModuleName)
                Button("Add") {
                    let name = newModuleName.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !name.isEmpty else { return }
                    operations.modules.addEmpty(name: name)
                    newModuleName = ""
                }
                Button("Cancel", role: .cancel) {
                    newModuleName = ""
                }
            }
            .fileImporter(
                isPresented: $showFileImporter,
                allowedContentTypes: importAllowedContentTypes
            ) { result in
                handleFileImport(result)
            }
            .alert("Import Failed", isPresented: Binding(
                get: { importError != nil },
                set: { if !$0 { importError = nil } }
            )) {
                Button("OK") { importError = nil }
            } message: {
                Text(importError ?? "")
            }
            .alert("Subscribe Module", isPresented: $showSubscribeAlert) {
                TextField("Anywhere Module URL", text: $subscribeURL)
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
        }
    }

    @ViewBuilder
    private var menuItems: some View {
        Button {
            showAddAlert = true
        } label: {
            Label("Add Module", systemImage: "plus")
        }
        Button {
            importError = nil
            showFileImporter = true
        } label: {
            Label("Import Module", systemImage: "square.and.arrow.down")
        }
        Button {
            subscribeURL = ""
            showSubscribeAlert = true
        } label: {
            Label("Subscribe Module", systemImage: "link")
        }
    }

    @ViewBuilder
    private func row(for module: Module) -> some View {
        HStack {
            ModuleIconView(iconLight: module.iconLight, iconDark: module.iconDark)
            Text(module.name)
            Spacer()
            statusDot(enabled: module.enabled)
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

    private func handleFileImport(_ result: Result<URL, Error>) {
        do {
            let url = try result.get()
            guard url.pathExtension.lowercased() == "amod" else {
                importError = String(localized: "Invalid Anywhere Module File.")
                return
            }
            let accessing = url.startAccessingSecurityScopedResource()
            defer { if accessing { url.stopAccessingSecurityScopedResource() } }
            let data = try Data(contentsOf: url)
            guard let body = String(data: data, encoding: .utf8) else {
                importError = String(localized: "Unknown content.")
                return
            }
            let base = url.deletingPathExtension().lastPathComponent
            let made = try ModuleOperations.makeModule(from: body, fallbackName: base.isEmpty ? "Imported" : base)
            operations.modules.add(made.module, routingSeeds: made.routingSeeds)
        } catch {
            importError = error.localizedDescription
        }
    }

    private func subscribe(to rawValue: String) {
        guard let url = Module.validSubscriptionURL(from: rawValue) else {
            subscribeError = String(localized: "Invalid Anywhere Module URL.")
            return
        }
        Task {
            do {
                let body = try await ModuleOperations.fetchBody(from: url)
                let made = try ModuleOperations.makeModule(
                    from: body,
                    fallbackName: ModuleOperations.fallbackName(for: url),
                    subscriptionURL: url
                )
                operations.modules.add(made.module, routingSeeds: made.routingSeeds)
            } catch {
                subscribeError = error.localizedDescription
            }
        }
    }
}
