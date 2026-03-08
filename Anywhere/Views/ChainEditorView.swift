//
//  ChainEditorView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/8/26.
//

import SwiftUI

struct ChainEditorView: View {
    @Environment(VPNViewModel.self) private var viewModel: VPNViewModel
    @Environment(\.dismiss) private var dismiss

    /// Existing chain to edit, or `nil` for a new chain.
    var chain: ProxyChain?
    var onSave: (ProxyChain) -> Void

    @State private var name: String = ""
    @State private var selectedProxyIds: [UUID] = []
    @State private var showingProxyPicker = false

    private var isEditing: Bool { chain != nil }

    private var selectedProxies: [ProxyConfiguration] {
        selectedProxyIds.compactMap { id in
            viewModel.configurations.first(where: { $0.id == id })
        }
    }

    private var canSave: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty && selectedProxies.count >= 2
    }

    var body: some View {
        NavigationStack {
            Form {
                TextField("Name", text: $name)

                Section {
                    ForEach(Array(selectedProxies.enumerated()), id: \.element.id) { index, proxy in
                        HStack(spacing: 12) {
                            Text("\(index + 1)")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.white)
                                .frame(width: 22, height: 22)
                                .background(
                                    Circle()
                                        .fill(index == 0 ? Color.blue : index == selectedProxies.count - 1 ? Color.green : Color.secondary)
                                )

                            VStack(alignment: .leading, spacing: 2) {
                                Text(proxy.name)
                                    .font(.body)
                                Text("\(proxy.serverAddress):\(proxy.serverPort, format: .number.grouping(.never))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }

                            Spacer()

                            if index == 0 {
                                Text("Entry")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            } else if index == selectedProxies.count - 1 {
                                Text("Exit")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .onMove(perform: moveProxy)
                    .onDelete(perform: deleteProxy)

                    Button {
                        showingProxyPicker = true
                    } label: {
                        Label("Add Proxy", systemImage: "plus")
                    }
                } header: {
                    Text("Proxies")
                } footer: {
                    if selectedProxies.count < 2 {
                        Text("Add at least 2 proxies to form a chain.")
                    }
                }

                if selectedProxies.count >= 2 {
                    Section("Route Preview") {
                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 6) {
                                Text("You")
                                    .font(.caption.weight(.medium))
                                    .foregroundStyle(.secondary)

                                ForEach(selectedProxies) { proxy in
                                    Image(systemName: "arrow.right")
                                        .font(.caption2)
                                        .foregroundStyle(.tertiary)
                                    Text(proxy.name)
                                        .font(.caption.weight(.medium))
                                        .lineLimit(1)
                                }

                                Image(systemName: "arrow.right")
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                                Text("Target")
                                    .font(.caption.weight(.medium))
                                    .foregroundStyle(.secondary)
                            }
                            .padding(.vertical, 4)
                        }
                    }
                }
            }
            .navigationTitle(isEditing ? "Edit Chain" : "New Chain")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if #available(iOS 26.0, *) {
                        Button(role: .cancel) {
                            dismiss()
                        } label: {
                            Label("Cancel", systemImage: "xmark")
                        }
                    } else {
                        Button("Cancel") { dismiss() }
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if #available(iOS 26.0, *) {
                        Button {
                            save()
                        } label: {
                            Label("Save", systemImage: "checkmark")
                        }
                        .disabled(!canSave)
                    } else {
                        Button("Save") { save() }
                            .disabled(!canSave)
                    }
                }
            }
            .environment(\.editMode, .constant(.active))
            .sheet(isPresented: $showingProxyPicker) {
                ProxyPickerView(
                    configurations: viewModel.configurations,
                    excludedIds: Set(selectedProxyIds)
                ) { selected in
                    selectedProxyIds.append(selected.id)
                }
            }
            .onAppear {
                if let chain {
                    name = chain.name
                    selectedProxyIds = chain.proxyIds
                }
            }
        }
    }

    private func moveProxy(from source: IndexSet, to destination: Int) {
        selectedProxyIds.move(fromOffsets: source, toOffset: destination)
    }

    private func deleteProxy(at offsets: IndexSet) {
        selectedProxyIds.remove(atOffsets: offsets)
    }

    private func save() {
        var result = chain ?? ProxyChain(name: name)
        result.name = name.trimmingCharacters(in: .whitespaces)
        result.proxyIds = selectedProxyIds
        onSave(result)
        dismiss()
    }
}

// MARK: - Proxy Picker

private struct ProxyPickerView: View {
    @Environment(\.dismiss) private var dismiss
    let configurations: [ProxyConfiguration]
    let excludedIds: Set<UUID>
    let onSelect: (ProxyConfiguration) -> Void

    private var available: [ProxyConfiguration] {
        configurations.filter { !excludedIds.contains($0.id) }
    }

    var body: some View {
        NavigationStack {
            List {
                ForEach(available) { proxy in
                    Button {
                        onSelect(proxy)
                        dismiss()
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(proxy.name)
                                .font(.body)
                                .foregroundStyle(.primary)
                            Text("\(proxy.serverAddress):\(proxy.serverPort, format: .number.grouping(.never))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            HStack(spacing: 4) {
                                Text(proxy.transport.uppercased())
                                Text("·")
                                Text(proxy.security.uppercased())
                            }
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                        }
                    }
                }
            }
            .overlay {
                if available.isEmpty {
                    ContentUnavailableView(
                        "No Proxies Available",
                        systemImage: "network.slash",
                        description: Text("All proxies are already in this chain.")
                    )
                }
            }
            .navigationTitle("Select Proxy")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }
}
