//
//  GroupEditorView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/8/26.
//

import SwiftUI

struct GroupEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(ConfigurationStore.self) private var configurationStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(GroupStore.self) private var groupStore
    
    let kind: ProxyGroup.Kind
    var group: ProxyGroup?
    var onSave: (ProxyGroup) -> Void

    @State private var name: String = ""
    @State private var memberIds: [UUID] = []
    @State private var showingMemberPicker = false

    private var isEditing: Bool { group != nil }

    private var members: [MultiSelectPickerView.Item] {
        memberIds.compactMap(memberRow(for:))
    }
    
    private var candidates: [MultiSelectPickerView.Item] {
        let taken = Set(
            groupStore.groups(of: kind)
                .filter { $0.id != group?.id }
                .flatMap(\.memberIds)
        ).union(memberIds)
        switch kind {
        case .servers:
            return configurationStore.configurations
                .filter { $0.subscriptionId == nil && !taken.contains($0.id) }
                .compactMap { memberRow(for: $0.id) }
        case .chains:
            return chainStore.chains
                .filter { !taken.contains($0.id) }
                .compactMap { memberRow(for: $0.id) }
        }
    }

    private var canSave: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledContent {
                        TextField("Name", text: $name)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Name", systemName: "tag.fill", foregroundStyle: .white, backgroundStyle: .gray.gradient)
                    }
                }

                Section {
                    ForEach(members) { member in
                        Text(member.title)
                    }
                    .onMove { source, destination in
                        memberIds.move(fromOffsets: source, toOffset: destination)
                    }
                    .onDelete { offsets in
                        memberIds.remove(atOffsets: offsets)
                    }

                    Button {
                        showingMemberPicker = true
                    } label: {
                        if kind == .servers {
                            Label("Add Proxy", systemImage: "plus")
                        } else {
                            Label("Add Chain", systemImage: "plus")
                        }
                    }
                    .disabled(candidates.isEmpty)
                } header: {
                    if kind == .servers {
                        Text("Proxies")
                    } else {
                        Text("Chains")
                    }
                }
            }
            .navigationTitle(isEditing ? "Edit Group" : "New Group")
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
            .sheet(isPresented: $showingMemberPicker) {
                MultiSelectPickerView(items: candidates) { selected in
                    memberIds.append(contentsOf: selected)
                }
            }
            .onAppear {
                if let group {
                    name = group.name
                    memberIds = group.memberIds.filter { memberRow(for: $0) != nil }
                }
            }
        }
    }

    private func memberRow(for id: UUID) -> MultiSelectPickerView.Item? {
        switch kind {
        case .servers:
            guard let configuration = configurationStore.configurations.first(where: { $0.id == id }) else { return nil }
            return MultiSelectPickerView.Item(
                id: id,
                title: configuration.name
            )
        case .chains:
            guard let chain = chainStore.chains.first(where: { $0.id == id }) else { return nil }
            return MultiSelectPickerView.Item(
                id: id,
                title: chain.name
            )
        }
    }

    private func save() {
        var result = group ?? ProxyGroup(name: name, kind: kind)
        result.name = name.trimmingCharacters(in: .whitespaces)
        result.memberIds = memberIds
        onSave(result)
        dismiss()
    }
}
