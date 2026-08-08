//
//  MultiSelectPickerView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/8/26.
//

import SwiftUI

struct MultiSelectPickerView: View {
    struct Item: Identifiable {
        let id: UUID
        let title: String
    }

    struct ItemSection: Identifiable {
        let id: String
        let header: String?
        let items: [Item]
    }

    @Environment(\.dismiss) private var dismiss
    
    let sections: [ItemSection]
    let onAdd: ([UUID]) -> Void

    @State private var selectedIds: Set<UUID> = []

    init(sections: [ItemSection], onAdd: @escaping ([UUID]) -> Void) {
        self.sections = sections
        self.onAdd = onAdd
    }

    init(items: [Item], onAdd: @escaping ([UUID]) -> Void) {
        self.init(sections: [ItemSection(id: "items", header: nil, items: items)], onAdd: onAdd)
    }

    var body: some View {
        NavigationStack {
            List {
                ForEach(sections) { section in
                    Section {
                        ForEach(section.items) { item in
                            itemRow(item)
                        }
                    } header: {
                        if let header = section.header {
                            Text(header)
                        }
                    }
                }
            }
            .navigationTitle("Select")
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
                            add()
                        } label: {
                            Label("Add", systemImage: "checkmark")
                        }
                        .disabled(selectedIds.isEmpty)
                    } else {
                        Button("Add") { add() }
                            .disabled(selectedIds.isEmpty)
                    }
                }
            }
        }
    }

    private func itemRow(_ item: Item) -> some View {
        Button {
            if selectedIds.contains(item.id) {
                selectedIds.remove(item.id)
            } else {
                selectedIds.insert(item.id)
            }
        } label: {
            HStack {
                Text(item.title)
                Spacer()
                if selectedIds.contains(item.id) {
                    Image(systemName: "checkmark")
                        .font(.caption.bold())
                        .foregroundStyle(.tint)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func add() {
        onAdd(sections.flatMap(\.items).map(\.id).filter { selectedIds.contains($0) })
        dismiss()
    }
}
