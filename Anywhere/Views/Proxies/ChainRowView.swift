//
//  ChainRowView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import SwiftUI

struct ChainRowView: View {
    let item: ChainListItem
    
    let onSelect: () -> Void
    let onTestLatency: () -> Void
    let onEdit: () -> Void
    var onAddToGroup: ((UUID) -> Void)? = nil
    var groupOptions: [PickerItem] = []
    var onRemoveFromGroup: (() -> Void)? = nil
    let onDelete: () -> Void

    var body: some View {
        Button(action: onSelect) {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    HStack {
                        Text(item.name)
                            .font(.body.weight(.medium))
                        if item.isSelected {
                            Image(systemName: "checkmark")
                                .font(.caption.bold())
                                .foregroundStyle(.tint)
                        }
                    }

                    if item.isValid {
                        HStack(spacing: 4) {
                            ForEach(Array(item.proxyNames.enumerated()), id: \.offset) { index, proxyName in
                                if index > 0 {
                                    Image(systemName: "arrow.right")
                                        .font(.system(size: 8))
                                }
                                Text(proxyName)
                                    .lineLimit(1)
                            }
                        }
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    } else {
                        Text("Invalid chain — some proxies are missing")
                            .font(.caption)
                            .foregroundStyle(.red)
                    }

                    HStack(spacing: 4) {
                        Text("\(item.proxyNames.count) proxie(s)")
                        if let entry = item.entryAddress, let exit = item.exitAddress {
                            Text("·")
                            Text("\(entry) → \(exit)")
                                .lineLimit(1)
                        }
                    }
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                }

                Spacer()

                if item.isValid {
                    LatencyLabel(latency: item.latency)
                        .onTapGesture(perform: onTestLatency)
                }
            }
            .padding()
            .background {
                RoundedRectangle(cornerRadius: 24)
                    .fill(Color(.secondarySystemGroupedBackground))
            }
            .contentShape(RoundedRectangle(cornerRadius: 24))
            .contentShape(.contextMenuPreview, RoundedRectangle(cornerRadius: 24))
        }
        .buttonStyle(.plain)
        .opacity(item.isValid ? 1 : 0.6)
        .contextMenu {
            if item.isValid {
                Button(action: onTestLatency) {
                    Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
                }
            }
            Button(action: onEdit) {
                Label("Edit", systemImage: "pencil")
            }
            if let onAddToGroup, !groupOptions.isEmpty {
                Menu {
                    ForEach(groupOptions) { option in
                        Button(option.name) { onAddToGroup(option.id) }
                    }
                } label: {
                    Label("Add to Group", systemImage: "folder.badge.plus")
                }
            }
            if let onRemoveFromGroup {
                Button(action: onRemoveFromGroup) {
                    Label("Remove from Group", systemImage: "folder.badge.minus")
                }
            }
            Button(role: .destructive, action: onDelete) {
                Label("Delete", systemImage: "trash")
            }
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive, action: onDelete) {
                Label("Delete", systemImage: "trash")
            }
            Button(action: onEdit) {
                Label("Edit", systemImage: "pencil")
            }
            .tint(.orange)
        }
    }
}
