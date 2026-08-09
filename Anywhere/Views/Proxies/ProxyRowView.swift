//
//  ProxyRowView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI

struct ProxyRowView: View {
    let item: ProxyListItem
    
    let onSelect: () -> Void
    let onTestLatency: () -> Void
    let onCopyLink: () -> Void
    let onEdit: () -> Void
    var onAddToGroup: ((UUID) -> Void)? = nil
    var groupOptions: [PickerItem] = []
    var onRemoveFromGroup: (() -> Void)? = nil
    let onDelete: () -> Void

    var body: some View {
        Button(action: onSelect) {
            HStack {
                VStack(alignment: .leading) {
                    HStack {
                        Text(item.name)
                            .font(.body.weight(.medium))
                        if item.isSelected {
                            Image(systemName: "checkmark")
                                .font(.caption.bold())
                                .foregroundStyle(.tint)
                        }
                    }
                    HStack(spacing: 5) {
                        TagBadge(text: item.protocolName, color: .blue)
                        if let networkTag = item.networkTag {
                            TagBadge(text: networkTag, color: .green)
                        }
                        if let transportLayerTag = item.transportLayerTag {
                            TagBadge(text: transportLayerTag, color: .teal)
                        }
                        if let securityLayerTag = item.securityLayerTag {
                            TagBadge(text: securityLayerTag, color: .orange)
                        }
                        if item.isVision {
                            TagBadge(text: "Vision", color: .purple)
                        }
                    }
                }

                Spacer()

                LatencyLabel(latency: item.latency)
                    .onTapGesture(perform: onTestLatency)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .contextMenu {
            Section {
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
            }
            Section {
                Section {
                    Button(action: onTestLatency) {
                        Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
                    }
                }
                Button(action: onCopyLink) {
                    Label("Copy Link", systemImage: "doc.on.doc")
                }
            }
            Section {
                Button(action: onEdit) {
                    Label("Edit", systemImage: "pencil")
                }
                
                Button(role: .destructive, action: onDelete) {
                    Label("Delete", systemImage: "trash")
                }
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
