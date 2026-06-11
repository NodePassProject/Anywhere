//
//  ProxyRowView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI

struct ProxyRowView: View {
    let item: ProxyListItem
    let editingDisabled: Bool
    let onSelect: () -> Void
    let onTestLatency: () -> Void
    let onCopyLink: () -> Void
    let onEdit: () -> Void
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
                    HStack(spacing: 4) {
                        ForEach(Array(item.tags.enumerated()), id: \.offset) { index, tag in
                            if index > 0 { Text("·") }
                            Text(tag)
                        }
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                Spacer()

                LatencyLabel(latency: item.latency)
                    .onTapGesture(perform: onTestLatency)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .contextMenu {
            Button(action: onTestLatency) {
                Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
            }
            if !editingDisabled {
                Button(action: onCopyLink) {
                    Label("Copy Link", systemImage: "doc.on.doc")
                }
                Button(action: onEdit) {
                    Label("Edit", systemImage: "pencil")
                }
                Button(role: .destructive, action: onDelete) {
                    Label("Delete", systemImage: "trash")
                }
            }
        }
        .swipeActions(edge: .trailing) {
            if !editingDisabled {
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
}
