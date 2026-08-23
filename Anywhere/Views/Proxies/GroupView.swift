//
//  GroupView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/11/26.
//

import SwiftUI

struct GroupView<Content: View>: View {
    let group: ProxyGroup
    let memberCount: Int
    @Binding var isExpanded: Bool

    let onReorder: () -> Void
    let onTestLatency: () -> Void
    let onEdit: () -> Void
    let onDelete: () -> Void

    @ViewBuilder let content: Content

    private let animation: Animation = .spring(response: 0.5, dampingFraction: 0.82)

    var body: some View {
        VStack(spacing: 0) {
            Button {
                withAnimation(animation) {
                    isExpanded.toggle()
                }
            } label: {
                header
                    .padding(.horizontal, isExpanded ? 0 : 12)
            }
            .buttonStyle(.plain)

            if isExpanded {
                LazyVStack(spacing: 10) {
                    content
                }
                .padding(.top, 12)
            }
        }
        .padding(.horizontal, isExpanded ? 7 : 0)
        .padding(.vertical, isExpanded ? 12 : 0)
        .background {
            RoundedRectangle(cornerRadius: 24)
                .fill(Color(isExpanded ? .systemGroupedBackground : .clear))
                .shadow(color: .primary.opacity(isExpanded ? 0.2 : 0), radius: 6)
                .padding(.horizontal, isExpanded ? 0 : 12)
        }
        .padding(.horizontal, isExpanded ? 5 : 0)
        .padding(.vertical, isExpanded ? 12 : 0)
        .geometryGroup()
    }
    
    @ViewBuilder
    private var iconView: some View {
        let imageSize: CGFloat = isExpanded ? 36 : 18
        Image(systemName: "folder")
            .resizable()
            .scaledToFit()
            .frame(width: imageSize, height: imageSize)
            .foregroundStyle(.secondary)
    }

    private var header: some View {
        HStack(spacing: isExpanded ? 20 : 10) {
            iconView
            Text(group.name)
                .font(.body.weight(.medium))
            Spacer()
            TagBadge(text: memberCount.description, color: .accentColor)
        }
        .padding()
        .background {
            RoundedRectangle(cornerRadius: 24)
                .fill(Color(isExpanded ? .systemGroupedBackground : .secondarySystemGroupedBackground))
        }
        .contentShape(RoundedRectangle(cornerRadius: 24))
        .contentShape(.contextMenuPreview, RoundedRectangle(cornerRadius: 24))
        .swipeActions {
            Button(role: .destructive, action: onDelete) {
                Label("Delete", systemImage: "trash")
            }
            Button(action: onEdit) {
                Label("Edit", systemImage: "pencil")
            }
            .tint(.orange)
        }
        .contextMenu {
            Section {
                Button(action: onEdit) {
                    Label("Edit", systemImage: "pencil")
                }
                Button(role: .destructive, action: onDelete) {
                    Label("Delete", systemImage: "trash")
                }
            }
        }
    }
}
