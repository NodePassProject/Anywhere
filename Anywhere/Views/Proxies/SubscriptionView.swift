//
//  SubscriptionView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/11/26.
//

import SwiftUI

struct SubscriptionView<Content: View>: View {
    let subscription: Subscription
    let configurationCount: Int
    @Binding var isExpanded: Bool
    let isUpdating: Bool

    let onUpdate: () -> Void
    let onReorder: () -> Void
    let onTestLatency: () -> Void
    let onRename: () -> Void
    let onDelete: () -> Void

    @ViewBuilder let content: Content

    @Environment(\.colorScheme) private var colorScheme

    private let animation: Animation = .spring(response: 0.5, dampingFraction: 0.82)

    var body: some View {
        VStack(spacing: 0) {
            Button {
                withAnimation(animation) {
                    isExpanded.toggle()
                }
            } label: {
                header
                    .contentShape(RoundedRectangle(cornerRadius: 24))
                    .padding(.horizontal, isExpanded ? 0 : 12)
            }
            .buttonStyle(.plain)

            VStack(spacing: 10) {
                content
            }
            .padding(.top, 12)
            .rotation3DEffect(
                .degrees(isExpanded ? 0 : -85),
                axis: (x: 1, y: 0, z: 0),
                anchor: .top,
                perspective: 0.4
            )
            .opacity(isExpanded ? 1 : 0)
            .frame(height: isExpanded ? nil : 0, alignment: .top)
            .clipped()
            .allowsHitTesting(isExpanded)
            .accessibilityHidden(!isExpanded)
        }
        .padding(.horizontal, isExpanded ? 12 : 0)
        .padding(.vertical, isExpanded ? 12 : 0)
        .background {
            RoundedRectangle(cornerRadius: 24)
                .fill(Color(.systemGroupedBackground))
                .shadow(color: .primary.opacity(0.2), radius: 6)
                .opacity(isExpanded ? 1 : 0)
        }
        .padding(.vertical, isExpanded ? 12 : 0)
        .geometryGroup()
    }

    private var iconData: Data? {
        switch colorScheme {
        case .dark: subscription.iconDark ?? subscription.iconLight
        default: subscription.iconLight ?? subscription.iconDark
        }
    }

    @ViewBuilder
    private var iconView: some View {
        if let icon = iconData, let image = UIImage(data: icon) {
            Image(uiImage: image)
                .resizable()
                .scaledToFit()
                .frame(width: 20, height: 20)
                .clipShape(RoundedRectangle(cornerRadius: 5))
        } else {
            Image(systemName: "globe")
                .font(.subheadline.weight(.medium))
                .foregroundStyle(.secondary)
        }
    }

    private var header: some View {
        HStack {
            iconView
            VStack(alignment: .leading, spacing: 5) {
                HStack {
                    Text(subscription.name)
                        .font(.body.weight(.medium))
                        .lineLimit(1)
                    if isUpdating {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Button(action: onUpdate) {
                            Image(systemName: "arrow.clockwise")
                        }
                        .buttonStyle(.borderless)
                    }
                    Spacer()
                    TagBadge(text: configurationCount.description, color: .accentColor)
                }
                SubscriptionUsageView(subscription: subscription)
            }
        }
        .padding()
        .background {
            RoundedRectangle(cornerRadius: 24)
                .fill(Color(isExpanded ? .systemGroupedBackground : .secondarySystemGroupedBackground))
        }
        .contentShape(RoundedRectangle(cornerRadius: 24))
        .swipeActions {
            Button(role: .destructive, action: onDelete) {
                Label("Delete", systemImage: "trash")
            }
            Button(action: onUpdate) {
                Label("Update", systemImage: "arrow.clockwise")
            }
            .tint(.blue)
            Button(action: onRename) {
                Label("Rename", systemImage: "pencil")
            }
        }
        .contextMenu {
            if configurationCount > 1 {
                Button(action: onReorder) {
                    Label("Reorder", systemImage: "arrow.up.arrow.down")
                }
            }
            if configurationCount > 0 {
                Section {
                    Button(action: onTestLatency) {
                        Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
                    }
                }
            }
            Section {
                Button(action: onRename) {
                    Label("Rename", systemImage: "pencil")
                }
                Button(action: onUpdate) {
                    Label("Update", systemImage: "arrow.clockwise")
                }
                Button(role: .destructive, action: onDelete) {
                    Label("Delete", systemImage: "trash")
                }
            }
        }
    }
}

private struct SubscriptionUsageView: View {
    let subscription: Subscription

    private static let byteFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        formatter.allowsNonnumericFormatting = false
        return formatter
    }()

    private var totalBytes: Int64? {
        guard let total = subscription.total, total > 0 else { return nil }
        return total
    }

    private var usedBytes: Int64? {
        guard subscription.upload != nil || subscription.download != nil else { return nil }
        return (subscription.upload ?? 0) + (subscription.download ?? 0)
    }

    private var usedFraction: Double? {
        guard let usedBytes, let totalBytes else { return nil }
        return Double(usedBytes) / Double(totalBytes)
    }

    var body: some View {
        if usageDescription != nil || subscription.expire != nil {
            HStack(spacing: 5) {
                if let usedFraction {
                    UsageRing(fraction: usedFraction)
                }
                if let usageDescription, let expire = subscription.expire {
                    Text([usageDescription, expireDescription(expire)].joined(separator: " · "))
                } else if let usageDescription {
                    Text(usageDescription)
                } else if let expire = subscription.expire {
                    Text(expireDescription(expire))
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    private struct UsageRing: View {
        let fraction: Double

        var body: some View {
            ZStack {
                Circle()
                    .inset(by: 1)
                    .stroke(.quaternary, lineWidth: 2)
                Circle()
                    .inset(by: 1)
                    .trim(from: 0, to: max(0.03, min(fraction, 1)))
                    .stroke(usageWarningColor(for: fraction), style: StrokeStyle(lineWidth: 2, lineCap: .round))
                    .rotationEffect(.degrees(-90))
            }
            .frame(width: 12, height: 12)
            .animation(.snappy(duration: 0.3, extraBounce: 0), value: fraction)
        }

        private func usageWarningColor(for fraction: Double) -> Color {
            if fraction >= 0.95 {
                .red
            } else if fraction >= 0.8 {
                .orange
            } else {
                .blue
            }
        }
    }

    private var usageDescription: String? {
        switch (usedBytes, totalBytes) {
        case let (used?, total?):
            String(localized: "\(Self.byteFormatter.string(fromByteCount: used)) of \(Self.byteFormatter.string(fromByteCount: total)) used")
        case let (used?, nil):
            String(localized: "\(Self.byteFormatter.string(fromByteCount: used)) used")
        case let (nil, total?):
            String(localized: "\(Self.byteFormatter.string(fromByteCount: total)) total")
        case (nil, nil):
            nil
        }
    }

    private func expireDescription(_ expire: Date) -> String {
        let calendar = Calendar.current
        let days = calendar.dateComponents(
            [.day],
            from: calendar.startOfDay(for: .now),
            to: calendar.startOfDay(for: expire)
        ).day ?? 0
        if expire < .now {
            return String(localized: "Expired")
        } else {
            return String(localized: "Expires in \(days) day(s)")
        }
    }
}
