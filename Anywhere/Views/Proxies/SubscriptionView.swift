//
//  SubscriptionView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/11/26.
//

import SwiftUI

struct SubscriptionView<Content: View>: View {
    @Environment(\.colorScheme) private var colorScheme
    
    let subscription: Subscription
    let configurationCount: Int
    @Binding var isExpanded: Bool
    let isUpdating: Bool

    let onRename: () -> Void
    let onDelete: () -> Void

    @ViewBuilder let content: Content

    var body: some View {
        VStack(spacing: 0) {
            Button {
                withAnimation(.spring(response: 0.5, dampingFraction: 0.82)) {
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

    private var iconData: Data? {
        switch colorScheme {
        case .dark: subscription.iconDark ?? subscription.iconLight
        default: subscription.iconLight ?? subscription.iconDark
        }
    }

    @ViewBuilder
    private var iconView: some View {
        let imageSize: CGFloat = isExpanded ? 36 : 18
        if let icon = iconData, let image = SubscriptionIconCache.image(for: icon) {
            Image(uiImage: image)
                .resizable()
                .scaledToFit()
                .frame(width: imageSize, height: imageSize)
        } else {
            Image(systemName: "globe")
                .resizable()
                .scaledToFit()
                .frame(width: imageSize, height: imageSize)
                .foregroundStyle(.secondary)
        }
    }

    private var header: some View {
        HStack(spacing: isExpanded ? 20 : 10) {
            iconView
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 10) {
                    Text(subscription.name)
                        .font(.body.weight(.medium))
                        .lineLimit(1)
                    if isUpdating {
                        ProgressView()
                            .controlSize(.small)
                    }
                    Spacer()
                    TagBadge(text: configurationCount.description, color: .accentColor)
                }
                if isExpanded {
                    SubscriptionUsageView(subscription: subscription)
                }
            }
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
            Button(action: onRename) {
                Label("Rename", systemImage: "pencil")
            }
            .tint(.gray)
        }
        .contextMenu {
            Button(action: onRename) {
                Label("Rename", systemImage: "pencil")
            }
            Button(role: .destructive, action: onDelete) {
                Label("Delete", systemImage: "trash")
            }
        }
    }
}

private enum SubscriptionIconCache {
    static let cache = NSCache<NSData, UIImage>()

    static func image(for data: Data) -> UIImage? {
        let key = data as NSData
        if let cached = cache.object(forKey: key) {
            return cached
        }
        guard let image = UIImage(data: data) else { return nil }
        cache.setObject(image, forKey: key)
        return image
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
            VStack(alignment: .leading, spacing: 5) {
                if let usedFraction, let usageDescription {
                    HStack(spacing: 5) {
                        UsageRing(fraction: usedFraction)
                        Text(usageDescription)
                    }
                }
                if let expire = subscription.expire {
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
