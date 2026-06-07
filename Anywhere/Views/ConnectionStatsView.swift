//
//  ConnectionStatsView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import SwiftUI

struct ConnectionStatsView: View {
    @Environment(ConnectionStatsModel.self) private var stats
    
    private static let connectionCeiling: Double = 256
    private static let memoryCeiling: Double = 50 * 1024 * 1024
    
    var body: some View {
        VStack(spacing: 16) {
            HStack(spacing: 16) {
                StatCard("Upload", systemImage: "arrow.up") {
                    StatValue(Self.formatBytes(stats.bytesOut))
                }
                StatCard("Download", systemImage: "arrow.down") {
                    StatValue(Self.formatBytes(stats.bytesIn))
                }
            }
            HStack(spacing: 16) {
                StatCard("TCP", systemImage: "arrow.left.arrow.right", spacing: 15) {
                    Gauge(value: Double(stats.tcpConnectionCount), in: 0...Self.connectionCeiling) { }
                        .gaugeStyle(AnywherePressureGaugeStyle())
                }
                StatCard("UDP", systemImage: "arrow.left.and.right", spacing: 15) {
                    Gauge(value: Double(stats.udpConnectionCount), in: 0...Self.connectionCeiling) { }
                        .gaugeStyle(AnywherePressureGaugeStyle())
                }
            }
            StatCard("Memory", systemImage: "memorychip", height: 100) {
                StatValue(Self.formatBytes(Int64(stats.memoryBytes)))
                Gauge(value: Double(stats.memoryBytes), in: 0...Self.memoryCeiling) { }
                    .gaugeStyle(AnywherePressureGaugeStyle())
            }
            HStack(spacing: 16) {
                StatCard("Dial", systemImage: "phone") {
                    StatValue(Self.formatMilliseconds(stats.dialMs))
                }
                StatCard("Handshake", systemImage: "recordingtape") {
                    StatValue(Self.formatMilliseconds(stats.handshakeMs))
                }
            }
        }
    }

    // MARK: - Formatting

    private static let byteFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        formatter.allowsNonnumericFormatting = false
        return formatter
    }()

    private static func formatBytes(_ bytes: Int64) -> String {
        byteFormatter.string(fromByteCount: bytes)
    }

    private static func formatMilliseconds(_ ms: Int?) -> String {
        guard let ms else { return "—" }
        return "\(ms) ms"
    }
}

// MARK: - StatCard

struct StatCard<Content: View>: View {
    private let titleKey: LocalizedStringKey
    private let systemImage: String
    private let spacing: CGFloat
    private let height: CGFloat
    private let content: Content

    init(
        _ titleKey: LocalizedStringKey,
        systemImage: String,
        spacing: CGFloat = 10,
        height: CGFloat = 80,
        @ViewBuilder content: () -> Content
    ) {
        self.titleKey = titleKey
        self.systemImage = systemImage
        self.spacing = spacing
        self.height = height
        self.content = content()
    }

    var body: some View {
        VStack(spacing: spacing) {
            Label(titleKey, systemImage: systemImage)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.white.opacity(0.7))
            content
        }
        .padding(16)
        .frame(height: height)
        .frame(maxWidth: .infinity)
        .modifier(StatCardChrome())
    }
}

struct StatValue: View {
    private let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(.system(size: 24, design: .rounded))
            .foregroundStyle(.white)
            .lineLimit(1)
            .minimumScaleFactor(0.6)
            .contentTransition(.numericText())
            .animation(.default, value: text)
    }
}

private struct StatCardChrome: ViewModifier {
    func body(content: Content) -> some View {
        content
            .contentShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(.white.opacity(0.2))
            )
    }
}

// MARK: - Gauge style

struct AnywherePressureGaugeStyle: GaugeStyle {
    func makeBody(configuration: Configuration) -> some View {
        VStack(alignment: .leading) {
            GeometryReader { proxy in
                let fraction = min(max(configuration.value, 0), 1)
                let fillWidth = fraction == 0 ? 0 : max(proxy.size.width * fraction, proxy.size.height)
                ZStack(alignment: .leading) {
                    Capsule()
                        .foregroundStyle(.white.opacity(0.2))
                    Capsule()
                        .foregroundStyle(.cyan)
                        .frame(width: fillWidth)
                        .animation(.default, value: fraction)
                }
            }
            .frame(height: 10)
            configuration.label
        }
    }
}

#if DEBUG
#Preview {
    ZStack {
        LinearGradient(
            colors: [Color.connectedBackgroundStart, Color.connectedBackgroundEnd],
            startPoint: .top,
            endPoint: .bottom
        )
        .ignoresSafeArea()
        ConnectionStatsView()
            .environment(ConnectionStatsModel.previewSeeded())
            .padding(24)
    }
}
#endif
