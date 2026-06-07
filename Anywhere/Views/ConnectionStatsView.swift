//
//  ConnectionStatsView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import SwiftUI
import Charts

struct ConnectionStatsView: View {
    @Environment(ConnectionStatsModel.self) private var stats
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(ChainStore.self) private var chainStore

    private static let connectionCeiling: Double = 256
    private static let memoryCeiling: Double = 50 * 1024 * 1024
    
    private func routeName(_ target: RouteTarget) -> String {
        target.displayName(configStore: configStore, chainStore: chainStore)
    }

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
            if stats.bytesOut > 0 || stats.bytesIn > 0 {
                RouteBreakdownCard(
                    routes: stats.routes,
                    name: routeName
                )
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

    fileprivate static func formatBytes(_ bytes: Int64) -> String {
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

// MARK: - Route Breakdown

private struct RouteBreakdownCard: View {
    let routes: [RouteTrafficEntry]
    let name: (RouteTarget) -> String
    
    private static let proxyPalette: [Color] =
        [.cyan, .orange, .purple, .pink, .yellow, .mint, .indigo, .teal]
    private static let directColor: Color = .green
    private static let otherColor: Color = .gray
    
    private static let maxRows = 4

    private struct Slice: Identifiable {
        let id: String
        let label: String
        let bytes: Int64
        let color: Color
    }
    
    private var slices: [Slice] {
        let proxies: [RouteTrafficEntry] = routes
            .filter { $0.totalBytes > 0 && $0.target.configurationID != nil }
            .sorted { $0.totalBytes > $1.totalBytes }
        let directBytes: Int64 = routes.first { $0.target == .direct }?.totalBytes ?? 0

        // Reserve one row for Direct; the rest go to proxies, with an "Other"
        // bucket taking a slot when they don't all fit.
        let proxyBudget = Self.maxRows - 1
        let overflow = proxies.count > proxyBudget
        let shownCount = overflow ? proxyBudget - 1 : proxies.count
        let shown: [RouteTrafficEntry] = Array(proxies.prefix(shownCount))

        var rows: [Slice] = []
        for index in shown.indices {
            let proxy = shown[index]
            rows.append(Slice(
                id: proxy.id,
                label: name(proxy.target),
                bytes: proxy.totalBytes,
                color: Self.proxyPalette[index % Self.proxyPalette.count]
            ))
        }
        if overflow {
            var otherBytes: Int64 = 0
            for proxy in proxies.dropFirst(shownCount) { otherBytes += proxy.totalBytes }
            rows.append(Slice(id: "__other__", label: String(localized: "Other"),
                              bytes: otherBytes, color: Self.otherColor))
        }
        rows.append(Slice(id: "__direct__", label: name(.direct),
                          bytes: directBytes, color: Self.directColor))
        return rows.sorted { $0.bytes > $1.bytes }
    }

    private var total: Int64 { slices.reduce(0) { $0 + $1.bytes } }

    var body: some View {
        VStack(spacing: 14) {
            Label("Traffic by Route", systemImage: "chart.pie")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.white.opacity(0.7))

            HStack(spacing: 18) {
                donut
                    .frame(maxWidth: .infinity)
                legend
                    .frame(maxWidth: .infinity)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 80)
        .modifier(StatCardChrome())
    }

    private var donut: some View {
        Chart(slices) { slice in
            SectorMark(
                angle: .value("Usage", Double(slice.bytes)),
                innerRadius: .ratio(0.62),
                angularInset: 1.5
            )
            .cornerRadius(3)
            .foregroundStyle(slice.color)
        }
        .chartLegend(.hidden)
    }

    private var legend: some View {
        VStack(alignment: .leading, spacing: 12) {
            ForEach(slices) { slice in
                LegendRow(
                    color: slice.color,
                    label: slice.label,
                    bytes: slice.bytes,
                    fraction: total > 0 ? Double(slice.bytes) / Double(total) : 0
                )
            }
        }
    }
}

private struct LegendRow: View {
    let color: Color
    let label: String
    let bytes: Int64
    let fraction: Double

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(color)
                .frame(width: 10, height: 10)
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: label)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.white.opacity(0.85))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(ConnectionStatsView.formatBytes(bytes))
                    .font(.system(size: 15, design: .rounded))
                    .foregroundStyle(.white)
                    .contentTransition(.numericText())
                    .animation(.default, value: bytes)
            }
            Spacer(minLength: 4)
            Text(fraction, format: .percent.precision(.fractionLength(0)))
                .font(.caption.weight(.semibold))
                .foregroundStyle(.white.opacity(0.6))
                .monospacedDigit()
        }
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
            .environment(ConfigurationStore.shared)
            .environment(ChainStore.shared)
            .padding(24)
    }
}

#Preview("Route Breakdown") {
    let us = UUID(), jp = UUID(), de = UUID(), fr = UUID(), sg = UUID()
    let names: [UUID: String] = [
        us: "US · Los Angeles", jp: "JP · Tokyo", de: "DE · Frankfurt",
        fr: "FR · Paris", sg: "SG · Singapore",
    ]
    // Five proxies + direct → exercises the 4-row cap and the "Other" bucket.
    return ZStack {
        LinearGradient(
            colors: [Color.connectedBackgroundStart, Color.connectedBackgroundEnd],
            startPoint: .top,
            endPoint: .bottom
        )
        .ignoresSafeArea()
        RouteBreakdownCard(
            routes: [
                RouteTrafficEntry(target: .proxy(us), bytesIn: 1_200_000_000, bytesOut: 180_000_000),
                RouteTrafficEntry(target: .proxy(jp), bytesIn: 400_000_000, bytesOut: 100_000_000),
                RouteTrafficEntry(target: .proxy(de), bytesIn: 120_000_000, bytesOut: 30_000_000),
                RouteTrafficEntry(target: .proxy(fr), bytesIn: 90_000_000, bytesOut: 20_000_000),
                RouteTrafficEntry(target: .proxy(sg), bytesIn: 60_000_000, bytesOut: 10_000_000),
                RouteTrafficEntry(target: .direct, bytesIn: 240_000_000, bytesOut: 40_000_000),
            ],
            name: { target in
                switch target {
                case .direct: return "Direct"
                case .reject: return "Reject"
                case .proxy(let id): return names[id] ?? "Proxy"
                }
            }
        )
        .padding(24)
    }
}
#endif
