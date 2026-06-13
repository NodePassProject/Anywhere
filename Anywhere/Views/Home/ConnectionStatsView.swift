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

    private static let tcpConnectionCeiling: Double = 256
    private static let udpConnectionCeiling: Double = 256
    private static let memoryCeiling: Double = 50 * 1024 * 1024

    @State private var availableWidth: CGFloat = 330

    private func routeName(_ target: RouteTarget) -> String {
        target.displayName(configStore: configStore, chainStore: chainStore)
    }

    var body: some View {
        Grid(horizontalSpacing: StatCardSize.spacing, verticalSpacing: StatCardSize.spacing) {
            ForEach(rows, id: \.self) { row in
                GridRow {
                    ForEach(row, id: \.self) { unit in
                        card(for: unit)
                            .gridCellColumns(unit.size.columnSpan)
                    }
                }
            }
        }
        .frame(minWidth: 350, maxWidth: .infinity)
        .environment(\.statCardUnitLength, Self.unitLength(for: availableWidth))
        .onGeometryChange(for: CGFloat.self) { proxy in
            proxy.size.width
        } action: { width in
            availableWidth = width
        }
    }

    // MARK: - Card layout

    /// One case per card; `size` is the card's grid footprint.
    private enum StatUnit: Hashable {
        case upload
        case download
        case route
        case tcp
        case udp
        case memory
        case sleepWake
        case dial
        case handshake

        var size: StatCardSize {
            switch self {
            case .route: .medium
            default: .small
            }
        }
    }

    private var rows: [[StatUnit]] {
        var units: [StatUnit] = [.upload, .download]
        if stats.bytesOut > 0 || stats.bytesIn > 0 {
            units.append(.route)
        }
        units += [.tcp, .udp, .memory, .sleepWake, .dial, .handshake]
        return Self.packRows(units, columns: Self.columnCount(for: availableWidth))
    }

    private static func columnCount(for width: CGFloat) -> Int {
        max(2, Int((width + StatCardSize.spacing) / (StatCardSize.minUnitLength + StatCardSize.spacing)))
    }
    
    private static func unitLength(for width: CGFloat) -> CGFloat {
        let columns = columnCount(for: width)
        let unit = (width - CGFloat(columns - 1) * StatCardSize.spacing) / CGFloat(columns)
        return min(max(unit, StatCardSize.minUnitLength), StatCardSize.maxUnitLength)
    }

    private static func packRows(_ units: [StatUnit], columns: Int) -> [[StatUnit]] {
        var pending = units
        var rows: [[StatUnit]] = []
        while !pending.isEmpty {
            var row: [StatUnit] = []
            var used = 0
            var candidate = 0
            while candidate < pending.count {
                let unit = pending[candidate]
                if used + unit.size.columnSpan <= columns || row.isEmpty {
                    used += unit.size.columnSpan
                    row.append(unit)
                    pending.remove(at: candidate)
                } else {
                    candidate += 1
                }
            }
            rows.append(row)
        }
        return rows
    }

    @ViewBuilder
    private func card(for unit: StatUnit) -> some View {
        switch unit {
        case .upload:
            StatCard("Upload", systemImage: "arrow.up") {
                StatValue(Self.formatBytes(stats.bytesOut))
                Spacer()
                StatDetailRow(label: "Rate", value: Self.formatBytesPerSecond(stats.uploadBytesPerSecond))
            }
        case .download:
            StatCard("Download", systemImage: "arrow.down") {
                StatValue(Self.formatBytes(stats.bytesIn))
                Spacer()
                StatDetailRow(label: "Rate", value: Self.formatBytesPerSecond(stats.downloadBytesPerSecond))
            }
        case .route:
            RouteBreakdownCard(
                routes: stats.routes,
                name: routeName
            )
        case .tcp:
            StatCard("TCP", systemImage: "arrow.left.arrow.right") {
                StatValue("\(stats.tcpConnectionCount)")
                Spacer()
                PressureGauge(value: Double(stats.tcpConnectionCount), ceiling: Self.tcpConnectionCeiling)
            }
        case .udp:
            StatCard("UDP", systemImage: "arrow.left.and.right") {
                StatValue("\(stats.udpConnectionCount)")
                Spacer()
                PressureGauge(value: Double(stats.udpConnectionCount), ceiling: Self.udpConnectionCeiling)
            }
        case .memory:
            StatCard("Memory", systemImage: "memorychip") {
                StatValue(Self.formatBytes(Int64(stats.memoryBytes)))
                Spacer()
                PressureGauge(value: Double(stats.memoryBytes), ceiling: Self.memoryCeiling)
            }
        case .sleepWake:
            SleepWakeCard(wakeSeconds: stats.wakeSeconds, sleepSeconds: stats.sleepSeconds)
        case .dial:
            StatCard("Dial", systemImage: "phone") {
                StatValue(Self.formatMilliseconds(stats.dialMs))
                Spacer()
                StatDetailRow(label: "Average", value: Self.formatMilliseconds(stats.avgDialMs))
            }
        case .handshake:
            StatCard("Handshake", systemImage: "recordingtape") {
                StatValue(Self.formatMilliseconds(stats.handshakeMs))
                Spacer()
                StatDetailRow(label: "Average", value: Self.formatMilliseconds(stats.avgHandshakeMs))
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

    private static func formatBytesPerSecond(_ bytesPerSecond: Int64?) -> String {
        guard let bytesPerSecond else { return "—" }
        return String(localized: "\(byteFormatter.string(fromByteCount: bytesPerSecond))/s")
    }

    private static func formatMilliseconds(_ ms: Int?) -> String {
        guard let ms else { return "—" }
        return "\(ms) ms"
    }

    fileprivate static func formatDuration(_ seconds: TimeInterval) -> String {
        Duration.seconds(seconds).formatted(
            .units(allowed: [.hours, .minutes, .seconds], width: .narrow, maximumUnitCount: 2)
        )
    }
}

// MARK: - Card sizing

/// Grid footprint of a stat card: `small` is 1×1, `medium` is 2×1.
enum StatCardSize {
    case small
    case medium
    
    static let minUnitLength: CGFloat = 160
    static let maxUnitLength: CGFloat = 200
    
    static let spacing: CGFloat = 10

    var columnSpan: Int {
        switch self {
        case .small: 1
        case .medium: 2
        }
    }

    func width(unitLength: CGFloat) -> CGFloat {
        CGFloat(columnSpan) * unitLength + CGFloat(columnSpan - 1) * Self.spacing
    }
}

extension EnvironmentValues {
    /// Edge of a 1×1 stat card, set by `ConnectionStatsView` from the measured
    /// width.
    @Entry var statCardUnitLength: CGFloat = 170
}

// MARK: - StatCard

struct StatCard<Content: View>: View {
    @Environment(\.statCardUnitLength) private var unitLength

    private let titleKey: LocalizedStringKey
    private let systemImage: String
    private let size: StatCardSize
    private let content: Content

    init(
        _ titleKey: LocalizedStringKey,
        systemImage: String,
        size: StatCardSize = .small,
        @ViewBuilder content: () -> Content
    ) {
        self.titleKey = titleKey
        self.systemImage = systemImage
        self.size = size
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(titleKey, systemImage: systemImage)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.white.opacity(0.7))
            content
        }
        .padding()
        .frame(width: size.width(unitLength: unitLength), height: unitLength, alignment: .topLeading)
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
            .font(.system(size: 28, design: .rounded))
            .foregroundStyle(.white)
            .lineLimit(1)
            .minimumScaleFactor(0.6)
            .contentTransition(.numericText())
            .animation(.default, value: text)
    }
}

/// Caption row under a `StatValue`: dimmed label, animated trailing value.
private struct StatDetailRow: View {
    let label: LocalizedStringKey
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .foregroundStyle(.white.opacity(0.6))
            Spacer()
            Text(value)
                .foregroundStyle(.white)
                .contentTransition(.numericText())
                .animation(.default, value: value)
        }
        .font(.system(size: 14))
    }
}

private struct PressureGauge: View {
    let value: Double
    let ceiling: Double

    var body: some View {
        Gauge(value: value, in: 0...ceiling) {
            Text("Pressure")
                .font(.system(size: 14))
                .foregroundStyle(.white.opacity(0.6))
        }
        .gaugeStyle(AnywhereLinearGaugeStyle())
    }
}

private struct StatCardChrome: ViewModifier {
    func body(content: Content) -> some View {
        content
            .contentShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(.white.opacity(0.1))
            )
    }
}

// MARK: - Donut chart

private struct DonutSegment: Identifiable {
    let id: String
    let value: Double
    let color: Color
}

private struct DonutChart: View {
    let segments: [DonutSegment]

    var body: some View {
        Chart(segments) { segment in
            SectorMark(
                angle: .value("Value", segment.value),
                innerRadius: .ratio(0.62),
                angularInset: 1.5
            )
            .cornerRadius(3)
            .foregroundStyle(segment.color)
        }
        .chartLegend(.hidden)
    }
}

private struct LegendRow: View {
    let color: Color
    let label: String
    let value: String

    var body: some View {
        HStack {
            Circle()
                .fill(color)
                .frame(width: 10, height: 10)
            Text(verbatim: label)
                .font(.caption.weight(.medium))
                .foregroundStyle(.white.opacity(0.85))
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            Text(verbatim: value)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.white.opacity(0.6))
                .monospacedDigit()
        }
    }
}

// MARK: - Sleep / Wake

private struct SleepWakeCard: View {
    let wakeSeconds: TimeInterval
    let sleepSeconds: TimeInterval

    private static let wakeColor: Color = .cyan
    private static let sleepColor: Color = .indigo

    var body: some View {
        StatCard("Caffeine", systemImage: "cup.and.heat.waves") {
            DonutChart(segments: [
                DonutSegment(id: "wake",
                             value: wakeSeconds + sleepSeconds > 0 ? wakeSeconds : 1,
                             color: Self.wakeColor),
                DonutSegment(id: "sleep", value: sleepSeconds, color: Self.sleepColor),
            ])
            VStack {
                LegendRow(color: Self.wakeColor,
                          label: String(localized: "Wake"),
                          value: ConnectionStatsView.formatDuration(wakeSeconds))
                LegendRow(color: Self.sleepColor,
                          label: String(localized: "Sleep"),
                          value: ConnectionStatsView.formatDuration(sleepSeconds))
            }
        }
    }
}

// MARK: - Route Breakdown

private struct RouteSlice: Identifiable {
    let id: String
    let label: String
    let bytes: Int64
    let color: Color
}

private struct RouteBreakdownCard: View {
    let routes: [RouteTrafficEntry]
    let name: (RouteTarget) -> String

    private static let proxyPalette: [Color] =
    [.cyan, .orange, .purple, .pink, .yellow, .mint, .indigo, .teal]
    private static let directColor: Color = .green
    private static let otherColor: Color = .gray

    private static let maxRows = 5

    private func makeSlices() -> [RouteSlice] {
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

        var rows: [RouteSlice] = []
        for index in shown.indices {
            let proxy = shown[index]
            rows.append(RouteSlice(
                id: proxy.id,
                label: name(proxy.target),
                bytes: proxy.totalBytes,
                color: Self.proxyPalette[index % Self.proxyPalette.count]
            ))
        }
        if overflow {
            var otherBytes: Int64 = 0
            for proxy in proxies.dropFirst(shownCount) { otherBytes += proxy.totalBytes }
            rows.append(RouteSlice(id: "__other__", label: String(localized: "Other"),
                                   bytes: otherBytes, color: Self.otherColor))
        }
        rows.append(RouteSlice(id: "__direct__", label: name(.direct),
                               bytes: directBytes, color: Self.directColor))
        return rows
    }

    var body: some View {
        let slices = makeSlices()
        let total = slices.reduce(0) { $0 + $1.bytes }
        StatCard("Traffic by Route", systemImage: "chart.pie", size: .medium) {
            HStack(spacing: 18) {
                DonutChart(segments: slices.map {
                    DonutSegment(id: $0.id, value: Double($0.bytes), color: $0.color)
                })
                .frame(maxWidth: .infinity)
                RouteLegend(slices: slices, total: total)
                    .frame(maxWidth: .infinity)
            }
        }
    }
}

private struct RouteLegend: View {
    let slices: [RouteSlice]
    let total: Int64

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(slices) { slice in
                LegendRow(
                    color: slice.color,
                    label: slice.label,
                    value: (total > 0 ? Double(slice.bytes) / Double(total) : 0)
                        .formatted(.percent.precision(.fractionLength(0)))
                )
            }
        }
    }
}

// MARK: - Gauge style

struct AnywhereLinearGaugeStyle: GaugeStyle {
    var color: Color = .cyan

    func makeBody(configuration: Configuration) -> some View {
        VStack(alignment: .leading) {
            configuration.label
                .foregroundStyle(.white)
            GeometryReader { proxy in
                let fraction = min(max(configuration.value, 0), 1)
                let fillWidth = fraction == 0 ? 0 : max(proxy.size.width * fraction, proxy.size.height)
                ZStack(alignment: .leading) {
                    Capsule()
                        .foregroundStyle(.white.opacity(0.2))
                    Capsule()
                        .foregroundStyle(color)
                        .frame(width: fillWidth)
                        .animation(.default, value: fraction)
                }
            }
            .frame(height: 10)
        }
    }
}

struct AnywhereRingGaugeStyle: GaugeStyle {
    var color: Color = .cyan

    func makeBody(configuration: Configuration) -> some View {
        ZStack {
            Circle()
                .stroke(Color.white.opacity(0.2), lineWidth: 15)

            Circle()
                .trim(from: 0, to: configuration.value)
                .stroke(color,
                        style: StrokeStyle(lineWidth: 15, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.easeOut, value: configuration.value)

            configuration.label
                .foregroundStyle(.white)
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
        ScrollView {
            ConnectionStatsView()
                .environment(ConnectionStatsModel.previewSeeded())
                .environment(ConfigurationStore.shared)
                .environment(ChainStore.shared)
                .padding(24)
        }
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

#Preview("Sleep / Wake") {
    ZStack {
        LinearGradient(
            colors: [Color.connectedBackgroundStart, Color.connectedBackgroundEnd],
            startPoint: .top,
            endPoint: .bottom
        )
        .ignoresSafeArea()
        SleepWakeCard(wakeSeconds: 3 * 3600 + 24 * 60, sleepSeconds: 47 * 60)
            .padding(24)
    }
}
#endif
