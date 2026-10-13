//
//  ConnectionStatsView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/7/26.
//

import SwiftUI
import Charts

struct ConnectionStatsView: View {
    @Environment(ConnectionStats.self) private var connectionStats
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(ChainStore.self) private var chainStore

    private static let tcpConnectionCeiling = Double(TunnelLimits.tcpMaxConnections)
    private static let udpConnectionCeiling = Double(TunnelLimits.udpMaxFlows)
    private static let memoryCeiling: Double = 50 * 1024 * 1024

    @State private var availableWidth: CGFloat?

    private func routeName(_ target: RouteTarget) -> String {
        target.displayName(configStore: configStore, chainStore: chainStore)
    }

    var body: some View {
        ZStack {
            if let availableWidth {
                let rows = rows(availableWidth: availableWidth)
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
                .frame(minWidth: 110, maxWidth: .infinity)
                .environment(\.statCardUnitLength, Self.unitLength(for: availableWidth))
                .animation(.default, value: rows)
            }
        }
        .onGeometryChange(for: CGFloat.self) { proxy in
            proxy.size.width
        } action: { width in
            availableWidth = width
        }
    }

    // MARK: - Card layout

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

    private func rows(availableWidth: CGFloat) -> [[StatUnit]] {
        let units: [StatUnit] = [.upload, .download, .route, .tcp, .udp, .memory, .sleepWake, .dial, .handshake]
        return Self.packRows(units, columns: Self.columnCount(for: availableWidth))
    }
    
    static let maxColumnCount = 4
    
    private static let compactWidthLimit: CGFloat = 330

    private static func columnCount(for width: CGFloat) -> Int {
        guard width > compactWidthLimit else { return 2 }
        return min(maxColumnCount, max(2, StatCardSize.columnCount(fitting: width)))
    }

    private static func unitLength(for width: CGFloat) -> CGFloat {
        guard width > compactWidthLimit else { return width / 2 }
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
                StatValue(Formatting.formatBytes(connectionStats.bytesOut))
                Spacer()
                StatDetailRow(
                    label: "Rate",
                    value: Formatting.formatBytesPerSecond(connectionStats.uploadBytesPerSecond)
                )
            }
        case .download:
            StatCard("Download", systemImage: "arrow.down") {
                StatValue(Formatting.formatBytes(connectionStats.bytesIn))
                Spacer()
                StatDetailRow(
                    label: "Rate",
                    value: Formatting.formatBytesPerSecond(connectionStats.downloadBytesPerSecond)
                )
            }
        case .route:
            RouteBreakdownCard(
                routes: connectionStats.routes,
                name: routeName
            )
        case .tcp:
            NavigationLink {
                TCPConnectionListView()
            } label: {
                StatCard("TCP", systemImage: "arrow.left.arrow.right", hasChevron: true) {
                    StatValue("\(connectionStats.tcpConnectionCount)")
                    Spacer()
                    PressureGauge(
                        value: Double(connectionStats.tcpConnectionCount),
                        ceiling: Self.tcpConnectionCeiling
                    )
                }
            }
            .buttonStyle(.plain)
        case .udp:
            NavigationLink {
                UDPFlowListView()
            } label: {
                StatCard("UDP", systemImage: "arrow.left.and.right", hasChevron: true) {
                    StatValue("\(connectionStats.udpConnectionCount)")
                    Spacer()
                    PressureGauge(
                        value: Double(connectionStats.udpConnectionCount),
                        ceiling: Self.udpConnectionCeiling
                    )
                }
            }
            .buttonStyle(.plain)
        case .memory:
            StatCard("Memory", systemImage: "memorychip") {
                StatValue(Formatting.formatBytes(Int64(connectionStats.memoryBytes)))
                Spacer()
                PressureGauge(
                    value: Double(connectionStats.memoryBytes),
                    ceiling: Self.memoryCeiling
                )
            }
        case .sleepWake:
            SleepWakeCard(
                wakeSeconds: connectionStats.wakeSeconds,
                sleepSeconds: connectionStats.sleepSeconds
            )
        case .dial:
            StatCard("Dial", systemImage: "phone") {
                StatValue(Formatting.formatMilliseconds(connectionStats.dialMs))
                Spacer()
                StatDetailRow(
                    label: "Average",
                    value: Formatting.formatMilliseconds(connectionStats.avgDialMs)
                )
            }
        case .handshake:
            StatCard("Handshake", systemImage: "recordingtape") {
                StatValue(Formatting.formatMilliseconds(connectionStats.handshakeMs))
                Spacer()
                StatDetailRow(
                    label: "Average",
                    value: Formatting.formatMilliseconds(connectionStats.avgHandshakeMs)
                )
            }
        }
    }
}

// MARK: - Card sizing

enum StatCardSize {
    case small
    case medium
    
    static let minUnitLength: CGFloat = 160
    static let maxUnitLength: CGFloat = 200

    static let spacing: CGFloat = 10
    
    static func columnCount(fitting width: CGFloat) -> Int {
        max(1, Int((width + spacing) / (minUnitLength + spacing)))
    }
    
    static func gridWidth(columns: Int, unitLength: CGFloat) -> CGFloat {
        CGFloat(columns) * unitLength + CGFloat(columns - 1) * spacing
    }

    var columnSpan: Int {
        switch self {
        case .small: 1
        case .medium: 2
        }
    }

    func width(unitLength: CGFloat) -> CGFloat {
        Self.gridWidth(columns: columnSpan, unitLength: unitLength)
    }
}

extension EnvironmentValues {
    @Entry var statCardUnitLength: CGFloat = 170
}

// MARK: - StatCard

struct StatCard<Content: View>: View {
    @Environment(\.statCardUnitLength) private var unitLength

    private let titleKey: LocalizedStringKey
    private let systemImage: String
    private let size: StatCardSize
    private let hasChevron: Bool
    private let content: Content

    init(
        _ titleKey: LocalizedStringKey,
        systemImage: String,
        size: StatCardSize = .small,
        hasChevron: Bool = false,
        @ViewBuilder content: () -> Content
    ) {
        self.titleKey = titleKey
        self.systemImage = systemImage
        self.size = size
        self.hasChevron = hasChevron
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label(titleKey, systemImage: systemImage)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                if hasChevron {
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                }
            }
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
            .font(.system(size: 28, weight: .semibold, design: .rounded))
            .lineLimit(1)
            .minimumScaleFactor(0.6)
            .contentTransition(.numericText())
            .animation(.default, value: text)
    }
}

private struct StatDetailRow: View {
    let label: LocalizedStringKey
    let value: String

    var body: some View {
        HStack {
            Text(label)
            Spacer()
            Text(value)
                .contentTransition(.numericText())
                .animation(.default, value: value)
        }
        .foregroundStyle(.secondary)
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
                .foregroundStyle(.secondary)
        }
        .gaugeStyle(AnywhereLinearGaugeStyle())
    }
}

private struct StatCardChrome: ViewModifier {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(AppSettings.self) private var settings

    func body(content: Content) -> some View {
        content
            .contentShape(RoundedRectangle(cornerRadius: 24))
            .background(
                RoundedRectangle(cornerRadius: 24)
                    .fill(background)
            )
    }

    private var background: Color {
        let data = colorScheme == .light
            ? settings.statCardBackgroundLightData
            : settings.statCardBackgroundDarkData
        return data.flatMap(Color.init(archivedData:)) ?? .statCardBackground
    }
}

// MARK: - Donut chart

private struct DonutSegment: Identifiable, Hashable {
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
        .animation(.default, value: segments)
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
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer()
            Text(verbatim: value)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
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
                DonutSegment(
                    id: "wake",
                    value: wakeSeconds + sleepSeconds > 0 ? wakeSeconds : 1,
                    color: Self.wakeColor
                ),
                DonutSegment(
                    id: "sleep",
                    value: sleepSeconds,
                    color: Self.sleepColor
                ),
            ])
            VStack {
                LegendRow(
                    color: Self.wakeColor,
                    label: String(localized: "Wake"),
                    value: Formatting.formatDuration(wakeSeconds)
                )
                LegendRow(
                    color: Self.sleepColor,
                    label: String(localized: "Sleep"),
                    value: Formatting.formatDuration(sleepSeconds)
                )
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
        
        let proxyBudget = Self.maxRows - 1
        let overflow = proxies.count > proxyBudget
        let shownCount = overflow ? proxyBudget - 1 : proxies.count
        let shown: [RouteTrafficEntry] = Array(proxies.prefix(shownCount))

        var rows: [RouteSlice] = []
        for index in shown.indices {
            let proxy = shown[index]
            rows.append(
                RouteSlice(
                    id: proxy.id,
                    label: name(proxy.target),
                    bytes: proxy.totalBytes,
                    color: Self.proxyPalette[index % Self.proxyPalette.count]
                )
            )
        }
        if overflow {
            var otherBytes: Int64 = 0
            for proxy in proxies.dropFirst(shownCount) { otherBytes += proxy.totalBytes }
            rows.append(
                RouteSlice(
                    id: "__other__",
                    label: String(localized: "Other"),
                    bytes: otherBytes,
                    color: Self.otherColor)
            )
        }
        rows.append(
            RouteSlice(
                id: "__direct__",
                label: name(.direct),
                bytes: directBytes,
                color: Self.directColor
            )
        )
        return rows
    }

    var body: some View {
        let slices = makeSlices()
        let total = slices.reduce(0) { $0 + $1.bytes }
        StatCard("Traffic by Route", systemImage: "chart.pie", size: .medium) {
            if slices.count == 1, slices[0].bytes == 0 {
                Text("No Data")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
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
    var color: Color = .blue

    func makeBody(configuration: Configuration) -> some View {
        VStack(alignment: .leading) {
            configuration.label
            GeometryReader { proxy in
                let fraction = min(max(configuration.value, 0), 1)
                let fillWidth = fraction == 0 ? 0 : max(proxy.size.width * fraction, proxy.size.height)
                ZStack(alignment: .leading) {
                    Capsule()
                        .foregroundStyle(.primary.opacity(0.1))
                    Capsule()
                        .foregroundStyle(color)
                        .frame(width: fillWidth)
                        .animation(.default, value: fraction)
                }
            }
            .frame(height: 5)
        }
    }
}

struct AnywhereRingGaugeStyle: GaugeStyle {
    var color: Color = .blue

    func makeBody(configuration: Configuration) -> some View {
        ZStack {
            Circle()
                .stroke(Color.primary.opacity(0.1), lineWidth: 15)

            Circle()
                .trim(from: 0, to: configuration.value)
                .stroke(color,
                        style: StrokeStyle(lineWidth: 15, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.easeOut, value: configuration.value)

            configuration.label
        }
    }
}

#if DEBUG
#Preview {
    ZStack {
        LinearGradient(
            colors: [Color.homeBackgroundStart, Color.homeBackgroundEnd],
            startPoint: .top,
            endPoint: .bottom
        )
        .ignoresSafeArea()
        ScrollView {
            ConnectionStatsView()
                .environment(ConnectionStats.previewSeeded())
                .environment(ConfigurationStore(syncStore: .shared))
                .environment(ChainStore(syncStore: .shared))
                .environment(AppSettings())
                .padding(24)
        }
    }
}

#Preview("Route Breakdown") {
    let us = UUID(), jp = UUID(), de = UUID(), fr = UUID(), sg = UUID()
    let names: [UUID: String] = [
        us: "🇺🇸 Los Angeles",
        jp: "🇯🇵 Tokyo",
        de: "🇩🇪 Frankfurt",
        fr: "🇫🇷 Paris",
        sg: "🇸🇬 Singapore",
    ]
    return ZStack {
        LinearGradient(
            colors: [Color.homeBackgroundStart, Color.homeBackgroundEnd],
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
                case .default: return "Default"
                case .direct: return "Direct"
                case .reject: return "Reject"
                case .defaultProxy: return "Proxy"
                case .proxy(let id): return names[id] ?? "Proxy"
                }
            }
        )
        .environment(AppSettings())
        .padding(24)
    }
}

#Preview("Sleep / Wake") {
    ZStack {
        LinearGradient(
            colors: [Color.homeBackgroundStart, Color.homeBackgroundEnd],
            startPoint: .top,
            endPoint: .bottom
        )
        .ignoresSafeArea()
        SleepWakeCard(wakeSeconds: 3 * 3600 + 24 * 60, sleepSeconds: 47 * 60)
            .environment(AppSettings())
            .padding(24)
    }
}
#endif
