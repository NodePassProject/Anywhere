//
//  DemoViews.swift
//  Anywhere
//
//  Demo views for Xcode Previews. Self-contained with mock data,
//  no dependency on VPNViewModel or persistent stores.
//

#if DEBUG

import SwiftUI

// MARK: - Sample Data

private let sampleSubscriptionId = UUID()

private let sampleConfigurations: [VLESSConfiguration] = [
    VLESSConfiguration(name: "Tokyo", serverAddress: "jp-tok.example.com", serverPort: 443, uuid: UUID(), encryption: "none", transport: "tcp", flow: "xtls-rprx-vision", security: "reality"),
    VLESSConfiguration(name: "Seoul", serverAddress: "kr.example.com", serverPort: 443, uuid: UUID(), encryption: "none", transport: "ws", security: "tls"),
    VLESSConfiguration(name: "US - New York", serverAddress: "us-ny.example.com", serverPort: 443, uuid: UUID(), encryption: "none", transport: "tcp", flow: "xtls-rprx-vision", security: "reality", subscriptionId: sampleSubscriptionId),
    VLESSConfiguration(name: "US - Los Angeles", serverAddress: "us-la.example.com", serverPort: 443, uuid: UUID(), encryption: "none", transport: "tcp", flow: "xtls-rprx-vision", security: "reality", subscriptionId: sampleSubscriptionId),
    VLESSConfiguration(name: "JP - Tokyo", serverAddress: "jp-tok.example.net", serverPort: 443, uuid: UUID(), encryption: "none", transport: "ws", security: "tls", subscriptionId: sampleSubscriptionId),
    VLESSConfiguration(name: "DE - Frankfurt", serverAddress: "de-fra.example.net", serverPort: 443, uuid: UUID(), encryption: "none", transport: "httpupgrade", security: "tls", subscriptionId: sampleSubscriptionId),
    VLESSConfiguration(name: "SG - Singapore", serverAddress: "sg.example.net", serverPort: 443, uuid: UUID(), encryption: "none", transport: "xhttp", security: "reality", subscriptionId: sampleSubscriptionId),
]

private let sampleSubscription = Subscription(
    id: sampleSubscriptionId,
    name: "Subscription",
    url: "https://example.com/subscribe"
)

private let sampleLatencyResults: [UUID: LatencyResult] = [
    sampleConfigurations[0].id: .success(85),
    sampleConfigurations[1].id: .success(142),
    sampleConfigurations[2].id: .success(210),
    sampleConfigurations[3].id: .success(450),
    sampleConfigurations[4].id: .success(620),
    sampleConfigurations[5].id: .failed,
    sampleConfigurations[6].id: .testing,
]

// MARK: - Demo Home View (Connected with Traffic Stats)

struct DemoHomeView: View {
    var isConnected = true
    var bytesIn: Int64 = 157_286_400
    var bytesOut: Int64 = 12_582_912
    var configName = "Tokyo"

    var body: some View {
        ZStack {
            LinearGradient(
                colors: isConnected
                    ? [Color("GradientStart"), Color("GradientEnd")]
                    : [Color("GradientDisconnectedStart"), Color("GradientDisconnectedEnd")],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            GeometryReader { geometry in
                ScrollView {
                    VStack(spacing: 0) {
                        Spacer()

                        // Power button
                        ZStack {
                            Circle()
                                .fill(
                                    RadialGradient(
                                        colors: [isConnected ? .cyan.opacity(0.25) : .clear, .clear],
                                        center: .center,
                                        startRadius: 50,
                                        endRadius: 110
                                    )
                                )
                                .frame(width: 200, height: 200)
                                .phaseAnimator([false, true]) { content, phase in
                                    content
                                        .scaleEffect(phase ? 1.15 : 0.95)
                                        .opacity(phase ? 0.5 : 1.0)
                                } animation: { _ in
                                    .easeInOut(duration: 2)
                                }

                            if #available(iOS 26.0, *) {
                                Circle()
                                    .fill(.clear)
                                    .frame(width: 140, height: 140)
                                    .glassEffect(.clear, in: .circle)
                                    .shadow(color: isConnected ? .cyan.opacity(0.4) : .black.opacity(0.08), radius: isConnected ? 24 : 8)
                            } else {
                                Circle()
                                    .fill(.regularMaterial)
                                    .frame(width: 140, height: 140)
                                    .shadow(color: isConnected ? .cyan.opacity(0.4) : .black.opacity(0.08), radius: isConnected ? 24 : 8)
                            }

                            Image(systemName: "power")
                                .font(.system(size: 44, weight: .light))
                                .foregroundStyle(isConnected ? .white : .accentColor)
                        }
                        .padding(.bottom, 16)

                        // Status
                        Text(isConnected ? "Connected" : "Disconnected")
                            .font(.title3.weight(.medium))
                            .foregroundStyle(isConnected ? .white : .secondary)
                            .padding(.bottom, isConnected ? 20 : 40)

                        // Traffic stats
                        if isConnected {
                            cardContent {
                                HStack {
                                    HStack(spacing: 6) {
                                        Image(systemName: "arrow.up")
                                            .font(.caption.weight(.semibold))
                                            .foregroundStyle(.white.opacity(0.7))
                                        Text(Self.formatBytes(bytesOut))
                                            .font(.callout.monospacedDigit())
                                            .foregroundStyle(.white)
                                    }
                                    Spacer()
                                    HStack(spacing: 6) {
                                        Image(systemName: "arrow.down")
                                            .font(.caption.weight(.semibold))
                                            .foregroundStyle(.white.opacity(0.7))
                                        Text(Self.formatBytes(bytesIn))
                                            .font(.callout.monospacedDigit())
                                            .foregroundStyle(.white)
                                    }
                                }
                            }
                            .padding(.horizontal, 24)
                            .padding(.bottom, 20)
                        }

                        // Configuration card
                        cardContent {
                            VStack(spacing: 12) {
                                HStack {
                                    Image(systemName: "antenna.radiowaves.left.and.right")
                                        .foregroundStyle(isConnected ? .white.opacity(0.7) : .secondary)
                                        .frame(width: 24)
                                    Text(configName)
                                        .font(.body.weight(.medium))
                                        .foregroundStyle(isConnected ? .white : .primary)
                                    Spacer()
                                    Image(systemName: "chevron.up.chevron.down")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(isConnected ? Color.white.opacity(0.4) : Color.secondary.opacity(0.4))
                                }
                            }
                        }
                        .padding(.horizontal, 24)

                        Spacer()
                    }
                    .frame(minHeight: geometry.size.height)
                }
            }
        }
    }

    @ViewBuilder
    private func cardContent<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        if #available(iOS 26.0, *) {
            content()
                .padding(16)
                .contentShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                .glassEffect(.clear.interactive(), in: .rect(cornerRadius: 16))
        } else {
            content()
                .padding(16)
                .contentShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                .background(
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(.regularMaterial)
                )
        }
    }

    private static let byteFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        return formatter
    }()

    private static func formatBytes(_ bytes: Int64) -> String {
        byteFormatter.string(fromByteCount: bytes)
    }
}

// MARK: - Demo Proxy List View (Servers with Latency)

struct DemoProxyListView: View {
    @State private var showingAddSheet = false
    @State private var showingManualAddSheet = false
    
    private let selectedId = sampleConfigurations[0].id

    private var standalone: [VLESSConfiguration] {
        sampleConfigurations.filter { $0.subscriptionId == nil }
    }

    private var subscriptionConfigs: [VLESSConfiguration] {
        sampleConfigurations.filter { $0.subscriptionId == sampleSubscriptionId }
    }

    var body: some View {
        NavigationStack {
            List {
                if !standalone.isEmpty {
                    Section {
                        ForEach(standalone) { config in
                            configRow(config)
                        }
                    }
                }
                Section {
                    ForEach(subscriptionConfigs) { config in
                        configRow(config)
                    }
                } header: {
                    HStack {
                        Text(sampleSubscription.name)
                        Spacer()
                        Image(systemName: "arrow.clockwise")
                            .foregroundStyle(.secondary)
                        Image(systemName: "ellipsis.circle")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Proxies")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    HStack(spacing: 12) {
                        Button {} label: {
                            Label("Test All", systemImage: "gauge.with.dots.needle.67percent")
                        }
                        
                        Button {
                            showingAddSheet = true
                        } label: {
                            Label("Add", systemImage: "plus")
                        }
                    }
                }
            }
            .sheet(isPresented: $showingAddSheet) {
                DynamicSheet(animation: .snappy(duration: 0.3, extraBounce: 0)) {
                    AddProxyView(showingManualAddSheet: $showingManualAddSheet) { _ in } onSubscriptionImport: { _, _ in }
                }
            }
            .sheet(isPresented: $showingManualAddSheet) {
                ProxyEditorView { _ in }
            }
        }
    }

    @ViewBuilder
    private func configRow(_ config: VLESSConfiguration) -> some View {
        let latency = sampleLatencyResults[config.id]

        HStack {
            VStack(alignment: .leading, spacing: 2) {
                HStack {
                    Text(config.name)
                        .font(.body)
                    if config.id == selectedId {
                        Image(systemName: "checkmark")
                            .font(.caption.bold())
                            .foregroundStyle(.tint)
                    }
                }
                Text("\(config.serverAddress):\(config.serverPort, format: .number.grouping(.never))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack(spacing: 4) {
                    Text(config.transport.uppercased())
                    Text("·")
                    Text(config.security.uppercased())
                    if let flow = config.flow, flow.contains("vision") {
                        Text("·")
                        Text("Vision")
                    }
                }
                .font(.caption2)
                .foregroundStyle(.tertiary)
            }

            Spacer()

            latencyView(latency)
        }
    }

    @ViewBuilder
    private func latencyView(_ latency: LatencyResult?) -> some View {
        switch latency {
        case .testing:
            ProgressView()
                .controlSize(.small)
                .frame(width: 50, alignment: .trailing)
        case .success(let ms):
            Text("\(ms) ms")
                .font(.caption)
                .monospacedDigit()
                .foregroundStyle(latencyColor(ms))
                .frame(minWidth: 50, alignment: .trailing)
        case .failed:
            Text("timeout")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(minWidth: 50, alignment: .trailing)
        case nil:
            EmptyView()
        }
    }

    private func latencyColor(_ ms: Int) -> Color {
        if ms < 300 { return .green }
        if ms < 600 { return .yellow }
        return .red
    }
}

// MARK: - Previews

#Preview("Home - Connected") {
    DemoHomeView(isConnected: true)
}

#Preview("Home - Disconnected") {
    DemoHomeView(isConnected: false)
}

#Preview("Proxy List") {
    DemoProxyListView()
}

#endif
