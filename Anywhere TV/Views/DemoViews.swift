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

private let sampleConfigurations: [ProxyConfiguration] = [
    ProxyConfiguration(name: "Tokyo", serverAddress: "jp-tok.example.com", serverPort: 443, uuid: UUID(), encryption: "none", transport: "tcp", flow: "xtls-rprx-vision", security: "reality"),
    ProxyConfiguration(name: "Seoul", serverAddress: "kr.example.com", serverPort: 443, uuid: UUID(), encryption: "none", transport: "ws", security: "tls"),
    ProxyConfiguration(name: "US - New York", serverAddress: "us-ny.example.com", serverPort: 443, uuid: UUID(), encryption: "none", transport: "tcp", flow: "xtls-rprx-vision", security: "reality", subscriptionId: sampleSubscriptionId),
    ProxyConfiguration(name: "US - Los Angeles", serverAddress: "us-la.example.com", serverPort: 443, uuid: UUID(), encryption: "none", transport: "tcp", flow: "xtls-rprx-vision", security: "reality", subscriptionId: sampleSubscriptionId),
    ProxyConfiguration(name: "JP - Tokyo", serverAddress: "jp-tok.example.net", serverPort: 443, uuid: UUID(), encryption: "none", transport: "ws", security: "tls", subscriptionId: sampleSubscriptionId),
    ProxyConfiguration(name: "DE - Frankfurt", serverAddress: "de-fra.example.net", serverPort: 443, uuid: UUID(), encryption: "none", transport: "httpupgrade", security: "tls", subscriptionId: sampleSubscriptionId),
    ProxyConfiguration(name: "SG - Singapore", serverAddress: "sg.example.net", serverPort: 443, uuid: UUID(), encryption: "none", transport: "xhttp", security: "reality", subscriptionId: sampleSubscriptionId),
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

// MARK: - Demo Home View

struct DemoHomeView: View {
    var isConnected = true
    var bytesIn: Int64 = 157_286_400
    var bytesOut: Int64 = 12_582_912
    var configName = "Tokyo"
    var configProtocol = "VLESS"
    var configTransport = "TCP"
    var configSecurity = "REALITY"

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

            VStack(spacing: 0) {
                Spacer()

                // Power button
                ZStack {
                    Circle()
                        .fill(
                            RadialGradient(
                                colors: [isConnected ? .cyan.opacity(0.3) : .clear, .clear],
                                center: .center,
                                startRadius: 80,
                                endRadius: 180
                            )
                        )
                        .frame(width: 400, height: 400)
                        .phaseAnimator([false, true]) { content, phase in
                            content
                                .scaleEffect(phase ? 1.15 : 0.95)
                                .opacity(phase ? 0.5 : 1.0)
                        } animation: { _ in
                            .easeInOut(duration: 2)
                        }

                    Circle()
                        .fill(.white.opacity(0.15))
                        .frame(width: 300, height: 300)
                        .shadow(color: isConnected ? .cyan.opacity(0.5) : .black.opacity(0.1), radius: isConnected ? 40 : 12)

                    Image(systemName: "power")
                        .font(.system(size: 80, weight: .light))
                        .foregroundStyle(isConnected ? .white : .accentColor)
                }
                .padding(.bottom, 20)

                // Status
                Text(isConnected ? "Connected" : "Disconnected")
                    .font(.system(size: 48, weight: .medium))
                    .foregroundStyle(isConnected ? .white : .secondary)
                    .padding(.bottom, isConnected ? 30 : 50)

                // Traffic stats
                if isConnected {
                    HStack(spacing: 80) {
                        statCard(icon: "arrow.up", label: "Upload", value: Self.formatBytes(bytesOut))
                        statCard(icon: "arrow.down", label: "Download", value: Self.formatBytes(bytesIn))
                    }
                    .padding(.bottom, 30)
                }

                // Configuration card
                HStack(spacing: 32) {
                    Image(systemName: "antenna.radiowaves.left.and.right")
                        .resizable()
                        .scaledToFit()
                        .foregroundStyle(isConnected ? .white.opacity(0.7) : .secondary)
                        .frame(width: 48)

                    VStack(alignment: .leading, spacing: 4) {
                        Text(configName)
                            .font(.system(size: 32, weight: .medium))
                            .foregroundStyle(isConnected ? .white : .primary)
                        HStack(spacing: 6) {
                            Text(configProtocol)
                            Text("·")
                            Text(configTransport)
                            Text("·")
                            Text(configSecurity)
                        }
                        .font(.system(size: 28))
                        .foregroundStyle(isConnected ? .white.opacity(0.5) : .secondary)
                    }

                    Spacer()

                    Image(systemName: "chevron.right")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(isConnected ? .white.opacity(0.4) : .secondary.opacity(0.4))
                }
                .padding(24)
                .padding(.horizontal, 200)

                Spacer()
            }
        }
    }

    private func statCard(icon: String, label: String, value: String) -> some View {
        HStack(spacing: 14) {
            Image(systemName: icon)
                .font(.title3.weight(.semibold))
                .foregroundStyle(.white.opacity(0.7))
            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.white.opacity(0.5))
                Text(value)
                    .font(.title3.monospacedDigit().weight(.medium))
                    .foregroundStyle(.white)
            }
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 16)
        .frame(width: 300)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(.white.opacity(0.12))
        )
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

// MARK: - Demo Proxy List View

struct DemoProxyListView: View {
    @State private var showingAddSheet = false

    private let selectedId = sampleConfigurations[0].id

    private var standalone: [ProxyConfiguration] {
        sampleConfigurations.filter { $0.subscriptionId == nil }
    }

    private var subscriptionConfigs: [ProxyConfiguration] {
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
                    }
                }
            }
            .navigationTitle("Proxies")
            .toolbar {
                ToolbarItem {
                    Button {} label: {
                        Image(systemName: "gauge.with.dots.needle.67percent")
                            .accessibilityLabel("Test All")
                    }
                }
                ToolbarItem {
                    Button {
                        showingAddSheet = true
                    } label: {
                        Image(systemName: "plus")
                            .accessibilityLabel("Add")
                    }
                }
            }
            .sheet(isPresented: $showingAddSheet) {
                NavigationStack {
                    AddProxyView { _ in } onSubscriptionImport: { _, _ in }
                }
            }
        }
    }

    @ViewBuilder
    private func configRow(_ config: ProxyConfiguration) -> some View {
        let latency = sampleLatencyResults[config.id]

        HStack {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
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
                    .lineLimit(1)
                HStack(spacing: 4) {
                    Text(config.outboundProtocol.name)
                    Text("·")
                    Text(config.transport.uppercased())
                    Text("·")
                    Text(config.security.uppercased())
                    if let flow = config.flow, flow.uppercased().contains("VISION") {
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
                .frame(width: 80, alignment: .trailing)
        case .success(let ms):
            Text("\(ms) ms")
                .font(.callout)
                .monospacedDigit()
                .foregroundStyle(latencyColor(ms))
                .frame(minWidth: 80, alignment: .trailing)
        case .failed:
            Text("timeout")
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(minWidth: 80, alignment: .trailing)
        case .insecure:
            Text("insecure")
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(minWidth: 80, alignment: .trailing)
        case nil:
            EmptyView()
        }
    }

    private func latencyColor(_ ms: Int) -> Color {
        if ms < 300 { return .green }
        if ms < 500 { return .yellow }
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
