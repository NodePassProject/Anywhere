//
//  HomeView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI
import NetworkExtension

struct HomeView: View {
    @Environment(AppSettings.self) private var settings
    @Environment(TunnelController.self) private var tunnel
    @Environment(ProxySelection.self) private var selection
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(SubscriptionStore.self) private var subscriptionStore
    
    private static let horizontalPadding: CGFloat = 20
    private static let paneSpacing: CGFloat = 20
    private static let minControlPaneWidth: CGFloat = 320
    private static let maxControlPaneWidth: CGFloat = 500

    @Namespace private var namespace

    @State private var containerSize = CGSize.zero
    
    @State private var connectionEffectsEnabled = false
    
    @State private var showingProxiesSheet = false
    @State private var showingAddSheet = false
    @State private var showingManualAddSheet = false
    @State private var showingSettingsSheet = false

    private var isLoading: Bool { !configStore.isLoaded }

    private var isConnected: Bool {
        tunnel.rawStatus == .connected
    }

    private var isTransitioning: Bool { tunnel.rawStatus.isTransitioning }

    var body: some View {
        ZStack {
            BackgroundGradient(isConnected: isConnected)
                .ignoresSafeArea()

            Group {
                if isConnected && Self.allowsSideBySide(contentWidth: contentWidth) {
                    sideBySideLayout
                } else {
                    stackedLayout
                }
            }
            .animation(connectionEffectsEnabled ? Animation.bouncy : nil, value: isConnected)
            .sensoryFeedback(trigger: isConnected) { _, _ in
                guard connectionEffectsEnabled else { return nil }
                return .impact
            }
        }
        .colorScheme(settings.homeColorScheme.colorSceme)
        .onGeometryChange(for: CGSize.self) { proxy in
            proxy.size
        } action: { size in
            containerSize = size
        }
        .sheet(isPresented: $showingProxiesSheet) {
            NavigationStack {
                ProxiesPageView()
            }
        }
        .sheet(isPresented: $showingAddSheet) {
            DynamicSheet(animation: .snappy(duration: 0.3, extraBounce: 0)) {
                AddProxyView(showingManualAddSheet: $showingManualAddSheet)
            }
        }
        .sheet(isPresented: $showingManualAddSheet) {
            ProxyEditorView { configuration in
                configStore.add(configuration); selection.selectIfNone(configuration)
            }
        }
        .sheet(isPresented: $showingSettingsSheet) {
            NavigationStack {
                SettingsView()
            }
        }
        .alert("VPN Error", isPresented: Binding(
            get: { tunnel.startError != nil },
            set: { if !$0 { tunnel.startError = nil } }
        )) {
            Button("OK") { tunnel.startError = nil }
        } message: {
            Text(tunnel.startError ?? "")
        }
        .onChange(of: tunnel.isManagerReady, initial: true) { _, ready in
            guard ready, !connectionEffectsEnabled else { return }
            Task { @MainActor in connectionEffectsEnabled = true }
        }
    }

    // MARK: - Layouts

    private var contentWidth: CGFloat {
        containerSize.width - 2 * Self.horizontalPadding
    }

    private static func allowsSideBySide(contentWidth: CGFloat) -> Bool {
        StatCardSize.columnCount(fitting: contentWidth) > ConnectionStatsView.maxColumnCount
    }

    private var stackedLayout: some View {
        DetailRevealScrollView(revealsDetail: isConnected) {
            connectionControls
                .padding(.horizontal, Self.horizontalPadding)
        } detail: {
            ConnectionStatsView()
                .padding(.top, 16)
                .padding(.horizontal, Self.horizontalPadding)
        }
    }
    
    private var sideBySideLayout: some View {
        // Give the stats pane what a fully grown grid needs, but never squeeze
        // the controls pane below its minimum width.
        let detailWidth = min(
            StatCardSize.gridWidth(
                columns: ConnectionStatsView.maxColumnCount,
                unitLength: StatCardSize.maxUnitLength
            ),
            contentWidth - Self.minControlPaneWidth - Self.paneSpacing
        )
        return HStack(spacing: Self.paneSpacing) {
            ScrollView {
                connectionControls
                    .frame(maxWidth: .infinity, minHeight: containerSize.height)
            }
            .scrollBounceBehavior(.basedOnSize, axes: .vertical)

            ScrollView {
                ConnectionStatsView()
                    .padding(.vertical, 16)
                    .frame(minHeight: containerSize.height)
            }
            .frame(width: detailWidth)
            .scrollBounceBehavior(.basedOnSize, axes: .vertical)
            .transition(.move(edge: .trailing).combined(with: .opacity))
        }
        .frame(maxWidth: Self.maxControlPaneWidth + Self.paneSpacing + detailWidth)
        .frame(maxWidth: .infinity)
        .padding(.horizontal, Self.horizontalPadding)
    }

    private var connectionControls: some View {
        VStack(spacing: 80) {
            VStack(spacing: 20) {
                powerButton
                    .matchedGeometryEffect(id: "powerButton", in: namespace)
                statusLabel
                    .matchedGeometryEffect(id: "statusLabel", in: namespace)
            }
            HStack {
                configurationCard
                    .matchedGeometryEffect(id: "configurationCard", in: namespace)
                settingsButton
                    .matchedGeometryEffect(id: "settingsButton", in: namespace)
            }
            .frame(maxWidth: Self.maxControlPaneWidth)
        }
    }

    private var powerButton: some View {
        PowerButton(
            isConnected: isConnected,
            isTransitioning: isTransitioning,
            isLoading: isLoading,
            isDisabled: isLoading
                || ((!tunnel.isManagerReady || isTransitioning)
                    && configStore.hasConfigurations),
            animatesChanges: connectionEffectsEnabled
        ) {
            guard !isLoading else { return }
            if configStore.hasConfigurations {
                withAnimation(.spring(response: 0.5, dampingFraction: 0.7)) {
                    tunnel.toggle()
                }
            } else {
                showingAddSheet = true
            }
        }
    }

    private var configurationCard: some View {
        ConfigurationCapsule(
            isConnected: isConnected,
            showingProxiesSheet: $showingProxiesSheet,
            showingAddSheet: $showingAddSheet
        )
    }
    
    private var statusLabel: some View {
        Text(tunnel.status.localizedText)
            .font(.headline)
            .foregroundStyle(.secondary)
    }
    
    private var settingsButton: some View {
        Button {
            showingSettingsSheet = true
        } label: {
            ProminentCircle {
                Image(systemName: "gearshape.fill")
                    .accessibilityLabel("Settings")
            }
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Background

private struct BackgroundGradient: View {
    @Environment(AppSettings.self) private var settings

    let isConnected: Bool

    var body: some View {
        if isConnected {
            LinearGradient(
                colors: [
                    color(settings.connectedBackgroundStartData, default: .connectedBackgroundStart),
                    color(settings.connectedBackgroundEndData, default: .connectedBackgroundEnd),
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .transition(.blurReplace)
        } else {
            LinearGradient(
                colors: [
                    color(settings.disconnectedBackgroundStartData, default: .disconnectedBackgroundStart),
                    color(settings.disconnectedBackgroundEndData, default: .disconnectedBackgroundEnd),
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .transition(.blurReplace)
        }
    }

    private func color(_ data: Data?, default fallback: Color) -> Color {
        data.flatMap(Color.init(archivedData:)) ?? fallback
    }
}

// MARK: - Power Button

private struct PowerButton: View {
    private static let circleDiameter: CGFloat = 140

    let isConnected: Bool
    let isTransitioning: Bool
    let isLoading: Bool
    let isDisabled: Bool
    let animatesChanges: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            ZStack {
                if #available(iOS 27.0, *) {
                    Circle()
                        .fill(.clear)
                        .frame(width: Self.circleDiameter)
                        .glassEffect(.regular, in: .circle)
                } else if #available(iOS 26.0, *) {
                    Circle()
                        .fill(.clear)
                        .frame(width: Self.circleDiameter)
                        .glassEffect(.clear, in: .circle)
                } else {
                    Circle()
                        .fill(.white.opacity(0.2))
                        .frame(width: Self.circleDiameter)
                        .shadow(color: isConnected ? .cyan.opacity(0.4) : .black.opacity(0.08), radius: isConnected ? 24 : 8)
                }
                if isTransitioning || isLoading {
                    ProgressView()
                        .controlSize(.large)
                } else {
                    Image(systemName: "power")
                        .font(.system(size: 40, weight: .light))
                }
            }
            .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .disabled(isDisabled)
        .animation(animatesChanges ? Animation.easeInOut(duration: 0.6) : nil, value: isConnected)
    }
}

// MARK: - Configuration Capsule

private struct ConfigurationCapsule: View {
    @Environment(ProxySelection.self) private var selection
    @Environment(ConfigurationStore.self) private var configStore

    let isConnected: Bool
    @Binding var showingProxiesSheet: Bool
    @Binding var showingAddSheet: Bool

    var body: some View {
        if let configuration = selection.selectedConfiguration {
            selectedCapsule(configuration)
        } else if configStore.isLoaded {
            emptyCapsule
        } else {
            loadingCapsule
        }
    }

    private func selectedCapsule(_ configuration: ProxyConfiguration) -> some View {
        Button {
            showingProxiesSheet = true
        } label: {
            ProminentCapsule {
                HStack {
                    Image("anywhere")
                        .foregroundStyle(.primary.opacity(0.7))
                        .frame(width: 24)
                    Text(configuration.name)
                        .font(.body.weight(.medium))
                        .lineLimit(1)
                    Spacer()
                    Image(systemName: "chevron.up.chevron.down")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.primary.opacity(0.7))
                }
            }
        }
        .buttonStyle(.plain)
    }

    private var emptyCapsule: some View {
        Button {
            showingAddSheet = true
        } label: {
            ProminentCapsule {
                HStack(spacing: 12) {
                    Image(systemName: "plus.circle.fill")
                        .font(.title2)
                        .foregroundStyle(.tint)
                    Text("Add a Configuration")
                        .font(.body.weight(.medium))
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .buttonStyle(.plain)
    }
    
    private var loadingCapsule: some View {
        ProminentCapsule {
            HStack(spacing: 12) {
                ProgressView()
                Text("Loading…")
                    .font(.body.weight(.medium))
                    .foregroundStyle(.secondary)
                Spacer()
            }
        }
    }
}

private struct ProminentCapsule<Content: View>: View {
    private let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        if #available(iOS 27.0, *) {
            content
                .padding(16)
                .contentShape(Capsule())
                .glassEffect(.regular.interactive(), in: .capsule)
        } else if #available(iOS 26.0, *) {
            content
                .padding(16)
                .contentShape(Capsule())
                .glassEffect(.clear.interactive(), in: .capsule)
        } else {
            content
                .padding(16)
                .contentShape(Capsule())
                .background(
                    Capsule()
                        .fill(.white.opacity(0.2))
                )
        }
    }
}

private struct ProminentCircle<Content: View>: View {
    private let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        if #available(iOS 27.0, *) {
            content
                .padding(16)
                .contentShape(Circle())
                .glassEffect(.regular.interactive(), in: .capsule)
        } else if #available(iOS 26.0, *) {
            content
                .padding(16)
                .contentShape(Circle())
                .glassEffect(.clear.interactive(), in: .capsule)
        } else {
            content
                .padding(16)
                .contentShape(Circle())
                .background(
                    Circle()
                        .fill(.white.opacity(0.2))
                )
        }
    }
}

// MARK: - Previews

#if DEBUG
#Preview("Connected") {
    let container = AppContainer.preview()
    container.selection.selectedConfiguration = ProxyConfiguration(
        name: "🇺🇸 Los Angeles",
        serverAddress: "203.0.113.10",
        serverPort: 443,
        outbound: .socks5(username: nil, password: nil)
    )
    container.tunnel.setStatusForPreview(.connected)

    return HomeView()
        .environment(AppSettings())
        .environment(container.tunnel)
        .environment(container.selection)
        .environment(container.latency)
        .environment(container.configurationStore)
        .environment(container.chainStore)
        .environment(container.subscriptionStore)
        .environment(ConnectionStatsModel.previewSeeded())
        .colorScheme(.dark)
}
#endif
