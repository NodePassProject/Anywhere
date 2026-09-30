//
//  MainControlView.swift
//  Anywhere
//
//  Created by NodePassProject on 9/22/26.
//

import SwiftUI
import NetworkExtension

struct MainControlView: View {
    @Environment(Operations.self) private var operations
    @Environment(TunnelController.self) private var tunnelController
    @Environment(ProxySelection.self) private var proxySelection
    @Environment(LatencyCenter.self) private var latencyCenter
    @Environment(ConfigurationStore.self) private var configurationStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(GroupStore.self) private var groupStore
    @Environment(SubscriptionStore.self) private var subscriptionStore

    let connectionEffectsEnabled: Bool
    
    @State private var centerOffset: CGFloat = 0
    @State private var showingProxiesView = false
    @State private var showingAddSheet = false
    @State private var showingManualAddSheet = false

    private var isLoading: Bool { !configurationStore.isLoaded }

    private var isConnected: Bool {
        tunnelController.rawStatus == .connected
    }

    private var isTransitioning: Bool { tunnelController.rawStatus.isTransitioning }

    private var isPowerButtonDisabled: Bool {
        if configurationStore.hasConfigurations {
            if !isTransitioning {
                if tunnelController.isManagerReady {
                    return false
                }
            }
        }
        return true
    }

    var body: some View {
        MainControlLayout(
            idealSpacingRatio: 0.12,
            maxSpacing: 100,
            minSpacing: 20,
            centerOffset: centerOffset
        ) {
            VStack(spacing: 20) {
                PowerButton(
                    isConnected: isConnected,
                    isTransitioning: isTransitioning,
                    isLoading: isLoading,
                    isDisabled: isPowerButtonDisabled,
                    animatesChanges: connectionEffectsEnabled
                ) {
                    guard !isLoading else { return }
                    if configurationStore.hasConfigurations {
                        withAnimation(.spring(response: 0.5, dampingFraction: 0.7)) {
                            operations.tunnel.toggle()
                        }
                    } else {
                        showingAddSheet = true
                    }
                }

                let status = tunnelController.status
                HStack {
                    if [.connecting, .disconnecting, .reasserting].contains(status) {
                        ProgressView()
                            .controlSize(.mini)
                    }
                    Text(status.localizedText)
                        .font(.headline)
                        .foregroundStyle(.secondary)
                }
            }

            ConfigurationCapsule(
                isConnected: isConnected,
                showingProxiesPage: $showingProxiesView,
                showingAddSheet: $showingAddSheet
            )
            .frame(maxWidth: 500)
        }
        .onGeometryChange(for: CGFloat.self) { proxy in
            (proxy.safeAreaInsets.bottom - proxy.safeAreaInsets.top) / 2
        } action: { offset in
            centerOffset = offset
        }
        .padding(.horizontal)
        .animation(connectionEffectsEnabled ? Animation.bouncy : nil, value: isConnected)
        .sheet(isPresented: $showingProxiesView) {
            ProxiesView()
                .environment(operations)
                .environment(proxySelection)
                .environment(latencyCenter)
                .environment(configurationStore)
                .environment(chainStore)
                .environment(groupStore)
                .environment(subscriptionStore)
        }
        .sheet(isPresented: $showingAddSheet) {
            DynamicSheet(animation: .snappy(duration: 0.3, extraBounce: 0)) {
                AddProxyView(showingManualAddSheet: $showingManualAddSheet)
                    .environment(operations)
            }
        }
        .sheet(isPresented: $showingManualAddSheet) {
            ProxyEditorView { configuration in
                operations.configurations.add(configuration); operations.selection.selectIfNone(configuration)
            }
        }
    }
}

// MARK: - Layout

private struct MainControlLayout: Layout {
    let idealSpacingRatio: CGFloat
    let maxSpacing: CGFloat
    let minSpacing: CGFloat
    let centerOffset: CGFloat

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        guard let sizes = measure(subviews, width: proposal.width) else { return .zero }
        let idealSize = CGSize(
            width: max(sizes.group.width, sizes.capsule.width),
            height: sizes.group.height + maxSpacing + sizes.capsule.height
        )
        return proposal.replacingUnspecifiedDimensions(by: idealSize)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        guard let sizes = measure(subviews, width: bounds.width) else { return }
        let group = sizes.group, capsule = sizes.capsule

        let room = bounds.height - group.height - capsule.height
        let idealSpacing = min(max(bounds.height * idealSpacingRatio, minSpacing), maxSpacing)
        let spacing = max(min(idealSpacing, room), minSpacing)
        let contentHeight = group.height + spacing + capsule.height
        let centeredTop = bounds.midY + centerOffset - contentHeight / 2
        let top = max(bounds.minY, min(centeredTop, bounds.maxY - contentHeight))

        subviews[0].place(at: CGPoint(x: bounds.midX, y: top), anchor: .top, proposal: ProposedViewSize(group))
        subviews[1].place(at: CGPoint(x: bounds.midX, y: top + group.height + spacing), anchor: .top, proposal: ProposedViewSize(capsule))
    }

    private func measure(_ subviews: Subviews, width: CGFloat?) -> (group: CGSize, capsule: CGSize)? {
        guard subviews.count == 2 else { return nil }
        let proposal = ProposedViewSize(width: width, height: nil)
        return (subviews[0].sizeThatFits(proposal), subviews[1].sizeThatFits(proposal))
    }
}

// MARK: - Power Button

private struct PowerButton: View {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(AppSettings.self) private var settings
    
    private static let circleDiameter: CGFloat = 140

    let isConnected: Bool
    let isTransitioning: Bool
    let isLoading: Bool
    let isDisabled: Bool
    let animatesChanges: Bool
    let action: () -> Void

    private var indicatorColor: Color {
        if isConnected { return .green }
        if isTransitioning { return .orange }
        return .gray.opacity(0.8)
    }

    var body: some View {
        Button(action: action) {
            ZStack {
                if #available(iOS 27.0, *) {
                    Circle()
                        .fill(.clear)
                        .frame(width: Self.circleDiameter, height: Self.circleDiameter)
                        .glassEffect(.regular, in: .circle)
                } else if #available(iOS 26.0, *) {
                    Circle()
                        .fill(.clear)
                        .frame(width: Self.circleDiameter, height: Self.circleDiameter)
                        .glassEffect(.clear, in: .circle)
                } else {
                    Circle()
                        .fill(background)
                        .frame(width: Self.circleDiameter, height: Self.circleDiameter)
                }
                ZStack {
                    Image(systemName: "power")
                        .resizable()
                        .scaledToFit()
                        .frame(height: 40)
                    Image(systemName: "circle.fill")
                        .resizable()
                        .scaledToFit()
                        .frame(height: 5)
                        .foregroundStyle(indicatorColor)
                        .offset(y: 45)
                }
            }
            .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .disabled(isDisabled)
        .animation(animatesChanges ? Animation.easeInOut(duration: 0.6) : nil, value: isConnected)
    }
    
    private var background: Color {
        let data = colorScheme == .light
            ? settings.statCardBackgroundLightData
            : settings.statCardBackgroundDarkData
        return data.flatMap(Color.init(archivedData:)) ?? .statCardBackground
    }
}

// MARK: - Configuration Capsule

private struct ConfigurationCapsule: View {
    @Environment(ProxySelection.self) private var selection
    @Environment(ConfigurationStore.self) private var configurationStore

    let isConnected: Bool
    @Binding var showingProxiesPage: Bool
    @Binding var showingAddSheet: Bool

    var body: some View {
        if let configuration = selection.selectedConfiguration {
            selectedCapsule(configuration)
        } else if configurationStore.isLoaded {
            emptyCapsule
        } else {
            loadingCapsule
        }
    }

    private func selectedCapsule(_ configuration: ProxyConfiguration) -> some View {
        Button {
            showingProxiesPage = true
        } label: {
            ProminentCapsule {
                HStack {
                    HStack {
                        Image("anywhere.fill")
                            .font(.body.weight(.medium))
                        Text(configuration.name)
                            .font(.body.weight(.medium))
                            .lineLimit(1)
                    }
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
    @Environment(\.colorScheme) private var colorScheme
    @Environment(AppSettings.self) private var settings
    
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
                        .fill(background)
                )
        }
    }
    
    private var background: Color {
        let data = colorScheme == .light
            ? settings.statCardBackgroundLightData
            : settings.statCardBackgroundDarkData
        return data.flatMap(Color.init(archivedData:)) ?? .statCardBackground
    }
}

private struct ProminentCircle<Content: View>: View {
    @Environment(\.colorScheme) private var colorScheme
    @Environment(AppSettings.self) private var settings
    
    private let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        if #available(iOS 27.0, *) {
            content
                .padding(16)
                .contentShape(Circle())
                .glassEffect(.regular.interactive(), in: .circle)
        } else if #available(iOS 26.0, *) {
            content
                .padding(16)
                .contentShape(Circle())
                .glassEffect(.clear.interactive(), in: .circle)
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
    
    private var background: Color {
        let data = colorScheme == .light
            ? settings.statCardBackgroundLightData
            : settings.statCardBackgroundDarkData
        return data.flatMap(Color.init(archivedData:)) ?? .statCardBackground
    }
}

// MARK: - Previews

#if DEBUG
#Preview("Connected") {
    let container = AppContainer.preview()
    container.selection.select(ProxyConfiguration(
        name: "🇺🇸 Los Angeles",
        serverAddress: "203.0.113.10",
        serverPort: 443,
        outbound: .socks5(SOCKS5Configuration())
    ))
    container.tunnel.setStatusForPreview(.connected)

    return MainControlView(connectionEffectsEnabled: true)
        .environment(AppSettings())
        .environment(Operations(container: container))
        .environment(container.tunnel)
        .environment(container.selection)
        .environment(container.latency)
        .environment(container.configurationStore)
        .environment(container.chainStore)
        .environment(container.groupStore)
        .environment(container.subscriptionStore)
        .environment(ConnectionStats.previewSeeded())
        .colorScheme(.dark)
}
#endif
