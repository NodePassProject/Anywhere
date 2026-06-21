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
    @Environment(VPNViewModel.self) private var viewModel
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(SubscriptionStore.self) private var subscriptionStore

    @Namespace private var namespace

    @State private var showingAddSheet = false
    @State private var showingManualAddSheet = false
    
    @State private var connectionEffectsEnabled = false
    
    private var isLoading: Bool { !configStore.isLoaded }

    private var isConnected: Bool {
        viewModel.vpnStatus == .connected
    }

    private var isTransitioning: Bool { viewModel.vpnStatus.isTransitioning }

    private var experimentalEnabled: Bool { settings.experimentalEnabled }

    var body: some View {
        ZStack {
            BackgroundGradient(isConnected: isConnected)
                .ignoresSafeArea()

            GeometryReader { geometry in
                ScrollView {
                    LazyVStack(spacing: 16, pinnedViews: [.sectionHeaders]) {
                        if isConnected && experimentalEnabled {
                            Section {
                                ConnectionStatsView()
                            } header: {
                                HStack {
                                    powerButton
                                        .matchedGeometryEffect(id: "powerButton", in: namespace)
                                    configurationCard
                                        .matchedGeometryEffect(id: "configurationCard", in: namespace)
                                }
                                .padding(.vertical, 8)
                            }
                        } else {
                            VStack(spacing: 80) {
                                powerButton
                                    .matchedGeometryEffect(id: "powerButton", in: namespace)
                                configurationCard
                                    .matchedGeometryEffect(id: "configurationCard", in: namespace)
                            }
                            .frame(minHeight: geometry.size.height)
                        }
                    }
                    .padding(.horizontal, 20)
                    .animation(connectionEffectsEnabled ? Animation.bouncy : nil, value: isConnected)
                    .sensoryFeedback(trigger: isConnected) { _, _ in
                        guard connectionEffectsEnabled else { return nil }
                        return .impact
                    }
                }
                .scrollBounceBehavior(.basedOnSize, axes: .vertical)
            }
        }
        .sheet(isPresented: $showingAddSheet) {
            DynamicSheet(animation: .snappy(duration: 0.3, extraBounce: 0)) {
                AddProxyView(showingManualAddSheet: $showingManualAddSheet)
            }
        }
        .sheet(isPresented: $showingManualAddSheet) {
            ProxyEditorView { configuration in
                configStore.add(configuration); viewModel.selectIfNone(configuration)
            }
        }
        .alert("VPN Error", isPresented: Binding(
            get: { viewModel.startError != nil },
            set: { if !$0 { viewModel.startError = nil } }
        )) {
            Button("OK") { viewModel.startError = nil }
        } message: {
            Text(viewModel.startError ?? "")
        }
        .onChange(of: viewModel.isManagerReady, initial: true) { _, ready in
            guard ready, !connectionEffectsEnabled else { return }
            Task { @MainActor in connectionEffectsEnabled = true }
        }
    }

    private var powerButton: some View {
        PowerButton(
            isConnected: isConnected,
            isTransitioning: isTransitioning,
            isCompact: isConnected && experimentalEnabled,
            isLoading: isLoading,
            isDisabled: isLoading
                || (viewModel.isButtonDisabled(hasConfigurations: configStore.hasConfigurations)
                    && configStore.hasConfigurations),
            animatesChanges: connectionEffectsEnabled
        ) {
            guard !isLoading else { return }
            if configStore.hasConfigurations {
                withAnimation(.spring(response: 0.5, dampingFraction: 0.7)) {
                    viewModel.toggleVPN()
                }
            } else {
                showingAddSheet = true
            }
        }
    }

    private var configurationCard: some View {
        ConfigurationCapsule(isConnected: isConnected, showingAddSheet: $showingAddSheet)
            .frame(maxWidth: 500)
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
    let isConnected: Bool
    let isTransitioning: Bool
    let isCompact: Bool
    let isLoading: Bool
    let isDisabled: Bool
    let animatesChanges: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            ZStack {
//                if #available(iOS 27.0, *) {
//                    Circle()
//                        .fill(.clear)
//                        .frame(width: isCompact ? 50 : 140)
//                        .glassEffect(.regular, in: .circle)
//                } else if #available(iOS 26.0, *) {
//                    Circle()
//                        .fill(.clear)
//                        .frame(width: isCompact ? 50 : 140)
//                        .glassEffect(.clear, in: .circle)
//                } else {
//                    Circle()
//                        .fill(.white.opacity(0.2))
//                        .frame(width: isCompact ? 50 : 140)
//                        .shadow(color: isConnected ? .cyan.opacity(0.4) : .black.opacity(0.08), radius: isConnected ? 24 : 8)
//                }
                if #available(iOS 26.0, *) {
                    Circle()
                        .fill(.clear)
                        .frame(width: isCompact ? 50 : 140)
                        .glassEffect(.clear, in: .circle)
                } else {
                    Circle()
                        .fill(.white.opacity(0.2))
                        .frame(width: isCompact ? 50 : 140)
                        .shadow(color: isConnected ? .cyan.opacity(0.4) : .black.opacity(0.08), radius: isConnected ? 24 : 8)
                }

                if isTransitioning || isLoading {
                    ProgressView()
                        .controlSize(.large)
                        .tint(isConnected ? .white : .accentColor)
                } else {
                    Image(systemName: "power")
                        .font(.system(size: isCompact ? 24 : 40, weight: .light))
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
    @Environment(VPNViewModel.self) private var viewModel
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(SubscriptionStore.self) private var subscriptionStore

    let isConnected: Bool
    @Binding var showingAddSheet: Bool

    var body: some View {
        if let configuration = viewModel.selectedConfiguration {
            selectedCapsule(configuration)
        } else if configStore.isLoaded {
            emptyCapsule
        } else {
            loadingCapsule
        }
    }

    private func select(id: UUID) {
        if let chain = chainStore.chains.first(where: { $0.id == id }) {
            viewModel.selectChain(chain, configurations: configStore.configurations)
        } else if let configuration = configStore.configurations.first(where: { $0.id == id }) {
            viewModel.selectedConfiguration = configuration
        }
    }

    @ViewBuilder
    private func selectedCapsule(_ configuration: ProxyConfiguration) -> some View {
        Menu {
            ForEach(configStore.standalonePickerItems) { item in
                Button(item.name) { select(id: item.id) }
            }
            if !chainStore.pickerItems.isEmpty {
                Section {
                    ForEach(chainStore.pickerItems) { item in
                        Button(item.name) { select(id: item.id) }
                    }
                } header: {
                    Text("Chains")
                }
            }
            ForEach(subscriptionStore.pickerSections) { section in
                Section {
                    ForEach(section.items) { item in
                        Button(item.name) { select(id: item.id) }
                    }
                } header: {
                    Text(section.header ?? "")
                }
            }
            Button {
                showingAddSheet = true
            } label: {
                Label("Add", systemImage: "plus")
            }
        } label: {
            ProminentCapsule {
                HStack {
                    Image("anywhere")
                        .foregroundStyle(isConnected ? .white.opacity(0.7) : .secondary)
                        .frame(width: 24)
                    Text(configuration.name)
                        .font(.body.weight(.medium))
                        .foregroundStyle(isConnected ? .white : .primary)
                        .lineLimit(1)
                    Spacer()
                    Image(systemName: "chevron.up.chevron.down")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(isConnected ? .white.opacity(0.7) : .secondary)
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
//        if #available(iOS 27.0, *) {
//            content
//                .padding(16)
//                .contentShape(Capsule())
//                .glassEffect(.regular.interactive(), in: .capsule)
//        } else if #available(iOS 26.0, *) {
//            content
//                .padding(16)
//                .contentShape(Capsule())
//                .glassEffect(.clear.interactive(), in: .capsule)
//        } else {
//            content
//                .padding(16)
//                .contentShape(Capsule())
//                .background(
//                    Capsule()
//                        .fill(.white.opacity(0.2))
//                )
//        }
        if #available(iOS 26.0, *) {
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
