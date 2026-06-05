//
//  HomeView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI
import NetworkExtension

struct HomeView: View {
    @Environment(VPNViewModel.self) private var viewModel
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(SubscriptionStore.self) private var subscriptionStore

    @State private var proxyMode = AWCore.getProxyMode()

    @State private var showingAddSheet = false
    @State private var showingManualAddSheet = false

    private var isConnected: Bool {
        viewModel.vpnStatus == .connected
    }

    private var isTransitioning: Bool { viewModel.vpnStatus.isTransitioning }

    private var selectedPickerId: Binding<UUID?> {
        Binding(
            get: { viewModel.selectedChainId ?? viewModel.selectedConfiguration?.id },
            set: { newId in
                guard let id = newId else { return }
                if let chain = chainStore.chains.first(where: { $0.id == id }) {
                    viewModel.selectChain(chain, configurations: configStore.configurations)
                } else if let configuration = configStore.configurations.first(where: { $0.id == id }) {
                    viewModel.selectedConfiguration = configuration
                }
            }
        )
    }

    var body: some View {
        ZStack {
            if #available(iOS 26.0, *) {
                background
                    .ignoresSafeArea()
            } else {
                background
                    .ignoresSafeArea(edges: .horizontal)
                    .ignoresSafeArea(edges: .top)
            }

            GeometryReader { geometry in
                ScrollView {
                    VStack(spacing: 0) {
                        Spacer()
                        
                        VStack(spacing: 10) {
                            powerButton
                            statusText
                        }
                        .padding(.bottom, 50)
                        
                        if isConnected {
                            trafficStats
                                .padding(.bottom, 20)
                                .transition(.move(edge: .bottom).combined(with: .opacity))
                        }
                        
                        configurationCard
                        
                        Spacer()
                        
                        Rectangle()
                            .fill(.clear)
                            .frame(height: geometry.size.height / 8)
                    }
                    .padding(.horizontal, 24)
                    .frame(minHeight: geometry.size.height)
                    .animation(.easeInOut(duration: 0.4), value: isConnected)
                }
            }
        }
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("Proxy Mode", selection: $proxyMode) {
                    Text("Rule").tag(ProxyMode.rule)
                    Text("Global").tag(ProxyMode.global)
                }
                .pickerStyle(.segmented)
                .frame(minWidth: 120)
            }
        }
        .onAppear {
            proxyMode = AWCore.getProxyMode()
        }
        .onChange(of: proxyMode) {
            AWCore.setProxyMode(proxyMode)
            AWCore.notifyTunnelSettingsChanged()
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
    }

    // MARK: - Background

    @ViewBuilder
    private var background: some View {
        if isConnected {
            LinearGradient(
                colors: [Color.connectedBackgroundStart, Color.connectedBackgroundEnd],
                startPoint: .top,
                endPoint: .bottom
            )
            .transition(.blurReplace)
        } else {
            LinearGradient(
                colors: [Color.disconnectedBackgroundStart, Color.disconnectedBackgroundEnd],
                startPoint: .top,
                endPoint: .bottom
            )
            .transition(.blurReplace)
        }
    }

    // MARK: - Power Button

    @ViewBuilder
    private var powerButton: some View {
        Button {
            if configStore.hasConfigurations {
                withAnimation(.spring(response: 0.5, dampingFraction: 0.7)) {
                    viewModel.toggleVPN()
                }
            } else {
                showingAddSheet = true
            }
        } label: {
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
                        .fill(.white.opacity(0.2))
                        .frame(width: 140, height: 140)
                        .shadow(color: isConnected ? .cyan.opacity(0.4) : .black.opacity(0.08), radius: isConnected ? 24 : 8)
                }

                if isTransitioning {
                    ProgressView()
                        .controlSize(.large)
                        .tint(isConnected ? .white : .accentColor)
                } else {
                    Image(systemName: "power")
                        .font(.system(size: 44, weight: .light))
                        .foregroundStyle(isConnected ? .white : .accentColor)
                }
            }
            .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .disabled(viewModel.isButtonDisabled(hasConfigurations: configStore.hasConfigurations) && configStore.hasConfigurations)
        .sensoryFeedback(.impact(weight: .medium), trigger: isConnected)
        .animation(.easeInOut(duration: 0.6), value: isConnected)
    }
    
    // MARK: - Status Text
    
    @ViewBuilder
    private var statusText: some View {
        Text(viewModel.statusText)
            .font(.system(size: 20, weight: .medium))
            .foregroundStyle(isConnected ? .white : .secondary)
            .contentTransition(.interpolate)
            .animation(.easeInOut, value: viewModel.vpnStatus)
    }

    // MARK: - Traffic Stats

    @ViewBuilder
    private var trafficStats: some View {
        cardContent {
            ConnectionStatsContent()
        }
    }

    // MARK: - Configuration Card

    @ViewBuilder
    private var configurationCard: some View {
        if let configuration = viewModel.selectedConfiguration {
            selectedConfigurationCard(configuration)
        } else {
            emptyStateCard
        }
    }

    @ViewBuilder
    private func selectedConfigurationCard(_ configuration: ProxyConfiguration) -> some View {
        Menu {
            ForEach(configStore.standalonePickerItems) { item in
                Button(item.name) {
                    selectedPickerId.wrappedValue = item.id
                }
            }
            if !chainStore.pickerItems.isEmpty {
                Section {
                    ForEach(chainStore.pickerItems) { item in
                        Button(item.name) {
                            selectedPickerId.wrappedValue = item.id
                        }
                    }
                } header: {
                    Text("Chains")
                }
            }
            ForEach(subscriptionStore.pickerSections) { section in
                Section {
                    ForEach(section.items) { item in
                        Button(item.name) {
                            selectedPickerId.wrappedValue = item.id
                        }
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
            cardContent {
                HStack {
                    Image("anywhere")
                        .foregroundStyle(isConnected ? .white.opacity(0.7) : .secondary)
                        .frame(width: 24)
                    Text(configuration.name)
                        .font(.body.weight(.medium))
                        .foregroundStyle(isConnected ? .white : .primary)
                    Spacer()
                    Image(systemName: "chevron.up.chevron.down")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(isConnected ? .white.opacity(0.7) : .secondary)
                }
            }
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder
    private var emptyStateCard: some View {
        Button {
            showingAddSheet = true
        } label: {
            cardContent {
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
                        .fill(.white.opacity(0.2))
                )
        }
    }
}
