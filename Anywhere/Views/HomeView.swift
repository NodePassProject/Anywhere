//
//  HomeView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import SwiftUI
import NetworkExtension

struct HomeView: View {
    @Environment(VPNViewModel.self) private var viewModel: VPNViewModel

    @State private var showingAddSheet = false
    @State private var showingManualAddSheet = false
    @State private var pickerConfig = PickerConfig()

    private var isConnected: Bool {
        viewModel.vpnStatus == .connected
    }

    private var isTransitioning: Bool {
        viewModel.vpnStatus == .connecting || viewModel.vpnStatus == .disconnecting || viewModel.vpnStatus == .reasserting
    }

    var body: some View {
        ZStack {
            backgroundGradient
                .ignoresSafeArea()

            GeometryReader { geometry in
                ScrollView {
                    VStack(spacing: 0) {
                        Spacer()
                        
                        powerButton
                            .padding(.bottom, 16)
                        
                        Text(viewModel.statusText)
                            .font(.title3.weight(.medium))
                            .foregroundStyle(isConnected ? .white : .secondary)
                            .contentTransition(.interpolate)
                            .animation(.easeInOut, value: viewModel.vpnStatus)
                            .padding(.bottom, isConnected ? 20 : 40)
                        
                        if isConnected {
                            trafficStats
                                .padding(.horizontal, 24)
                                .padding(.bottom, 20)
                                .transition(.move(edge: .bottom).combined(with: .opacity))
                        }
                        
                        configurationCard
                            .padding(.horizontal, 24)
                        
                        Spacer()
                    }
                    .frame(minHeight: geometry.size.height)
                    .animation(.easeInOut(duration: 0.4), value: isConnected)
                }
            }
        }
        .picker3D($pickerConfig, items: viewModel.configurations.map { PickerItem(id: $0.id, name: $0.name) })
        .onChange(of: pickerConfig.show) {
            if !pickerConfig.show, let id = pickerConfig.selectedId, let configuration = viewModel.configurations.first(where: { $0.id == id }) {
                viewModel.selectedConfiguration = configuration
            }
        }
        .sheet(isPresented: $showingAddSheet) {
            DynamicSheet(animation: .snappy(duration: 0.3, extraBounce: 0)) {
                AddProxyView(showingManualAddSheet: $showingManualAddSheet) { configuration in
                    viewModel.addConfiguration(configuration)
                } onSubscriptionImport: { configurations, subscription in
                    viewModel.addSubscription(configurations: configurations, subscription: subscription)
                }
            }
        }
        .sheet(isPresented: $showingManualAddSheet) {
            ProxyEditorView { configuration in
                viewModel.addConfiguration(configuration)
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
    private var backgroundGradient: some View {
        if isConnected {
            LinearGradient(
                colors: [Color("GradientStart"), Color("GradientEnd")],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .transition(.blurReplace)
        } else {
            LinearGradient(
                colors: [Color("GradientDisconnectedStart"), Color("GradientDisconnectedEnd")],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .transition(.blurReplace)
        }
    }

    // MARK: - Power Button

    private var powerButton: some View {
        Button {
            withAnimation(.spring(response: 0.5, dampingFraction: 0.7)) {
                viewModel.toggleVPN()
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
                        .fill(.regularMaterial)
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
        .disabled(viewModel.isButtonDisabled)
        .sensoryFeedback(.impact(weight: .medium), trigger: isConnected)
        .animation(.easeInOut(duration: 0.6), value: isConnected)
    }

    // MARK: - Traffic Stats

    private var trafficStats: some View {
        cardContent {
            HStack {
                HStack(spacing: 6) {
                    Image(systemName: "arrow.up")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.white.opacity(0.7))
                    Text(Self.formatBytes(viewModel.bytesOut))
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(.white)
                        .contentTransition(.numericText())
                }
                Spacer()
                HStack(spacing: 6) {
                    Image(systemName: "arrow.down")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.white.opacity(0.7))
                    Text(Self.formatBytes(viewModel.bytesIn))
                        .font(.callout.monospacedDigit())
                        .foregroundStyle(.white)
                        .contentTransition(.numericText())
                }
            }
            .animation(.default, value: viewModel.bytesIn)
            .animation(.default, value: viewModel.bytesOut)
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

    // MARK: - Configuration Card

    @ViewBuilder
    private var configurationCard: some View {
        if let configuration = viewModel.selectedConfiguration {
            selectedConfigurationCard(configuration)
        } else {
            emptyStateCard
        }
    }

    private func selectedConfigurationCard(_ configuration: VLESSConfiguration) -> some View {
        Button {
            pickerConfig.text = configuration.name
            pickerConfig.show = true
        } label: {
            cardContent {
                VStack(spacing: 12) {
                    HStack {
                        Image(systemName: "antenna.radiowaves.left.and.right")
                            .foregroundStyle(isConnected ? .white.opacity(0.7) : .secondary)
                            .frame(width: 24)
                        Text(configuration.name)
                            .font(.body.weight(.medium))
                            .foregroundStyle(isConnected ? .white : .primary)
                            .onGeometryChange(for: CGRect.self) { proxy in
                                proxy.frame(in: .global)
                            } action: { newValue in
                                pickerConfig.sourceFrame = newValue
                            }
                            .opacity(pickerConfig.show ? 0 : 1)
                        Spacer()
                        Image(systemName: "chevron.up.chevron.down")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(isConnected ? Color.white.opacity(0.4) : Color.secondary.opacity(0.4))
                    }
                }
            }
        }
        .buttonStyle(.plain)
    }

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
                        .fill(.regularMaterial)
                )
        }
    }
}
