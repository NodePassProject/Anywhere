//
//  HomeView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/14/26.
//

import SwiftUI
import NetworkExtension

struct HomeView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared

    @State private var showingProxyPicker = false

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

            VStack(spacing: 0) {
                Spacer()

                powerButton
                    .padding(.bottom, 20)

                Text(viewModel.statusText)
                    .font(.system(size: 48, weight: .medium))
                    .foregroundStyle(isConnected ? .white : .secondary)
                    .contentTransition(.interpolate)
                    .animation(.easeInOut, value: viewModel.vpnStatus)
                    .padding(.bottom, isConnected ? 30 : 50)

                if isConnected {
                    trafficStats
                        .padding(.bottom, 30)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }

                configurationCard
                    .padding(.horizontal, 200)

                Spacer()
            }
            .animation(.easeInOut(duration: 0.4), value: isConnected)
        }
        .sheet(isPresented: $showingProxyPicker) {
            ProxyPickerView()
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
            viewModel.toggleVPN()
        } label: {
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

                if isTransitioning {
                    ProgressView()
                        .scaleEffect(1.5)
                        .tint(isConnected ? .white : .accentColor)
                } else {
                    Image(systemName: "power")
                        .font(.system(size: 80, weight: .light))
                        .foregroundStyle(isConnected ? .white : .accentColor)
                }
            }
        }
        .buttonStyle(.plain)
        .buttonBorderShape(.circle)
        .disabled(viewModel.isButtonDisabled)
        .animation(.easeInOut(duration: 0.6), value: isConnected)
    }

    // MARK: - Traffic Stats

    private var trafficStats: some View {
        HStack(spacing: 80) {
            statCard(icon: "arrow.up", label: String(localized: "Upload"), value: Self.formatBytes(viewModel.bytesOut))
            statCard(icon: "arrow.down", label: String(localized: "Download"), value: Self.formatBytes(viewModel.bytesIn))
        }
        .animation(.default, value: viewModel.bytesIn)
        .animation(.default, value: viewModel.bytesOut)
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
                    .contentTransition(.numericText())
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

    // MARK: - Configuration Card

    @ViewBuilder
    private var configurationCard: some View {
        if let configuration = viewModel.selectedConfiguration {
            selectedConfigurationCard(configuration)
        } else {
            emptyStateCard
        }
    }

    private func selectedConfigurationCard(_ configuration: ProxyConfiguration) -> some View {
        Button {
            showingProxyPicker = true
        } label: {
            HStack(spacing: 32) {
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .resizable()
                    .scaledToFit()
                    .foregroundStyle(isConnected ? .white.opacity(0.7) : .secondary)
                    .frame(width: 48)

                VStack(alignment: .leading, spacing: 4) {
                    Text(configuration.name)
                        .font(.system(size: 32, weight: .medium))
                        .foregroundStyle(isConnected ? .white : .primary)
                    HStack(spacing: 6) {
                        Text(configuration.outboundProtocol.name)
                        Text("·")
                        Text(configuration.transport.uppercased())
                        let security = configuration.security.uppercased()
                        if security != "NONE" {
                            Text("·")
                            Text(security)
                        }
                        if let flow = configuration.flow, flow.uppercased().contains("VISION") {
                            Text("·")
                            Text("Vision")
                        }
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
        }
    }

    private var emptyStateCard: some View {
        Button {
            showingProxyPicker = true
        } label: {
            HStack(spacing: 32) {
                Image(systemName: "plus.circle.fill")
                    .font(.title2)
                    .foregroundStyle(.tint)
                Text("Add a Configuration")
                    .font(.title3.weight(.medium))
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(24)
            .background(
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .fill(.white.opacity(0.15))
            )
        }
        .buttonStyle(.card)
    }
}
