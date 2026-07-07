//
//  ContentView.swift
//  Anywhere
//
//  Created by NodePassProject on 7/4/26.
//

import SwiftUI

struct ContentView: View {
    @Environment(PhoneSession.self) private var phone
    @Environment(\.scenePhase) private var scenePhase
    
    @State private var showingPicker = false
    
    let formatter: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter
    }()
    
    var body: some View {
        NavigationStack {
            ZStack {
                BackgroundGradient(isConnected: phone.isConnected)
                    .ignoresSafeArea()

                if phone.snapshot == nil {
                    SyncPlaceholder(lastError: phone.lastError)
                } else {
                    home
                }
            }
        }
        .animation(.easeInOut(duration: 0.6), value: phone.isConnected)
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { phone.refresh() }
        }
        .sheet(isPresented: $showingPicker) {
            ConfigurationPicker()
        }
    }

    private var home: some View {
        VStack(spacing: 12) {
            PowerButton(
                isConnected: phone.isConnected,
                isTransitioning: phone.isTransitioning,
                isDisabled: !(phone.snapshot?.hasConfigurations ?? false)
            ) {
                phone.toggleVPN()
            }

            Text(phone.status.localizedText)
                .font(.footnote)
                .foregroundStyle(.secondary)

            if phone.lastError != nil, let snapshotDate = phone.snapshotDate {
                Text(formatter.localizedString(for: snapshotDate, relativeTo: .now))
                    .font(.system(size: 12))
                    .foregroundStyle(.orange)
            }

            ConfigurationCapsule(showingPicker: $showingPicker)
        }
        .padding(.horizontal, 8)
        .sensoryFeedback(.impact, trigger: phone.isConnected)
    }
}

// MARK: - Background

private struct BackgroundGradient: View {
    let isConnected: Bool

    var body: some View {
        if isConnected {
            LinearGradient(
                colors: [
                    Color.connectedBackgroundStart,
                    Color.connectedBackgroundEnd,
                ],
                startPoint: .top,
                endPoint: .bottom
            )
        } else {
            LinearGradient(
                colors: [
                    Color.disconnectedBackgroundStart,
                    Color.disconnectedBackgroundEnd,
                ],
                startPoint: .top,
                endPoint: .bottom
            )
        }
    }
}

// MARK: - Power Button

private struct PowerButton: View {
    let isConnected: Bool
    let isTransitioning: Bool
    let isDisabled: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            ZStack {
                if #available(watchOS 27.0, *) {
                    Circle()
                        .fill(.clear)
                        .glassEffect(.regular, in: .circle)
                } else if #available(watchOS 26.0, *) {
                    Circle()
                        .fill(.clear)
                        .glassEffect(.clear, in: .circle)
                } else {
                    Circle()
                        .fill(.white.opacity(0.2))
                        .shadow(color: isConnected ? .cyan.opacity(0.4) : .black.opacity(0.08), radius: isConnected ? 16 : 6)
                }
                if isTransitioning {
                    ProgressView()
                } else {
                    Image(systemName: "power")
                        .font(.system(size: 30, weight: .light))
                }
            }
            .frame(width: 78, height: 78)
            .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .handGestureShortcut(.primaryAction)
        .disabled(isDisabled || isTransitioning)
    }
}

// MARK: - Configuration Capsule

private struct ConfigurationCapsule: View {
    @Environment(PhoneSession.self) private var phone
    
    @Binding var showingPicker: Bool
    
    var body: some View {
        if phone.snapshot?.hasConfigurations ?? false {
            Button {
                showingPicker = true
            } label: {
                ProminentCapsule {
                    HStack(spacing: 6) {
                        Text(phone.snapshot?.selectedName ?? String(localized: "Not Configured"))
                            .font(.footnote.weight(.medium))
                            .lineLimit(1)
                        Image(systemName: "chevron.up.chevron.down")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .buttonStyle(.plain)
        } else {
            Text("Add a configuration on your iPhone.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
    }
}

private struct ProminentCapsule<Content: View>: View {
    private let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        if #available(watchOS 27.0, *) {
            content
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .contentShape(Capsule())
                .glassEffect(.regular.interactive(), in: .capsule)
        } else if #available(watchOS 26.0, *) {
            content
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .contentShape(Capsule())
                .glassEffect(.clear.interactive(), in: .capsule)
        } else {
            content
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .contentShape(Capsule())
                .background(
                    Capsule()
                        .fill(.white.opacity(0.2))
                )
        }
    }
}

// MARK: - Configuration Picker

private struct ConfigurationPicker: View {
    @Environment(PhoneSession.self) private var phone
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                ForEach(phone.snapshot?.sections ?? []) { section in
                    Section {
                        ForEach(section.items) { item in
                            row(for: item)
                        }
                    } header: {
                        if let header = section.header {
                            Text(header)
                        }
                    }
                }
            }
            .navigationTitle("Configurations")
        }
    }

    private func row(for item: WatchBridge.Item) -> some View {
        Button {
            phone.select(item.id)
            dismiss()
        } label: {
            HStack {
                Text(item.name)
                    .lineLimit(2)
                Spacer()
                if item.id == phone.snapshot?.selectedId {
                    Image(systemName: "checkmark")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(.tint)
                }
            }
        }
    }
}

// MARK: - Placeholder

private struct SyncPlaceholder: View {
    let lastError: String?

    var body: some View {
        VStack(spacing: 10) {
            if lastError == nil {
                ProgressView()
                Text("Syncing with iPhone")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                Image(systemName: "iphone.slash")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                Text("Open Anywhere on your iPhone to sync.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .padding(.horizontal, 8)
    }
}
