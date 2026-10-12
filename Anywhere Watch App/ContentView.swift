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
    
    var body: some View {
        NavigationStack {
            ZStack {
                BackgroundGradient()
                    .ignoresSafeArea()

                content
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

    @ViewBuilder
    private var content: some View {
        if let snapshot = phone.snapshot, phone.lastError == nil {
            if snapshot.hasConfigurations {
                controls
            } else {
                Placeholder("Add a configuration on your iPhone.") {
                    Image(systemName: "plus.circle")
                }
            }
        } else if phone.snapshot == nil, phone.lastError != nil {
            Placeholder("Open Anywhere on your iPhone to sync.") {
                Image(systemName: "iphone.slash")
            }
        } else {
            Placeholder("Syncing with iPhone") {
                ProgressView()
            }
        }
    }

    @ViewBuilder
    private var controls: some View {
        VStack(spacing: 12) {
            PowerButton(
                isConnected: phone.isConnected,
                isTransitioning: phone.isTransitioning
            ) {
                phone.toggleVPN()
            }

            HStack(spacing: 4) {
                if phone.isTransitioning {
                    ProgressView()
                        .frame(width: 14, height: 14)
                }
                Text(phone.status.localizedText)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            ConfigurationCapsule(showingPicker: $showingPicker)
        }
        .padding(.horizontal, 8)
        .sensoryFeedback(.impact, trigger: phone.isConnected)
    }
}

// MARK: - Background

private struct BackgroundGradient: View {
    var body: some View {
        LinearGradient(
            colors: [
                Color.homeBackgroundStart,
                Color.homeBackgroundEnd,
            ],
            startPoint: .top,
            endPoint: .bottom
        )
    }
}

// MARK: - Power Button

private struct PowerButton: View {
    let isConnected: Bool
    let isTransitioning: Bool
    let action: () -> Void

    private var indicatorColor: Color {
        if isConnected { return .green }
        if isTransitioning { return .orange }
        return .gray.opacity(0.8)
    }

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
                        .fill(Color.statCardBackground)
                }
                ZStack {
                    Image(systemName: "power")
                        .resizable()
                        .scaledToFit()
                        .frame(height: 24)
                    Image(systemName: "circle.fill")
                        .resizable()
                        .scaledToFit()
                        .frame(height: 4)
                        .foregroundStyle(indicatorColor)
                        .offset(y: 26)
                }
            }
            .frame(width: 78, height: 78)
            .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .handGestureShortcut(.primaryAction)
        .disabled(isTransitioning)
    }
}

// MARK: - Configuration Capsule

private struct ConfigurationCapsule: View {
    @Environment(PhoneSession.self) private var phone
    
    @Binding var showingPicker: Bool
    
    var body: some View {
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
                        .fill(Color.statCardBackground)
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

private struct Placeholder<Icon: View>: View {
    private let message: LocalizedStringKey
    private let icon: Icon

    init(_ message: LocalizedStringKey, @ViewBuilder icon: () -> Icon) {
        self.message = message
        self.icon = icon()
    }

    var body: some View {
        VStack(spacing: 10) {
            icon
                .font(.title3)
                .foregroundStyle(.secondary)
                .frame(width: 24, height: 24)
            Text(message)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.horizontal, 8)
    }
}
