//
//  VoyagerOnboardingView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import SwiftUI

struct VoyagerOnboardingView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(VoyagerStore.self) private var store

    @State private var errorMessage: String?
    @State private var isRestoring = false
    
    private static let termsURL = URL(string: "https://www.apple.com/legal/internet-services/itunes/dev/stdeula/")!
    private static let privacyURL = URL(string: "https://www.argsment.com/privacy-policy")!

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 48) {
                    header
                    benefitsList
                }
                .padding(.horizontal, 24)
                .padding(.top, 12)
                .padding(.bottom, 24)
            }
            .scrollBounceBehavior(.basedOnSize)
            .safeAreaInset(edge: .bottom) { purchaseBar }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button {
                        dismiss()
                    } label: {
                        Label("Close", systemImage: "xmark")
                    }
                }
            }
            .alert("Error", isPresented: Binding(
                get: { errorMessage != nil },
                set: { if !$0 { errorMessage = nil } }
            )) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(errorMessage ?? "")
            }
            .task { await store.loadProduct() }
        }
    }

    // MARK: - Header

    private var header: some View {
        VStack(spacing: 10) {
            Image(systemName: "sparkles")
                .font(.system(size: 44, weight: .semibold))
                .foregroundStyle(Self.goldGradient)
                .padding(.bottom, 2)

            Text("Anywhere Voyager")
                .font(.system(size: 28, weight: .bold, design: .serif))
        }
        .multilineTextAlignment(.center)
        .frame(maxWidth: .infinity)
    }

    // MARK: - Benefits

    private var benefitsList: some View {
        VStack(alignment: .leading, spacing: 18) {
            ForEach(Self.benefits) { benefit in
                HStack(alignment: .center, spacing: 14) {
                    Image(systemName: benefit.systemName)
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundStyle(Self.goldGradient)
                        .frame(width: 30, height: 30)

                    VStack(alignment: .leading, spacing: 2) {
                        Text(benefit.title)
                            .font(.subheadline.weight(.semibold))
                        Text(benefit.subtitle)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 0)
                }
            }
        }
        .frame(maxWidth: 600, alignment: .leading)
    }

    // MARK: - Bottom action bar

    @ViewBuilder
    private var purchaseBar: some View {
        VStack(spacing: 12) {
            paymentButton

            Button("Restore Purchases") {
                Task { await restore() }
            }
            .font(.footnote)
            .disabled(isRestoring)

            footerLinks
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 8)
        .background(.bar)
    }

    private var paymentButton: some View {
        Button {
            Task { await buy() }
        } label: {
            ZStack {
                if store.purchaseInFlight {
                    ProgressView()
                        .tint(Color(hex: 0x161326))
                } else {
                    paymentButtonTitle
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundStyle(Color(hex: 0x161326))
                }
            }
            .frame(maxWidth: .infinity, minHeight: 54)
            .background(Self.goldGradient, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        }
        .disabled(store.purchaseInFlight)
    }

    @ViewBuilder
    private var paymentButtonTitle: some View {
        if let price = store.displayPrice {
            Text("Unlock Voyager — \(price)")
        } else {
            ProgressView()
        }
    }

    private var footerLinks: some View {
        HStack(spacing: 32) {
            Link("Terms", destination: Self.termsURL)
            Link("Privacy", destination: Self.privacyURL)
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
    }

    // MARK: - Actions

    private func buy() async {
        do {
            if try await store.purchase() {
                dismiss()
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func restore() async {
        do {
            isRestoring = true
            try await store.restore()
            isRestoring = false
            if store.isMember {
                dismiss()
            } else {
                errorMessage = String(localized: "No previous purchase found to restore.")
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    // MARK: - Content

    private struct Benefit: Identifiable {
        let id = UUID()
        let systemName: String
        let title: LocalizedStringKey
        let subtitle: LocalizedStringKey
    }

    private static let benefits: [Benefit] = [
        Benefit(systemName: "lock.open.fill",
                title: "Full Features Unlocked",
                subtitle: "Enjoy Anywhere features with no restrictions."),
        Benefit(systemName: "infinity",
                title: "Lifetime Access",
                subtitle: "A single purchase, yours to keep."),
        Benefit(systemName: "person.2.fill",
                title: "Family Sharing",
                subtitle: "Share Voyager with family members."),
        Benefit(systemName: "paintpalette.fill",
                title: "Personalization",
                subtitle: "Build custom themes and use alternate icons."),
        Benefit(systemName: "hammer.fill",
                title: "Public Beta Access",
                subtitle: "Join the TestFlight beta and try new features first."),
        Benefit(systemName: "heart.fill",
                title: "Support Open Source",
                subtitle: "Help Anywhere community thrive.")
    ]

    private static let goldGradient = LinearGradient(
        colors: [Color(hex: 0xFBEFD2), Color(hex: 0xE7C98D)],
        startPoint: .top,
        endPoint: .bottom
    )
}

#Preview {
    VoyagerOnboardingView()
        .environment(VoyagerStore.shared)
}
