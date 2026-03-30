//
//  OnboardingView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/9/26.
//

import Foundation
import SwiftUI

struct OnboardingView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared
    @Binding var onboardingCompleted: Bool

    @AppStorage("bypassCountryCode", store: AWCore.userDefaults)
    private var bypassCountryCode = ""

    @State private var currentPage = 0
    @State private var isGoingForward = true
    @State private var adBlockEnabled = false

    var body: some View {
        VStack(spacing: 0) {
            VStack {
                switch currentPage {
                case 0: countryBypassPage
                default: adBlockPage
                }
            }
            .animation(.default, value: currentPage)
            
            bottomBar
                .padding(.horizontal, 24)
                .padding(.bottom, 16)
        }
        .background(
            LinearGradient(
                colors: [Color("GradientStart"), Color("GradientEnd")],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()
        )
        .onAppear {
            if let country = CountryBypassCatalog.shared.suggestedCountryCode() {
                bypassCountryCode = country
            }
        }
    }

    // MARK: - Bottom Bar

    private var bottomBar: some View {
        HStack {
            if currentPage > 0 {
                Button {
                    isGoingForward = false
                    currentPage -= 1
                } label: {
                    Text("Back")
                        .fontWeight(.medium)
                        .foregroundStyle(.white.opacity(0.7))
                }
            }

            Spacer()

            Button {
                if currentPage < 1 {
                    isGoingForward = true
                    currentPage += 1
                } else {
                    finishOnboarding()
                }
            } label: {
                Text(currentPage < 1 ? "Next" : "Get Started")
                    .fontWeight(.semibold)
                    .foregroundStyle(.white)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 12)
                    .background(.white.opacity(0.2), in: Capsule())
            }
            .buttonStyle(.plain)
        }
        .padding(.top, 8)
    }

    // MARK: - Page 1: Country Bypass

    private var countryBypassPage: some View {
        VStack {
            VStack(spacing: 24) {
                Spacer(minLength: 40)

                Image(systemName: "globe.americas.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(.white.opacity(0.9))

                VStack(spacing: 8) {
                    Text("Country Bypass")
                        .font(.title.bold())
                        .foregroundStyle(.white)
                    Text("Route traffic to your home country directly, bypassing the proxy for faster local access.")
                        .font(.subheadline)
                        .foregroundStyle(.white.opacity(0.7))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
                
                ScrollView {
                    VStack(spacing: 0) {
                        Button {
                            bypassCountryCode = ""
                        } label: {
                            HStack {
                                Text("Disable")
                                    .foregroundStyle(.white)
                                Spacer()
                                if bypassCountryCode == "" {
                                    Image(systemName: "checkmark")
                                        .fontWeight(.semibold)
                                        .foregroundStyle(.white)
                                }
                            }
                            .padding(.horizontal, 16)
                            .padding(.vertical, 12)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        ForEach(CountryBypassCatalog.shared.supportedCountryCodes, id: \.self) { code in
                            Divider().opacity(0.3)
                            countryRow(code: code) {
                                bypassCountryCode = code
                            }
                        }
                    }
                    .background(.white.opacity(0.2), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                    .padding(.horizontal, 24)
                }
            }
        }
    }

    @ViewBuilder
    private func countryRow(code: String, action: @escaping () -> Void) -> some View {
        let name = Locale.current.localizedString(forRegionCode: code) ?? code
        Button(action: action) {
            HStack {
                Text("\(flag(for: code)) \(name)")
                    .foregroundStyle(.white)
                Spacer()
                if bypassCountryCode == code {
                    Image(systemName: "checkmark")
                        .fontWeight(.semibold)
                        .foregroundStyle(.white)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    // MARK: - Page 2: AD Block

    private var adBlockPage: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "shield.checkered")
                .font(.system(size: 56))
                .foregroundStyle(.white.opacity(0.9))

            VStack(spacing: 8) {
                Text("AD Blocking")
                    .font(.title.bold())
                    .foregroundStyle(.white)
                Text("Block ads and trackers at the network level for a cleaner browsing experience.")
                    .font(.subheadline)
                    .foregroundStyle(.white.opacity(0.7))
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            Button {
                withAnimation(.spring(response: 0.4, dampingFraction: 0.7)) {
                    adBlockEnabled.toggle()
                }
            } label: {
                HStack {
                    Image(systemName: adBlockEnabled ? "checkmark.shield.fill" : "shield.slash")
                        .font(.title2)
                        .foregroundStyle(adBlockEnabled ? .green : .white.opacity(0.5))
                        .contentTransition(.symbolEffect(.replace))
                    Text("Enable AD Blocking")
                        .font(.body.weight(.medium))
                        .foregroundStyle(.white)
                    Spacer()
                    Toggle("", isOn: $adBlockEnabled)
                        .labelsHidden()
                }
                .padding(16)
                .background(.white.opacity(0.2), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 24)

            Spacer()
            Spacer()
        }
    }

    // MARK: - Actions

    private func finishOnboarding() {
        // Trigger a network request to prompt the local network permission
        // dialog on China devices.
        triggerNetworkPermission()

        // Apply AD block setting
        if adBlockEnabled {
            if let adBlock = RuleSetStore.shared.ruleSets.first(where: { $0.name == "ADBlock" }) {
                RuleSetStore.shared.updateAssignment(adBlock, configurationId: "REJECT")
            }
        }

        // Sync routing to network extension
        Task { await viewModel.syncRoutingConfigurationToNE() }

        // Notify settings changed for country bypass
        if !bypassCountryCode.isEmpty {
            notifySettingsChanged()
        }
        
        AWCore.userDefaults.set(true, forKey: "onboardingCompleted")

        withAnimation {
            onboardingCompleted = true
        }
    }

    // MARK: - Helpers

    private func flag(for countryCode: String) -> String {
        String(countryCode.unicodeScalars.compactMap {
            UnicodeScalar(127397 + $0.value)
        }.map(Character.init))
    }

    /// Fire-and-forget request to 1.1.1.1 to trigger the network permission
    /// dialog on China-region devices.
    private func triggerNetworkPermission() {
        guard let url = URL(string: "http://1.1.1.1") else { return }
        URLSession.shared.dataTask(with: url) { _, _, _ in }.resume()
    }

    private func notifySettingsChanged() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName("com.argsment.Anywhere.settingsChanged" as CFString),
            nil, nil, true
        )
    }
}
