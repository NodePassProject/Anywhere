//
//  AnywhereApp.swift
//  Anywhere
//
//  Created by NodePassProject on 1/23/26.
//

import SwiftUI

@main
struct AnywhereApp: App {
    @State private var onboardingCompleted = AWCore.getOnboardingCompleted()
    @State private var deepLinkManager = DeepLinkManager()
    
    var body: some Scene {
        WindowGroup {
            if onboardingCompleted {
                ContentView()
                    .onOpenURL { url in
                        deepLinkManager.handle(url: url)
                    }
                    .environment(VPNViewModel.shared)
                    .environment(ConfigurationStore.shared)
                    .environment(SubscriptionStore.shared)
                    .environment(ChainStore.shared)
                    .environment(ConnectionStatsModel.shared)
                    .environment(RequestsModel.shared)
                    .environment(LogsModel.shared)
                    .environment(RoutingRuleSetStore.shared)
                    .environment(CertificateStore.shared)
                    .environment(MITMRuleSetStore.shared)
                    .environment(MITMCertificateController.shared)
                    .environment(deepLinkManager)
            } else {
                OnboardingView(onboardingCompleted: $onboardingCompleted)
                    .environment(RoutingRuleSetStore.shared)
            }
        }
    }
}
