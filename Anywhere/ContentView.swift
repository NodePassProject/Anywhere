//
//  ContentView.swift
//  Anywhere
//
//  Created by NodePassProject on 1/23/26.
//

import SwiftUI

struct ContentView: View {
    @State private var onboardingCompleted = AWCore.getOnboardingCompleted()
    @State private var deepLinkManager = DeepLinkManager()
    
    var body: some View {
        if onboardingCompleted {
            MainTabView()
                .onOpenURL { url in
                    deepLinkManager.handle(url: url)
                }
                .environment(AppSettings.shared)
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
