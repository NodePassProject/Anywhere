//
//  ContentView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/3/26.
//

import SwiftUI

struct ContentView: View {
    @Environment(VoyagerStore.self) private var voyagerStore
    @Environment(AppSettings.self) private var settings
    @Environment(VPNViewModel.self) private var viewModel
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(RoutingRuleSetStore.self) private var ruleSetStore
    @Environment(DeepLinkManager.self) private var deepLinkManager
    @State private var onboardingCompleted = AWCore.getOnboardingCompleted()
    @State private var showingDeepLinkAddSheet = false
    @State private var showingManualAddSheet = false
    @State private var pendingDeepLinkURL: String?
    @State private var showingImportRuleSetsSheet = false
    @State private var pendingRuleSetLinks: [URL] = []
    
    private var showOrphanedAlert: Binding<Bool> {
        Binding(
            get: { !ruleSetStore.orphanedRuleSetNames.isEmpty },
            set: { if !$0 { ruleSetStore.acknowledgeOrphans() } }
        )
    }
    
    var body: some View {
        if onboardingCompleted {
            HomeView()
                .environment(VoyagerStore.shared)
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
                .sheet(isPresented: $showingDeepLinkAddSheet, onDismiss: { pendingDeepLinkURL = nil }) {
                    DynamicSheet(animation: .snappy(duration: 0.3, extraBounce: 0)) {
                        AddProxyView(showingManualAddSheet: $showingManualAddSheet, deepLinkURL: pendingDeepLinkURL)
                    }
                }
                .sheet(isPresented: $showingManualAddSheet) {
                    ProxyEditorView { configuration in
                        configStore.add(configuration)
                        viewModel.selectIfNone(configuration)
                    }
                }
                .sheet(isPresented: $showingImportRuleSetsSheet, onDismiss: { pendingRuleSetLinks = [] }) {
                    ImportRuleSetsView(links: pendingRuleSetLinks)
                }
                .fullScreenCover(isPresented: Binding(
                    get: { voyagerStore.isPresentingVoyagerView },
                    set: { voyagerStore.isPresentingVoyagerView = $0 }
                )) {
                    AnywhereVoyagerView()
                        .environment(voyagerStore)
                }
                .alert(String(localized: "Routing Rules Updated"), isPresented: showOrphanedAlert) {
                    Button(String(localized: "OK")) {}
                } message: {
                    let names = ruleSetStore.orphanedRuleSetNames.joined(separator: ", ")
                    Text("The proxy used by the following routing rules was deleted. They have been reset to Default: \(names)")
                }
                .onOpenURL { url in
                    deepLinkManager.handle(url: url)
                }
                .onChange(of: deepLinkManager.url) { _, newValue in
                    if let url = newValue {
                        pendingDeepLinkURL = url
                        deepLinkManager.url = nil
                        showingDeepLinkAddSheet = true
                    }
                }
                .onChange(of: deepLinkManager.ruleSetLinks) { _, newValue in
                    if let links = newValue, !links.isEmpty {
                        pendingRuleSetLinks = links
                        deepLinkManager.ruleSetLinks = nil
                        showingImportRuleSetsSheet = true
                    }
                }
        } else {
            OnboardingView(onboardingCompleted: $onboardingCompleted)
                .environment(RoutingRuleSetStore.shared)
        }
    }
}
