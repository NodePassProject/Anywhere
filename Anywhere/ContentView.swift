//
//  ContentView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/3/26.
//

import SwiftUI

struct ContentView: View {
    @Environment(AppState.self) private var appState
    @Environment(AppSettings.self) private var settings
    @Environment(Operations.self) private var operations
    @Environment(DeepLinkManager.self) private var deepLinkManager
    @State private var onboardingCompleted = AWCore.getOnboardingCompleted()
    @State private var showingDeepLinkAddSheet = false
    @State private var showingManualAddSheet = false
    @State private var pendingDeepLinkURL: String?
    @State private var showingImportRuleSetSheet = false
    @State private var pendingRuleSetLink: URL?
    @State private var showingImportModuleSheet = false
    @State private var pendingModuleLink: URL?
    
    private var showOrphanedAlert: Binding<Bool> {
        Binding(
            get: { !appState.orphanedRuleSetNames.isEmpty },
            set: { if !$0 { appState.orphanedRuleSetNames = [] } }
        )
    }
    
    var body: some View {
        if onboardingCompleted {
            HomeView()
                .sheet(isPresented: $showingDeepLinkAddSheet, onDismiss: { pendingDeepLinkURL = nil }) {
                    DynamicSheet(animation: .snappy(duration: 0.3, extraBounce: 0)) {
                        AddProxyView(showingManualAddSheet: $showingManualAddSheet, deepLinkURL: pendingDeepLinkURL)
                    }
                }
                .sheet(isPresented: $showingManualAddSheet) {
                    ProxyEditorView { configuration in
                        operations.configurations.add(configuration)
                        operations.selection.selectIfNone(configuration)
                    }
                }
                .sheet(isPresented: $showingImportRuleSetSheet, onDismiss: { pendingRuleSetLink = nil }) {
                    if let link = pendingRuleSetLink {
                        ImportRuleSetView(link: link)
                    }
                }
                .sheet(isPresented: $showingImportModuleSheet, onDismiss: { pendingModuleLink = nil }) {
                    if let link = pendingModuleLink {
                        ImportModuleView(link: link)
                    }
                }
                .alert(String(localized: "Routing Rules Updated"), isPresented: showOrphanedAlert) {
                    Button(String(localized: "OK")) {}
                } message: {
                    let names = appState.orphanedRuleSetNames.joined(separator: ", ")
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
                .onChange(of: deepLinkManager.ruleSetLink) { _, newValue in
                    if let link = newValue {
                        pendingRuleSetLink = link
                        deepLinkManager.ruleSetLink = nil
                        showingImportRuleSetSheet = true
                    }
                }
                .onChange(of: deepLinkManager.moduleLink) { _, newValue in
                    if let link = newValue {
                        pendingModuleLink = link
                        deepLinkManager.moduleLink = nil
                        showingImportModuleSheet = true
                    }
                }
        } else {
            OnboardingView(onboardingCompleted: $onboardingCompleted)
        }
    }
}
