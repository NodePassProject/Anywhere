//
//  AnywhereApp.swift
//  Anywhere
//
//  Created by NodePassProject on 1/23/26.
//

import SwiftUI

@main
struct AnywhereApp: App {
    @State private var container: AppContainer
    @State private var settings: AppSettings
    @State private var voyagerStore = VoyagerStore()
    @State private var mitmCertificateController = MITMCertificateController()
    @State private var deepLinkManager = DeepLinkManager()
    @State private var watchSession: WatchSessionManager

    init() {
        let container = AppContainer()

        let settings = AppSettings()
        settings.onTunnelBehaviorChange = { [weak tunnel = container.tunnel] in
            tunnel?.reconnect()
        }

        let watchSession = WatchSessionManager(
            tunnel: container.tunnel,
            selection: container.selection,
            configurationStore: container.configurationStore,
            chainStore: container.chainStore,
            subscriptionStore: container.subscriptionStore
        )
        watchSession.start()

        let coordinator = container.coordinator
        CloudBlobSync.start { await coordinator.reloadAll() }

        _container = State(initialValue: container)
        _settings = State(initialValue: settings)
        _watchSession = State(initialValue: watchSession)
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(container)
                .environment(container.appState)
                .environment(container.tunnel)
                .environment(container.selection)
                .environment(container.latency)
                .environment(container.stats)
                .environment(container.configurationStore)
                .environment(container.chainStore)
                .environment(container.groupStore)
                .environment(container.subscriptionStore)
                .environment(container.routingRuleSetStore)
                .environment(container.mitmRuleSetStore)
                .environment(container.certificateStore)
                .environment(settings)
                .environment(voyagerStore)
                .environment(mitmCertificateController)
                .environment(deepLinkManager)
        }
    }
}
