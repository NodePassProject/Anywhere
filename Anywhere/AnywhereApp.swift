//
//  AnywhereApp.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/23/26.
//

import SwiftUI

@main
struct AnywhereApp: App {
    @State private var vpnViewModel = VPNViewModel()
    @AppStorage("onboardingCompleted", store: AWCore.userDefaults)
    private var onboardingCompleted = false

    var body: some Scene {
        WindowGroup {
            if onboardingCompleted {
                ContentView()
                    .environment(vpnViewModel)
            } else {
                OnboardingView()
                    .environment(vpnViewModel)
            }
        }
    }
}
