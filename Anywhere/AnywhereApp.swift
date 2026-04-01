//
//  AnywhereApp.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/23/26.
//

import SwiftUI

@main
struct AnywhereApp: App {
    @State private var onboardingCompleted = AWCore.userDefaults.bool(forKey: "onboardingCompleted")
    @StateObject private var deepLinkManager = DeepLinkManager()

    var body: some Scene {
        WindowGroup {
            if onboardingCompleted {
                ContentView()
                    .environmentObject(deepLinkManager)
                    .onOpenURL { url in
                        deepLinkManager.handle(url: url)
                    }
            } else {
                OnboardingView(onboardingCompleted: $onboardingCompleted)
            }
        }
    }
}
