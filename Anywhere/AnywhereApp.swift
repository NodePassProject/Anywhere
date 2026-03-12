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

    var body: some Scene {
        WindowGroup {
            if onboardingCompleted {
                ContentView()
            } else {
                OnboardingView(onboardingCompleted: $onboardingCompleted)
            }
        }
    }
}
