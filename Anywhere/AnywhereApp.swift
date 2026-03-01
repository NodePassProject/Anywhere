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

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(vpnViewModel)
        }
    }
}
