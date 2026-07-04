//
//  AnywhereApp.swift
//  Anywhere
//
//  Created by NodePassProject on 7/4/26.
//

import SwiftUI

@main
struct AnywhereApp: App {
    init() {
        PhoneSession.shared.start()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(PhoneSession.shared)
        }
    }
}
