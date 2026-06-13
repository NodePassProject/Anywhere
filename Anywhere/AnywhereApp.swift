//
//  AnywhereApp.swift
//  Anywhere
//
//  Created by NodePassProject on 1/23/26.
//

import SwiftUI

@main
struct AnywhereApp: App {
    init() {
        CloudBlobSync.start()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
