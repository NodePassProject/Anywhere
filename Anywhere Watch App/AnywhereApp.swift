//
//  AnywhereApp.swift
//  Anywhere
//
//  Created by NodePassProject on 7/4/26.
//

import SwiftUI

@main
struct AnywhereApp: App {
    @State private var session: PhoneSession

    init() {
        let session = PhoneSession()
        session.start()
        _session = State(initialValue: session)
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(session)
        }
    }
}
