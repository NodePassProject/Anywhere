//
//  AppDelegate.swift
//  Anywhere
//
//  Created by NodePassProject on 3/19/26.
//

import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    let container = AppContainer()

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        container.start()
        let operations = Operations(container: container)
        Task { await CloudSync.shared.start { keys in await operations.reload(keys) } }
        return true
    }
}
