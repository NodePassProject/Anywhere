//
//  AppDelegate.swift
//  Anywhere
//
//  Created by NodePassProject on 3/19/26.
//

import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?
    private lazy var container = AppContainer()

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        container.start()
        let operations = Operations(container: container)
        CloudBlobSync.start { await operations.reloadAll() }
        window?.rootViewController = TVTabBarController(container: container)
        return true
    }
}
