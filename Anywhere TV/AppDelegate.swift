//
//  AppDelegate.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/19/26.
//

import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        window?.rootViewController = TVTabBarController()
        return true
    }
}
