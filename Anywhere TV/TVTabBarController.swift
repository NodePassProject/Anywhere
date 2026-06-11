//
//  TVTabBarController.swift
//  Anywhere
//
//  Created by NodePassProject on 3/19/26.
//

import UIKit

class TVTabBarController: UITabBarController {

    override func viewDidLoad() {
        super.viewDidLoad()

        let home = UINavigationController(rootViewController: TVHomeViewController())
        home.tabBarItem = UITabBarItem(title: String(localized: "Home"), image: UIImage(systemName: "house"), tag: 0)

        let proxies = UINavigationController(rootViewController: TVProxiesPageViewController())
        proxies.tabBarItem = UITabBarItem(title: String(localized: "Proxies"), image: UIImage(systemName: "network"), tag: 1)

        let settings = UINavigationController(rootViewController: TVSettingsViewController())
        settings.tabBarItem = UITabBarItem(title: String(localized: "Settings"), image: UIImage(systemName: "gearshape"), tag: 2)

        viewControllers = [home, proxies, settings]
    }
}
