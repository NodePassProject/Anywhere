//
//  TVTabBarController.swift
//  Anywhere TV
//
//  Created by Argsment Limited on 3/19/26.
//

import UIKit

class TVTabBarController: UITabBarController {

    override func viewDidLoad() {
        super.viewDidLoad()

        let home = UINavigationController(rootViewController: TVHomeViewController())
        home.tabBarItem = UITabBarItem(title: String(localized: "Home"), image: UIImage(systemName: "house"), tag: 0)

        let proxies = UINavigationController(rootViewController: TVProxyListViewController())
        proxies.tabBarItem = UITabBarItem(title: String(localized: "Proxies"), image: UIImage(systemName: "network"), tag: 1)

        let chains = UINavigationController(rootViewController: TVChainListViewController())
        chains.tabBarItem = UITabBarItem(title: String(localized: "Chains"), image: UIImage(systemName: "point.bottomleft.forward.to.point.topright.scurvepath.fill"), tag: 2)

        let settings = UINavigationController(rootViewController: TVSettingsViewController())
        settings.tabBarItem = UITabBarItem(title: String(localized: "Settings"), image: UIImage(systemName: "gearshape"), tag: 3)

        viewControllers = [home, proxies, chains, settings]
    }
}
