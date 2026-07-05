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

        tabs = [
            UITab(title: String(localized: "Home"), image: UIImage(systemName: "house"), identifier: "home") { _ in
                UINavigationController(rootViewController: TVHomeViewController())
            },
            UITab(title: String(localized: "Proxies"), image: UIImage(systemName: "network"), identifier: "proxies") { _ in
                UINavigationController(rootViewController: TVProxiesPageViewController())
            },
            UITab(title: String(localized: "Settings"), image: UIImage(systemName: "gearshape"), identifier: "settings") { _ in
                UINavigationController(rootViewController: TVSettingsViewController())
            }
        ]
    }
}
