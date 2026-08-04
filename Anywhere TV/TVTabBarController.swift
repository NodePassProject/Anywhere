//
//  TVTabBarController.swift
//  Anywhere
//
//  Created by NodePassProject on 3/19/26.
//

import UIKit

class TVTabBarController: UITabBarController {

    private let container: AppContainer

    init(container: AppContainer) {
        self.container = container
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        tabs = [
            UITab(title: String(localized: "Home"), image: UIImage(systemName: "house"), identifier: "home") { [container] _ in
                UINavigationController(rootViewController: TVHomeViewController(container: container))
            },
            UITab(title: String(localized: "Proxies"), image: UIImage(systemName: "network"), identifier: "proxies") { [container] _ in
                UINavigationController(rootViewController: TVProxiesPageViewController(container: container))
            },
            UITab(title: String(localized: "Settings"), image: UIImage(systemName: "gearshape"), identifier: "settings") { [container] _ in
                UINavigationController(rootViewController: TVSettingsViewController(container: container))
            }
        ]
    }
}
