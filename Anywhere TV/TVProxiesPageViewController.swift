//
//  TVProxiesPageViewController.swift
//  Anywhere
//
//  Created by NodePassProject on 6/11/26.
//

import UIKit

class TVProxiesPageViewController: UIViewController {

    private let segmentedControl = UISegmentedControl(items: [
        String(localized: "Servers"),
        String(localized: "Chains"),
    ])
    private let containerView = UIView()
    private let proxiesViewController = TVProxyListViewController()
    private let chainsViewController = TVChainListViewController()
    private weak var currentChild: UIViewController?

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Proxies")

        segmentedControl.selectedSegmentIndex = 0
        segmentedControl.addTarget(self, action: #selector(segmentChanged), for: .valueChanged)
        segmentedControl.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(segmentedControl)

        containerView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(containerView)

        NSLayoutConstraint.activate([
            segmentedControl.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 20),
            segmentedControl.centerXAnchor.constraint(equalTo: view.centerXAnchor),

            containerView.topAnchor.constraint(equalTo: segmentedControl.bottomAnchor, constant: 20),
            containerView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            containerView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            containerView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])

        show(proxiesViewController)
    }

    @objc private func segmentChanged() {
        show(segmentedControl.selectedSegmentIndex == 0 ? proxiesViewController : chainsViewController)
    }

    private func show(_ child: UIViewController) {
        // Selection follows focus on tvOS, so this fires on every focus scrub.
        guard child !== currentChild else { return }

        if let current = currentChild {
            current.willMove(toParent: nil)
            current.view.removeFromSuperview()
            current.removeFromParent()
        }

        addChild(child)
        child.loadViewIfNeeded()
        child.view.frame = containerView.bounds
        child.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        containerView.addSubview(child.view)
        child.didMove(toParent: self)
        currentChild = child

        navigationItem.rightBarButtonItems = child.navigationItem.rightBarButtonItems
        // Data may have changed while the child was detached from the window.
        child.setNeedsUpdateProperties()
    }
}
