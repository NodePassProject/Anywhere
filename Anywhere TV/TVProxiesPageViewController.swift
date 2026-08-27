//
//  TVProxiesPageViewController.swift
//  Anywhere
//
//  Created by NodePassProject on 6/11/26.
//

import UIKit

class TVProxiesPageViewController: UIViewController {

    private let container: AppContainer
    private let containerView = UIView()
    private let proxiesViewController: TVProxyListViewController
    private let chainsViewController: TVChainListViewController
    private weak var currentChild: UIViewController?

    private lazy var moreItem: UIBarButtonItem = {
        let menu = UIMenu(children: [
            UIDeferredMenuElement.uncached { [weak self] completion in
                completion(self?.moreMenuElements() ?? [])
            }
        ])
        let configuration = UIImage.SymbolConfiguration(pointSize: 40, weight: .medium)
        let image = UIImage(systemName: "ellipsis", withConfiguration: configuration)
        let item = UIBarButtonItem(image: image, menu: menu)
        item.tintColor = .label
        item.accessibilityLabel = String(localized: "More")
        return item
    }()

    init(container: AppContainer) {
        self.container = container
        self.proxiesViewController = TVProxyListViewController(container: container)
        self.chainsViewController = TVChainListViewController(container: container)
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Proxies")

        navigationItem.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .cancel, target: self, action: #selector(cancelTapped)
        )

        containerView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(containerView)

        NSLayoutConstraint.activate([
            containerView.topAnchor.constraint(equalTo: view.topAnchor),
            containerView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            containerView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            containerView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])

        show(AWCore.getProxiesPageProxyType() == "chains" ? chainsViewController : proxiesViewController)
    }

    @objc private func cancelTapped() {
        dismiss(animated: true)
    }

    // MARK: - More Menu

    private func moreMenuElements() -> [UIMenuElement] {
        let showingServers = currentChild === proxiesViewController

        let typePicker = UIMenu(options: [.displayInline, .singleSelection], children: [
            UIAction(
                title: String(localized: "Servers"),
                image: UIImage(systemName: "server.rack"),
                state: showingServers ? .on : .off
            ) { [weak self] _ in
                guard let self else { return }
                self.show(self.proxiesViewController)
            },
            UIAction(
                title: String(localized: "Chains"),
                image: UIImage(systemName: "point.bottomleft.forward.to.point.topright.scurvepath.fill"),
                state: showingServers ? .off : .on
            ) { [weak self] _ in
                guard let self else { return }
                self.show(self.chainsViewController)
            },
        ])

        var elements: [UIMenuElement] = [typePicker]
        if showingServers, !container.subscriptionStore.subscriptions.isEmpty {
            elements.append(UIMenu(options: .displayInline, children: [
                UIAction(title: String(localized: "Update Subscriptions"), image: UIImage(systemName: "arrow.clockwise")) { [weak self] _ in
                    self?.proxiesViewController.updateAllSubscriptions()
                }
            ]))
        }
        return elements
    }

    // MARK: - Children

    private func show(_ child: UIViewController) {
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

        navigationItem.rightBarButtonItems = [moreItem] + (child.navigationItem.rightBarButtonItems ?? [])
        AWCore.setProxiesPageProxyType(child === proxiesViewController ? "servers" : "chains")
        child.setNeedsUpdateProperties()
    }
}
