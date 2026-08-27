//
//  TVTunnelViewController.swift
//  Anywhere
//
//  Created by NodePassProject on 8/27/26.
//

import UIKit

class TVTunnelViewController: TVSettingsPageViewController {
    private lazy var operations = Operations(container: container)
    private let alwaysOnRow = TVToggleRow(title: String(localized: "Always On"))

    init(container: AppContainer) {
        super.init(container: container, pageTitle: String(localized: "Tunnel"))
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        alwaysOnRow.addTarget(self, action: #selector(alwaysOnTapped), for: .primaryActionTriggered)
        alwaysOnRow.setOn(AWCore.getAlwaysOnEnabled())
        addRow(alwaysOnRow)
        addFooter(String(localized: "Automatically reconnect VPN when it is disconnected."))
    }

    override func updateProperties() {
        super.updateProperties()
        alwaysOnRow.isEnabled = !container.tunnel.pendingReconnect
    }

    @objc private func alwaysOnTapped() {
        let newValue = !AWCore.getAlwaysOnEnabled()
        AWCore.setAlwaysOnEnabled(newValue)
        alwaysOnRow.setOn(newValue)
        operations.tunnel.reconnect()
    }
}
