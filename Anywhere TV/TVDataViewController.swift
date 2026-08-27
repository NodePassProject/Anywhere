//
//  TVDataViewController.swift
//  Anywhere
//
//  Created by NodePassProject on 8/27/26.
//

import UIKit

class TVDataViewController: TVSettingsPageViewController {
    private let iCloudSyncRow = TVToggleRow(title: String(localized: "iCloud Sync"))

    init(container: AppContainer) {
        super.init(container: container, pageTitle: String(localized: "Data"))
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        iCloudSyncRow.addTarget(self, action: #selector(iCloudSyncTapped), for: .primaryActionTriggered)
        iCloudSyncRow.setOn(AWCore.getICloudSyncEnabled())
        addRow(iCloudSyncRow)
        addFooter(String(localized: "Sync your data across your devices with iCloud."))
    }

    @objc private func iCloudSyncTapped() {
        let newValue = !AWCore.getICloudSyncEnabled()
        AWCore.setICloudSyncEnabled(newValue)
        iCloudSyncRow.setOn(newValue)
        Task { await CloudSync.shared.syncEnabledDidChange() }
    }
}
