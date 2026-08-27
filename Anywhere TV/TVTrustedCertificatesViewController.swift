//
//  TVTrustedCertificatesViewController.swift
//  Anywhere
//
//  Created by NodePassProject on 8/27/26.
//

import UIKit

class TVTrustedCertificatesViewController: TVSettingsPageViewController {
    private let insecureRow = TVToggleRow(title: String(localized: "Allow Insecure"), onColor: .systemRed)

    init(container: AppContainer) {
        super.init(container: container, pageTitle: String(localized: "Trusted Certificates"))
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        insecureRow.addTarget(self, action: #selector(insecureTapped), for: .primaryActionTriggered)
        insecureRow.setOn(AWCore.getAllowInsecure())
        addRow(insecureRow)
        addFooter(String(localized: "This will skip TLS certificate validation, making your connections vulnerable to MITM attacks."))
    }

    @objc private func insecureTapped() {
        if AWCore.getAllowInsecure() {
            setAllowInsecure(false)
        } else {
            let alert = UIAlertController(
                title: String(localized: "Allow Insecure"),
                message: String(localized: "This will skip TLS certificate validation, making your connections vulnerable to MITM attacks."),
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: String(localized: "Allow Anyway"), style: .destructive) { [weak self] _ in
                self?.setAllowInsecure(true)
            })
            alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
            present(alert, animated: true)
        }
    }

    private func setAllowInsecure(_ value: Bool) {
        AWCore.setAllowInsecure(value)
        AWNotificationCenter.notifyCertificatePolicyChanged()
        insecureRow.setOn(value)
    }
}
