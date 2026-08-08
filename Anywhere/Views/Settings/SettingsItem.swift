//
//  SettingsItem.swift
//  Anywhere
//
//  Created by NodePassProject on 6/20/26.
//

import SwiftUI

enum SettingsItem: String {
    case iCloudSync
    case personalization
    case alwaysOn
    case purify
    case globalMode
    case routingRules
    case allowInsecure
    case trustedCertificates
    case trustedNetwork
    case mitm
    case logs
    case requests

    private var title: String.LocalizationValue {
        switch self {
        case .iCloudSync: "iCloud Sync"
        case .personalization: "Personalization"
        case .alwaysOn: "Always On"
        case .purify: "Purify"
        case .globalMode: "Global Mode"
        case .routingRules: "Routing Rules"
        case .allowInsecure: "Allow Insecure"
        case .trustedCertificates: "Trusted Certificates"
        case .trustedNetwork: "Trusted Network"
        case .mitm: "MITM"
        case .logs: "Logs"
        case .requests: "Requests"
        }
    }

    private var systemName: String {
        switch self {
        case .iCloudSync: "icloud.fill"
        case .personalization: "paintpalette.fill"
        case .alwaysOn: "poweron"
        case .purify: "drop.fill"
        case .globalMode: "arrow.merge"
        case .routingRules: "arrow.triangle.branch"
        case .allowInsecure: "exclamationmark.shield.fill"
        case .trustedCertificates: "checkmark.seal.fill"
        case .trustedNetwork: "wifi"
        case .mitm: "key.horizontal.fill"
        case .logs:
            if #available(iOS 18.4, *) {
                "info.circle.text.page.fill"
            } else {
                "info"
            }
        case .requests: "mail.fill"
        }
    }

    private var foregroundColor: Color {
        switch self {
        case .iCloudSync: .blue
        default: .white
        }
    }

    private var backgroundColor: Color {
        switch self {
        case .iCloudSync: .white
        case .personalization: .pink
        case .alwaysOn: .green
        case .purify: .blue
        case .globalMode: .orange
        case .routingRules: .purple
        case .allowInsecure: .red
        case .trustedCertificates: .green
        case .trustedNetwork: .blue
        case .mitm: .teal
        case .logs: .blue
        case .requests: .blue
        }
    }

    var label: some View {
        TextWithColorfulIcon(
            title: title,
            comment: nil,
            systemName: systemName,
            foregroundStyle: foregroundColor,
            backgroundStyle: backgroundColor.gradient
        )
    }
}
