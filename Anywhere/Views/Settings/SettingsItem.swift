//
//  SettingsItem.swift
//  Anywhere
//
//  Created by NodePassProject on 6/20/26.
//

import SwiftUI

enum SettingsItem: String, CaseIterable, Identifiable {
    case iCloudSync
    case personalization
    case alwaysOn
    case globalMode
    case adBlocking
    case countryBypass
    case routingRules
    case allowInsecure
    case trustedCertificates
    case trustedNetwork
    case purify
    case reflection
    case mitm

    var id: String { rawValue }

    private var title: String.LocalizationValue {
        switch self {
        case .iCloudSync: "iCloud Sync"
        case .personalization: "Personalization"
        case .alwaysOn: "Always On"
        case .globalMode: "Global Mode"
        case .adBlocking: "AD Blocking"
        case .countryBypass: "Country Bypass"
        case .routingRules: "Routing Rules"
        case .allowInsecure: "Allow Insecure"
        case .trustedCertificates: "Trusted Certificates"
        case .trustedNetwork: "Trusted Network"
        case .purify: "Purify"
        case .reflection: "Reflection"
        case .mitm: "MITM"
        }
    }

    private var systemName: String {
        switch self {
        case .iCloudSync: "icloud.fill"
        case .personalization: "paintpalette.fill"
        case .alwaysOn: "poweron"
        case .globalMode: "arrow.merge"
        case .adBlocking: "shield.checkered"
        case .countryBypass: "globe.americas.fill"
        case .routingRules: "arrow.triangle.branch"
        case .allowInsecure: "exclamationmark.shield.fill"
        case .trustedCertificates: "checkmark.seal.fill"
        case .trustedNetwork: "wifi"
        case .purify: "drop.fill"
        case .reflection: "arrow.turn.up.left"
        case .mitm: "key.horizontal.fill"
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
        case .globalMode: .orange
        case .adBlocking: .red
        case .countryBypass: .blue
        case .routingRules: .purple
        case .allowInsecure: .red
        case .trustedCertificates: .green
        case .trustedNetwork: .blue
        case .purify: .blue
        case .reflection: .pink
        case .mitm: .mint
        }
    }

    var label: some View {
        TextWithColorfulIcon(
            title: title,
            comment: nil,
            systemName: systemName,
            foregroundColor: foregroundColor,
            backgroundColor: backgroundColor
        )
    }
}
