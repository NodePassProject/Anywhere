//
//  Page.swift
//  Anywhere
//
//  Created by NodePassProject on 9/23/26.
//

import Foundation

enum Page: Equatable, Hashable, Identifiable, CaseIterable {
    case launchpad
    case dashboard
    case toolbox
    case data
    case personalization
    case tunnel
    case purify
    case routing
    case mitm
    case modules
    case trustedCertificates
    case trustedNetwork
    case diagnosis
    case about
    
    var id: Int {
        switch self {
        case .launchpad: 0
        case .dashboard: 1
        case .toolbox: 2
        case .data: 3
        case .personalization: 4
        case .tunnel: 5
        case .purify: 6
        case .routing: 7
        case .mitm: 8
        case .modules: 9
        case .trustedCertificates: 10
        case .trustedNetwork: 11
        case .diagnosis: 12
        case .about: 13
        }
    }
    
    var name: String {
        switch self {
        case .launchpad: String(localized: "Launchpad")
        case .dashboard: String(localized: "Dashboard")
        case .toolbox: String(localized: "Toolbox")
        case .data: String(localized: "Data")
        case .personalization: String(localized: "Personalization")
        case .tunnel: String(localized: "Tunnel")
        case .purify: String(localized: "Purify")
        case .routing: String(localized: "Routing")
        case .mitm: String(localized: "MITM")
        case .modules: String(localized: "Modules")
        case .trustedCertificates: String(localized: "Trusted Certificates")
        case .trustedNetwork: String(localized: "Trusted Network")
        case .diagnosis: String(localized: "Diagnosis")
        case .about: String(localized: "About")
        }
    }
    
    var symbol: String {
        switch self {
        case .launchpad: "anywhere"
        case .dashboard: "rectangle.3.group"
        case .toolbox: "latch.2.case"
        case .data: "cylinder.split.1x2"
        case .personalization: "paintpalette"
        case .tunnel: "hammer"
        case .purify: "drop"
        case .routing: "arrow.triangle.branch"
        case .mitm: "key.horizontal"
        case .modules: "shippingbox"
        case .trustedCertificates: "checkmark.seal"
        case .trustedNetwork: "wifi"
        case .diagnosis: "stethoscope"
        case .about: "info.circle"
        }
    }
}
