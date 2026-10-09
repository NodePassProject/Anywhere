//
//  Page.swift
//  Anywhere
//
//  Created by NodePassProject on 9/23/26.
//

import Foundation

enum Page: Equatable, Hashable, Identifiable, CaseIterable {
    case launchpad
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
        case .toolbox: 1
        case .data: 2
        case .personalization: 3
        case .tunnel: 4
        case .purify: 5
        case .routing: 6
        case .mitm: 7
        case .modules: 8
        case .trustedCertificates: 9
        case .trustedNetwork: 10
        case .diagnosis: 11
        case .about: 12
        }
    }
    
    var name: String {
        switch self {
        case .launchpad: String(localized: "Launchpad")
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
