//
//  VPNStatus.swift
//  Anywhere
//
//  Created by NodePassProject on 7/4/26.
//

import Foundation

enum VPNStatus: Int, Codable {
    case invalid
    case disconnected
    case connecting
    case connected
    case reasserting
    case disconnecting

    var isTransitioning: Bool {
        self == .connecting || self == .disconnecting || self == .reasserting
    }
    
    var localizedText: String {
        switch self {
        case .connected:
            return String(localized: "Connected")
        case .connecting:
            return String(localized: "Connecting")
        case .disconnecting:
            return String(localized: "Disconnecting")
        case .reasserting:
            return String(localized: "Reconnecting")
        case .disconnected:
            return String(localized: "Disconnected")
        case .invalid:
            return String(localized: "Not Configured")
        }
    }
}
