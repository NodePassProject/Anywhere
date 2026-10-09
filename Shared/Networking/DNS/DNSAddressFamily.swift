//
//  DNSAddressFamily.swift
//  Anywhere
//
//  Created by NodePassProject on 10/9/26.
//

import Foundation

nonisolated enum DNSAddressFamily: Sendable, Hashable {
    case ipv4
    case ipv6
    case preferIPv4

    func admits(_ address: String) -> Bool {
        switch self {
        case .ipv4: return !address.contains(":")
        case .ipv6: return address.contains(":")
        case .preferIPv4: return true
        }
    }
}
