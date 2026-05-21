//
//  HysteriaCongestionControl.swift
//  Anywhere
//
//  Created by NodePassProject on 5/21/26.
//

import Foundation

/// Congestion controller for `.hysteria`. `brutal` paces each direction at a
/// fixed user-configured rate; `bbr` lets the connection adapt and asks the
/// server to run its own bandwidth detection.
enum HysteriaCongestionControl: String, Codable, Hashable, CaseIterable {
    case brutal
    case bbr

    var displayName: String {
        switch self {
        case .brutal: return "Brutal"
        case .bbr: return "BBR"
        }
    }

    // MARK: - Brutal bandwidth knobs
    //
    // Mbit/s ranges and defaults for the user-configured upload/download
    // rates. Only meaningful under `.brutal`. The clamps are applied at every
    // construction boundary (URL, dict, Clash, Codable) so the associated
    // values on `Outbound.hysteria` are always valid regardless of source.

    static let uploadMbpsRange: ClosedRange<Int> = 0...1000
    static let uploadMbpsDefault: Int = 20
    static let downloadMbpsRange: ClosedRange<Int> = 0...1000
    static let downloadMbpsDefault: Int = 50

    static func clampUploadMbps(_ raw: Int) -> Int {
        max(uploadMbpsRange.lowerBound, min(uploadMbpsRange.upperBound, raw))
    }

    static func clampDownloadMbps(_ raw: Int) -> Int {
        max(downloadMbpsRange.lowerBound, min(downloadMbpsRange.upperBound, raw))
    }
}
