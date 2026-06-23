//
//  HysteriaObfuscation.swift
//  Anywhere
//
//  Created by NodePassProject on 6/23/26.
//

import Foundation

/// Hysteria2 packet obfuscation: `salamander` (XOR keystream) or `gecko` (adds handshake fragmentation).
enum HysteriaObfuscation: Hashable {
    case salamander(password: String)
    case gecko(password: String, minPacketSize: Int, maxPacketSize: Int)

    var password: String {
        switch self {
        case .salamander(let password): return password
        case .gecko(let password, _, _): return password
        }
    }

    /// Wire tag used in `hysteria2://` links, Clash YAML, and stored JSON.
    var typeTag: String {
        switch self {
        case .salamander: return "salamander"
        case .gecko: return "gecko"
        }
    }

    // Gecko packet-size bounds, in bytes.
    static let geckoMinPacketSizeDefault = 512
    static let geckoMaxPacketSizeDefault = 1200
    static let geckoPacketSizeRange: ClosedRange<Int> = 0...2048

    /// Normalizes gecko bounds: absent/non-positive values fall back to the defaults, both are
    /// clamped to `geckoPacketSizeRange`, and an inverted `max` is raised to `min`.
    static func normalizedGeckoSizes(min rawMin: Int?, max rawMax: Int?) -> (min: Int, max: Int) {
        func clamp(_ value: Int) -> Int {
            Swift.max(geckoPacketSizeRange.lowerBound, Swift.min(geckoPacketSizeRange.upperBound, value))
        }
        let lo = clamp((rawMin ?? 0) > 0 ? rawMin! : geckoMinPacketSizeDefault)
        let hi = clamp((rawMax ?? 0) > 0 ? rawMax! : geckoMaxPacketSizeDefault)
        return hi >= lo ? (lo, hi) : (lo, lo)
    }

    /// Builds an obfuscation config from a wire `type` string, normalizing gecko sizes.
    /// Returns `nil` for an empty or unrecognized type, letting callers decide whether to treat
    /// that as "no obfuscation" or as an unsupported node to skip.
    static func make(type rawType: String?, password: String?,
                     geckoMinPacketSize: Int? = nil, geckoMaxPacketSize: Int? = nil) -> HysteriaObfuscation? {
        guard let rawType, !rawType.isEmpty else { return nil }
        let password = password ?? ""
        switch rawType.lowercased() {
        case "salamander":
            return .salamander(password: password)
        case "gecko":
            let sizes = normalizedGeckoSizes(min: geckoMinPacketSize, max: geckoMaxPacketSize)
            return .gecko(password: password, minPacketSize: sizes.min, maxPacketSize: sizes.max)
        default:
            return nil
        }
    }
}
