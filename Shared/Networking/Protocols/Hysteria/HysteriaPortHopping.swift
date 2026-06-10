//
//  HysteriaPortHopping.swift
//  Anywhere
//
//  Created by NodePassProject on 6/10/26.
//

import Foundation

/// Hysteria "port hopping" (a.k.a. multi-port / port jumping): the client rotates the UDP
/// destination port across a configured set on a fixed interval.
///
/// Spec format follows the conventions seen in the wild: comma- or whitespace-separated entries,
/// each either a single port (`443`) or an inclusive range using `-` or `:` (`5000-6000`,
/// `5000:6000`). Examples: `"20000-50000"`, `"443,5000-6000"`.
struct HysteriaPortHopping: Hashable, Codable {
    /// Raw spec exactly as configured/imported; preserved so links and stored configs round-trip.
    let portsSpec: String
    /// Seconds between hops.
    let intervalSeconds: Int

    /// Matches Hysteria's default hop interval.
    static let defaultIntervalSeconds = 30

    init(portsSpec: String, intervalSeconds: Int = HysteriaPortHopping.defaultIntervalSeconds) {
        self.portsSpec = portsSpec
        self.intervalSeconds = intervalSeconds > 0 ? intervalSeconds : HysteriaPortHopping.defaultIntervalSeconds
    }

    /// Parsed inclusive ranges, or `nil` when the spec yields no valid port.
    var ranges: [ClosedRange<UInt16>]? { Self.parseRanges(portsSpec) }

    /// Builds a config from a possibly-absent spec, returning `nil` when the spec is missing,
    /// empty, or parses to no valid port. `intervalSeconds` falls back to the default when absent.
    /// Centralizes the "absent/empty/invalid → no hopping" decision for the lenient importers.
    static func make(spec: String?, intervalSeconds: Int?) -> HysteriaPortHopping? {
        guard let spec, parseRanges(spec) != nil else { return nil }
        return HysteriaPortHopping(portsSpec: spec,
                                   intervalSeconds: intervalSeconds ?? defaultIntervalSeconds)
    }

    /// Parses the spec into normalized inclusive ranges. Reversed bounds are swapped; empty,
    /// non-numeric, or out-of-range (`0` / `>65535`) tokens are skipped. Returns `nil` if nothing
    /// parses, which callers treat as "port hopping disabled".
    static func parseRanges(_ spec: String) -> [ClosedRange<UInt16>]? {
        var result: [ClosedRange<UInt16>] = []
        let entries = spec.split { $0 == "," || $0 == " " || $0 == "\t" || $0 == "\n" || $0 == "\r" }
        for entry in entries {
            let bounds = entry.split(maxSplits: 1, omittingEmptySubsequences: false) {
                $0 == "-" || $0 == ":"
            }
            switch bounds.count {
            case 1:
                guard let port = UInt16(bounds[0]), port > 0 else { continue }
                result.append(port...port)
            case 2:
                guard let lo = UInt16(bounds[0]), let hi = UInt16(bounds[1]), lo > 0, hi > 0 else { continue }
                result.append(Swift.min(lo, hi)...Swift.max(lo, hi))
            default:
                continue
            }
        }
        return result.isEmpty ? nil : result
    }
}
