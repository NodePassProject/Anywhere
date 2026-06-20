//
//  HysteriaPortHopping.swift
//  Anywhere
//
//  Created by NodePassProject on 6/10/26.
//

import Foundation

/// Spec: comma/whitespace-separated entries, each a single port (`443`) or an inclusive range
/// using `-` or `:` (`5000-6000`, `5000:6000`).
struct HysteriaPortHopping: Hashable, Codable {
    /// Preserved verbatim so links and stored configs round-trip.
    let portsSpec: String
    /// Seconds between hops.
    let intervalSeconds: Int

    /// Matches Hysteria's default hop interval.
    static let defaultIntervalSeconds = 30

    init(portsSpec: String, intervalSeconds: Int = HysteriaPortHopping.defaultIntervalSeconds) {
        self.portsSpec = portsSpec
        self.intervalSeconds = intervalSeconds > 0 ? intervalSeconds : HysteriaPortHopping.defaultIntervalSeconds
    }

    var ranges: [ClosedRange<UInt16>]? { Self.parseRanges(portsSpec) }

    /// Centralizes the "absent/empty/invalid → no hopping" decision for lenient importers.
    static func make(spec: String?, intervalSeconds: Int?) -> HysteriaPortHopping? {
        guard let spec, parseRanges(spec) != nil else { return nil }
        return HysteriaPortHopping(portsSpec: spec,
                                   intervalSeconds: intervalSeconds ?? defaultIntervalSeconds)
    }

    /// Reversed bounds are swapped; empty, non-numeric, or out-of-range (`0`/`>65535`) tokens
    /// are skipped. `nil` means "port hopping disabled".
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
