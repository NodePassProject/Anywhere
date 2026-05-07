//
//  RoutingRuleParser.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/8/26.
//

import Foundation

/// Text-based importer for ``CustomRoutingRuleSet``s.
///
/// The text is a flat sequence of header lines and rule lines, in any
/// order. Header lines have the shape `<key> = <value>` and supply the
/// set's metadata. Rule lines use the existing CSV format.
///
///     name = My Rule Set
///     2, example.com
///     3, example
///     0, 10.0.0.0/8
///     1, 2001:db8::/32
///
/// Recognized keys:
///
/// - `name` — display name for the rule set
///
/// Unrecognized header keys are ignored. Comment lines start with `#`
/// or `//`. Lines that fail to parse as either a header or a rule are
/// dropped silently so a partially-valid file still imports what it can.
///
/// Rule line format:
///
///     <type>, <value>
///
/// Type IDs match ``RoutingRuleType``'s raw values:
///
/// | ID  | Type           | Value                                         |
/// | --- | -------------- | --------------------------------------------- |
/// | `0` | IPv4 CIDR      | `10.0.0.0/8` (`/32` appended if no prefix)    |
/// | `1` | IPv6 CIDR      | `2001:db8::/32` (`/128` appended if no prefix) |
/// | `2` | Domain Suffix  | `example.com`                                 |
/// | `3` | Domain Keyword | `example`                                     |
enum RoutingRuleSetParser {
    static func parse(_ text: String) -> CustomRoutingRuleSet {
        var name = ""
        var rules: [RoutingRule] = []

        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }
            if line.hasPrefix("#") || line.hasPrefix("//") { continue }

            if let header = parseHeader(line) {
                switch header.key {
                case "name":
                    name = header.value
                default:
                    break
                }
            } else if let rule = parseRuleLine(line) {
                rules.append(rule)
            }
        }

        return CustomRoutingRuleSet(name: name, rules: rules)
    }

    private static let recognizedHeaders: Set<String> = ["name"]

    private static func parseHeader(_ line: String) -> (key: String, value: String)? {
        guard let equal = line.firstIndex(of: "=") else { return nil }
        let key = line[line.startIndex..<equal]
            .trimmingCharacters(in: .whitespaces)
            .lowercased()
        guard recognizedHeaders.contains(key) else { return nil }
        let value = String(line[line.index(after: equal)...])
            .trimmingCharacters(in: .whitespaces)
        return (key, value)
    }

    private static func parseRuleLine(_ trimmed: String) -> RoutingRule? {
        guard let commaIndex = trimmed.firstIndex(of: ",") else { return nil }
        let prefix = trimmed[trimmed.startIndex..<commaIndex].trimmingCharacters(in: .whitespaces)
        let value = trimmed[trimmed.index(after: commaIndex)...].trimmingCharacters(in: .whitespaces)
        guard !value.isEmpty else { return nil }

        guard let typeInt = Int(prefix), let type = RoutingRuleType(rawValue: typeInt) else { return nil }
        return RoutingRule(type: type, value: normalizeValue(value, type: type))
    }

    private static func normalizeValue(_ value: String, type: RoutingRuleType) -> String {
        switch type {
        case .ipCIDR:
            // Single IPv4 (no slash) → append /32
            if !value.contains("/") {
                return value + "/32"
            }
            return value
        case .ipCIDR6:
            // Single IPv6 (no slash) → append /128
            if !value.contains("/") {
                return value + "/128"
            }
            return value
        case .domainSuffix, .domainKeyword:
            return value
        }
    }
}
