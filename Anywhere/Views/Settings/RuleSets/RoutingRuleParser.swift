//
//  RoutingRuleParser.swift
//  Anywhere
//
//  Created by NodePassProject on 5/8/26.
//

import Foundation

/// Import-only parser that turns the text representation of a
/// ``CustomRoutingRuleSet`` into a value the rule-set importer can
/// install. There is no serializer; the text comes from a user paste,
/// an imported `.arrs` file, or a downloaded subscription URL. The route
/// an imported set takes (direct / reject / proxy) is assigned separately
/// in the app, not carried in the text — the file supplies only a name
/// and a list of match rules.
///
/// The text is a flat sequence of lines, in any order:
///
///     name = My Rule Set
///     2, example.com
///     3, example
///     0, 10.0.0.0/8
///     1, 2001:db8::/32
///
/// - **Header lines** (`<key> = <value>`, case-insensitive key) supply
///   set metadata; only `name` is recognized.
/// - **Rule lines** (`<type>, <value>`) each describe one match rule.
///   Type is a ``RoutingRuleType`` raw value (`0`–`3`); the value is a
///   CIDR or domain, normalized in ``normalizeValue`` (a bare IP gains a
///   `/32` or `/128`).
/// - **Comments** start with `#` or `//`.
///
/// Parsing never fails: a line that is neither a recognized header nor a
/// valid rule (unrecognized key, unknown type, empty value) is dropped
/// silently, so a partially-valid file still imports what it can.
///
/// The full import-format and matching reference — every rule type, the
/// suffix-vs-keyword and CIDR semantics, and the source-tier priority
/// model — lives in `Documentations/Routing.md`.
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
