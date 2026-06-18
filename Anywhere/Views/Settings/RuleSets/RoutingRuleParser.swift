//
//  RoutingRuleParser.swift
//  Anywhere
//
//  Created by NodePassProject on 5/8/26.
//

import Foundation

/// The initial route a rule-set file requests via its `routing` header.
enum RuleSetImportRoute: Int {
    case `default` = 0
    case direct = 1
    case reject = 2
    
    var assignmentId: String? {
        switch self {
        case .default: return nil
        case .direct: return "DIRECT"
        case .reject: return "REJECT"
        }
    }
}

/// Import-only parser that turns the text representation of a
/// ``CustomRoutingRuleSet`` into a value the rule-set importer can
/// install. There is no serializer; the text comes from a user paste,
/// an imported `.arrs` file, or a downloaded subscription URL. A file
/// supplies a name, a list of match rules, and — optionally — an initial
/// route via the `routing` header (see ``RuleSetImportRoute``).
///
/// The text is a flat sequence of lines, in any order:
///
///     name = My Rule Set
///     routing = 1
///     2, example.com
///     3, example
///     0, 10.0.0.0/8
///     1, 2001:db8::/32
///
/// - **Header lines** (`<key> = <value>`, case-insensitive key) supply
///   set metadata: `name` sets the display name and `routing` sets the
///   initial route (`0` Default · `1` Direct · `2` Reject).
/// - **Rule lines** (`<type>, <value>`) each describe one match rule.
///   Type is a ``RoutingRuleType`` raw value (`0`–`3`); the value is a
///   CIDR or domain, normalized in ``RoutingRuleType/normalized(_:)`` (a bare IP gains a
///   `/32` or `/128`).
/// - **Comments** start with `#` or `//`.
///
/// Parsing never fails: a line that is neither a recognized header nor a
/// valid rule (unrecognized key, unknown type, empty or out-of-range value)
/// is dropped silently, so a partially-valid file still imports what it can.
///
/// The full import-format and matching reference — every rule type, the
/// suffix-vs-keyword and CIDR semantics, and the source-tier priority
/// model — lives in `Documentations/Routing.md`.
enum RoutingRuleSetParser {
    struct ParseResult {
        var name: String
        var rules: [RoutingRule]
        var routing: RuleSetImportRoute
    }

    static func parse(_ text: String) -> ParseResult {
        var name = ""
        var rules: [RoutingRule] = []
        var routing: RuleSetImportRoute = .default

        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }
            if line.hasPrefix("#") || line.hasPrefix("//") { continue }

            if let header = parseHeader(line) {
                switch header.key {
                case "name":
                    name = header.value
                case "routing":
                    if let code = Int(header.value), let value = RuleSetImportRoute(rawValue: code) {
                        routing = value
                    }
                default:
                    break
                }
            } else if let rule = parseRuleLine(line) {
                rules.append(rule)
            }
        }

        return ParseResult(name: name, rules: rules, routing: routing)
    }

    private static let recognizedHeaders: Set<String> = ["name", "routing"]

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
        return RoutingRule(type: type, value: type.normalized(value))
    }
}
