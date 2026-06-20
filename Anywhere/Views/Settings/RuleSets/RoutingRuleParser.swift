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

/// Format: flat lines in any order — header lines (`<key> = <value>`,
/// case-insensitive key) and rule lines (`<type>, <value>`); `#` or `//`
/// start comments. Parsing never fails: an unrecognized header or invalid
/// rule line is dropped silently, so a partially-valid file still imports.
/// Full format reference: `Documentations/Routing.md`.
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
