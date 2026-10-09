//
//  ModuleParser.swift
//  Anywhere
//
//  Created by NodePassProject on 10/9/26.
//

import Foundation

enum ModuleParser {
    private enum Section {
        case module
        case routing
        case mitm
    }

    static func parse(_ text: String) -> ModuleContent {
        var content = ModuleContent()
        var section: Section = .module
        var body: [String] = []
        var routingIndex = 0
        var mitmIndex = 0

        func flush() {
            defer { body = [] }
            switch section {
            case .module:
                parseModuleHeaders(body, into: &content)
            case .routing:
                guard hasContent(body) else { return }
                routingIndex += 1
                let parsed = RoutingRuleSetParser.parse(body.joined(separator: "\n"))
                let name = parsed.name.isEmpty ? "Routing \(routingIndex)" : parsed.name
                let ruleSet = ModuleRoutingRuleSet(name: name, rules: parsed.rules)
                content.routingRuleSets.append(ruleSet)
                if let seed = parsed.routing.assignmentId {
                    content.routingSeeds[ruleSet.id] = seed
                }
            case .mitm:
                guard hasContent(body) else { return }
                mitmIndex += 1
                let parsed = MITMRuleSetParser.parse(body.joined(separator: "\n"))
                let name = parsed.name.isEmpty ? "MITM \(mitmIndex)" : parsed.name
                content.mitmRuleSets.append(ModuleMITMRuleSet(
                    name: name,
                    domainSuffixes: parsed.domainSuffixes,
                    rules: parsed.rules,
                    parameters: parsed.parameters
                ))
            }
        }

        for raw in text.components(separatedBy: .newlines) {
            if let next = parseSectionMarker(raw.trimmingCharacters(in: .whitespaces)) {
                flush()
                section = next
                continue
            }
            body.append(raw)
        }
        flush()
        return content
    }

    private static func parseSectionMarker(_ line: String) -> Section? {
        guard line.hasPrefix("["), line.hasSuffix("]"), line.count >= 2 else { return nil }
        let inner = line.dropFirst().dropLast()
            .trimmingCharacters(in: .whitespaces)
            .lowercased()
        switch inner {
        case "module":
            return .module
        case "routing":
            return .routing
        case "mitm":
            return .mitm
        default:
            return nil
        }
    }

    private static func hasContent(_ lines: [String]) -> Bool {
        lines.contains { raw in
            let line = raw.trimmingCharacters(in: .whitespaces)
            return !line.isEmpty && !line.hasPrefix("#") && !line.hasPrefix("//")
        }
    }

    private static func parseModuleHeaders(_ lines: [String], into content: inout ModuleContent) {
        for raw in lines {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix("//") else { continue }
            guard let equal = line.firstIndex(of: "=") else { continue }
            let key = line[line.startIndex..<equal]
                .trimmingCharacters(in: .whitespaces)
                .lowercased()
            let value = String(line[line.index(after: equal)...])
                .trimmingCharacters(in: .whitespaces)
            switch key {
            case "name":
                content.name = value
            case "icon-light":
                content.iconLight = icon(value)
            case "icon-dark":
                content.iconDark = icon(value)
            default:
                break
            }
        }
    }
    
    private static func icon(_ value: String) -> Data? {
        guard let data = Data(iconBase64: value), data.count <= Module.maxIconBytes else { return nil }
        return data
    }
}
