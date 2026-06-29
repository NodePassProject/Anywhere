//
//  MITMRuleSetParser.swift
//  Anywhere
//
//  Created by NodePassProject on 5/8/26.
//

import Foundation
import JavaScriptCore

enum MITMRuleSetParser {
    /// Parsing starts in `.rule`, so files without `[Section]` headers parse as rules.
    private enum Section {
        case rule
        case parameter
        /// Unrecognized `[Section]`; its body is skipped (forward-compatible).
        case ignored
    }

    static func parse(_ text: String) -> MITMRuleSet {
        var name = ""
        var suffixes: [String] = []
        var rules: [MITMRule] = []
        var parameters: [MITMParameter] = []
        var parameterNames: Set<String> = []
        var section: Section = .rule

        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }
            if line.hasPrefix("#") || line.hasPrefix("//") { continue }

            if let next = parseSection(line) {
                section = next
                continue
            }

            // `name`/`hostname` are file-level metadata, recognized in any section.
            if let header = parseHeader(line) {
                switch header.key {
                case "name":
                    name = header.value
                case "hostname":
                    suffixes = header.value
                        .split(separator: ",")
                        .map { $0.trimmingCharacters(in: .whitespaces) }
                        .filter { !$0.isEmpty }
                default:
                    break
                }
                continue
            }

            switch section {
            case .rule:
                if let rule = parseRuleLine(line) { rules.append(rule) }
            case .parameter:
                guard parameters.count < MITMRuleSet.maxParameterCount else { continue }
                // Drop duplicate names: they'd collide as `Anywhere.params` keys.
                if let parameter = parseParameterLine(line),
                   parameterNames.insert(parameter.name).inserted {
                    parameters.append(parameter)
                }
            case .ignored:
                break
            }
        }

        return MITMRuleSet(
            name: name,
            domainSuffixes: suffixes,
            rules: rules,
            parameters: parameters
        )
    }

    /// Recognizes a `[Section]` header; unknown sections return `.ignored`.
    private static func parseSection(_ line: String) -> Section? {
        guard line.hasPrefix("["), line.hasSuffix("]"), line.count >= 2 else { return nil }
        let inner = line.dropFirst().dropLast()
            .trimmingCharacters(in: .whitespaces)
            .lowercased()
        switch inner {
        case "rule", "rules":
            return .rule
        case "parameter", "parameters", "param", "params":
            return .parameter
        default:
            return .ignored
        }
    }

    private static let recognizedHeaders: Set<String> = [
        "name",
        "hostname",
    ]

    /// Splits a `<key> = <value>` line on its first `=`. An unrecognized key returns nil so the caller retries the line as a rule.
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

    // MARK: - Rewrite sub-mode parsing

    /// Sub-mode table for `rewrite` (operation `0`):
    ///
    ///     0  transparent       <full-url>     rewrite the URL (+ dial on host change)
    ///     1  302 redirect      <full-url>     synthesize a 302 to the URL
    ///     2  200 reject (text) [<content>]    synthesize a text/plain 200
    ///     3  200 reject (gif)                 synthesize the canned 1×1 GIF
    ///     4  200 reject (data) [<base64>]     synthesize an octet-stream 200
    private static func parseRewriteAction(subMode: String, fields: [String]) -> MITMRewriteAction? {
        switch subMode.trimmingCharacters(in: .whitespaces) {
        case "0":
            guard fields.count == 1, let url = validRewriteURL(fields[0]) else { return nil }
            return .transparent(url: url)
        case "1":
            guard fields.count == 1, let url = validRewriteURL(fields[0]) else { return nil }
            return .redirect302(url: url)
        case "2":
            guard fields.count <= 1 else { return nil }
            return .reject200Text(content: fields.first ?? "")
        case "3":
            guard fields.isEmpty else { return nil }
            return .reject200Gif
        case "4":
            guard fields.count <= 1 else { return nil }
            return .reject200Data(base64: fields.first ?? "")
        default:
            return nil
        }
    }

    /// Partial check only (absolute URL with a host); the runtime re-validates in `MITMRewritePolicy`.
    private static func validRewriteURL(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty,
              let urlComponents = URLComponents(string: trimmed),
              let host = urlComponents.host, !host.isEmpty else { return nil }
        return trimmed
    }

    // MARK: - Rule line parsing

    private static func parseRuleLine(_ trimmed: String) -> MITMRule? {
        let fields = splitCSV(trimmed)
        guard fields.count >= 2 else { return nil }
        guard let phaseInt = Int(fields[0]),
              let phase = phase(from: phaseInt) else { return nil }
        guard let opInt = Int(fields[1]) else { return nil }
        let args = Array(fields.dropFirst(2))

        // Every rule leads with a urlPattern regex (matched against the whole request URL) gating the operation.
        switch opInt {
        case 0:  // rewrite — fields: urlPattern, subMode (0–4), <sub-mode args>
            guard args.count >= 2 else { return nil }
            let urlPattern = args[0]
            guard !urlPattern.isEmpty, isValidRegex(urlPattern) else { return nil }
            guard let action = parseRewriteAction(subMode: args[1], fields: Array(args.dropFirst(2))) else { return nil }
            return MITMRule(phase: .httpRequest, urlPattern: urlPattern, operation: .rewrite(action))

        case 1:  // header-add
            guard args.count == 3 else { return nil }
            let urlPattern = args[0]
            let name = args[1]
            guard !urlPattern.isEmpty, isValidRegex(urlPattern), !name.isEmpty else { return nil }
            return MITMRule(phase: phase, urlPattern: urlPattern, operation: .headerAdd(name: name, value: args[2]))

        case 2:  // header-delete
            guard args.count == 2 else { return nil }
            let urlPattern = args[0]
            let name = args[1]
            guard !urlPattern.isEmpty, isValidRegex(urlPattern), !name.isEmpty else { return nil }
            return MITMRule(phase: phase, urlPattern: urlPattern, operation: .headerDelete(name: name))

        case 3:  // header-replace — fields: urlPattern, name, value
            guard args.count == 3 else { return nil }
            let urlPattern = args[0]
            let name = args[1]
            guard !urlPattern.isEmpty, isValidRegex(urlPattern), !name.isEmpty else { return nil }
            return MITMRule(phase: phase, urlPattern: urlPattern, operation: .headerReplace(name: name, value: args[2]))

        case 4:  // body-replace — fields: urlPattern, search, replacement
            guard args.count == 3 else { return nil }
            let urlPattern = args[0]
            let search = args[1]
            guard !urlPattern.isEmpty, isValidRegex(urlPattern),
                  !search.isEmpty, isValidSearchRegex(search) else { return nil }
            return MITMRule(phase: phase, urlPattern: urlPattern, operation: .bodyReplace(search: search, replacement: args[2]))

        case 5:  // body-json — fields: urlPattern, action, <action-specific…>
            guard args.count >= 2 else { return nil }
            let urlPattern = args[0]
            guard !urlPattern.isEmpty, isValidRegex(urlPattern) else { return nil }
            guard let operation = parseJSONOperation(action: args[1], fields: Array(args.dropFirst(2))) else { return nil }
            return MITMRule(phase: phase, urlPattern: urlPattern, operation: .bodyJSON(operation))

        // Scripting operations use a separate 100+ id range.
        case 100:  // script — fields: urlPattern, base64
            guard args.count == 2 else { return nil }
            let urlPattern = args[0]
            guard !urlPattern.isEmpty, isValidRegex(urlPattern) else { return nil }
            let scriptBase64 = args[1]
            guard !scriptBase64.isEmpty, isValidScriptBase64(scriptBase64) else { return nil }
            return MITMRule(
                phase: phase,
                urlPattern: urlPattern,
                operation: .script(scriptBase64: scriptBase64)
            )

        case 101:  // stream-script — fields: urlPattern, base64
            guard args.count == 2 else { return nil }
            let urlPattern = args[0]
            guard !urlPattern.isEmpty, isValidRegex(urlPattern) else { return nil }
            let b64 = args[1]
            guard !b64.isEmpty, isValidScriptBase64(b64) else { return nil }
            return MITMRule(
                phase: phase,
                urlPattern: urlPattern,
                operation: .streamScript(scriptBase64: b64)
            )

        default:
            return nil
        }
    }

    /// Field layout for `body-json` (operation `5`) actions:
    ///
    ///     add                      <path>, <value>
    ///     replace                  <path>, <value>
    ///     delete                   <path>
    ///     replace-recursive        <key>, <value>
    ///     delete-recursive         <key>
    ///     remove-where-key-exists  <path>, <key>
    ///     remove-where-field-in    <path>, <field>, <values>
    ///
    /// Tokens matched case-insensitively; hyphenated and camelCase aliases
    /// both accepted. `<value>` / `<values>` are JSON literals; a non-JSON
    /// string is taken literally (see `MITMJSONPatch`).
    private static func parseJSONOperation(action rawAction: String, fields: [String]) -> MITMJSONOperation? {
        switch rawAction.trimmingCharacters(in: .whitespaces).lowercased() {
        case "add":
            guard fields.count == 2 else { return nil }
            return .add(path: fields[0], value: fields[1])
        case "replace":
            guard fields.count == 2 else { return nil }
            return .replace(path: fields[0], value: fields[1])
        case "delete":
            guard fields.count == 1 else { return nil }
            return .delete(path: fields[0])
        case "replace-recursive", "replacerecursive":
            guard fields.count == 2 else { return nil }
            return .replaceRecursive(key: fields[0], value: fields[1])
        case "delete-recursive", "deleterecursive":
            guard fields.count == 1 else { return nil }
            return .deleteRecursive(key: fields[0])
        case "remove-where-key-exists", "removewherekeyexists":
            guard fields.count == 2 else { return nil }
            return .removeWhereKeyExists(path: fields[0], key: fields[1])
        case "remove-where-field-in", "removewherefieldin":
            guard fields.count == 3 else { return nil }
            return .removeWhereFieldIn(path: fields[0], field: fields[1], values: fields[2])
        default:
            return nil
        }
    }

    // MARK: - Parameter line parsing

    /// Field layout: `<type>, <dataType>, <name>, <label>, <description>, <default> [, "[options]"]`
    /// (`type`: 0 input · 1 picker; `dataType`: 0 string). Picker options are a CSV-quoted bracketed list.
    private static func parseParameterLine(_ line: String) -> MITMParameter? {
        let fields = splitCSV(line)
        guard fields.count >= 6 else { return nil }
        guard let typeRaw = Int(fields[0]),
              let type = MITMParameter.InputType(rawValue: typeRaw) else { return nil }
        guard let dataRaw = Int(fields[1]),
              let dataType = MITMParameter.DataType(rawValue: dataRaw) else { return nil }
        let name = fields[2]
        guard isValidParameterName(name) else { return nil }
        let label = fields[3].isEmpty ? nil : fields[3]
        let description = fields[4].isEmpty ? nil : fields[4]
        let defaultValue = fields[5]
        let options = fields.count > 6 ? parseOptionList(fields[6]) : []

        switch type {
        case .input:
            return MITMParameter(
                type: .input,
                dataType: dataType,
                name: name,
                defaultValue: defaultValue,
                label: label,
                description: description
            )
        case .picker:
            guard !options.isEmpty else { return nil }
            var resolvedOptions = options
            let resolvedDefault: String
            if defaultValue.isEmpty {
                resolvedDefault = resolvedOptions[0]
            } else if options.contains(defaultValue) {
                resolvedDefault = defaultValue
            } else {
                resolvedOptions.insert(defaultValue, at: 0)
                resolvedDefault = defaultValue
            }
            return MITMParameter(
                type: .picker,
                dataType: dataType,
                name: name,
                defaultValue: resolvedDefault,
                options: resolvedOptions,
                label: label,
                description: description
            )
        }
    }

    /// Parses a picker's bracketed, CSV-quoted options list into its values.
    private static func parseOptionList(_ field: String) -> [String] {
        var inner = field.trimmingCharacters(in: .whitespaces)
        if inner.hasPrefix("[") { inner.removeFirst() }
        if inner.hasSuffix("]") { inner.removeLast() }
        return inner
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    private static func isValidParameterName(_ name: String) -> Bool {
        guard !name.isEmpty, name.utf8.count <= 128 else { return false }
        return name.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") }
    }

    private static func phase(from raw: Int) -> MITMPhase? {
        switch raw {
        case 0: return .httpRequest
        case 1: return .httpResponse
        default: return nil
        }
    }

    /// CSV-style split. `""` inside a quoted field produces a literal `"`;
    /// whitespace around unquoted fields is trimmed but preserved inside quotes.
    private static func splitCSV(_ input: String) -> [String] {
        var fields: [String] = []
        var current = ""
        var i = input.startIndex
        while true {
            while i < input.endIndex, input[i] == " " || input[i] == "\t" {
                i = input.index(after: i)
            }
            if i < input.endIndex, input[i] == "\"" {
                i = input.index(after: i)
                while i < input.endIndex {
                    let ch = input[i]
                    if ch == "\"" {
                        let next = input.index(after: i)
                        if next < input.endIndex, input[next] == "\"" {
                            current.append("\"")
                            i = input.index(after: next)
                        } else {
                            i = next
                            break
                        }
                    } else {
                        current.append(ch)
                        i = input.index(after: i)
                    }
                }
                while i < input.endIndex, input[i] == " " || input[i] == "\t" {
                    i = input.index(after: i)
                }
            } else {
                while i < input.endIndex, input[i] != "," {
                    current.append(input[i])
                    i = input.index(after: i)
                }
                current = current.trimmingCharacters(in: .whitespaces)
            }
            fields.append(current)
            current = ""
            if i >= input.endIndex { break }
            i = input.index(after: i)
        }
        return fields
    }

    private static func isValidRegex(_ pattern: String) -> Bool {
        (try? NSRegularExpression(pattern: pattern, options: [])) != nil
    }

    /// Validates a `search` pattern using Swift `Regex` (not `NSRegularExpression`)
    /// to match the engine the runtime uses at substitution time.
    private static func isValidSearchRegex(_ search: String) -> Bool {
        (try? Regex(search)) != nil
    }

    /// base64 → UTF-8 → JS syntax check, wrapped in the same IIFE the runtime uses.
    /// Parse-only: never evaluates, so user code with side effects is not run at import time.
    private static func isValidScriptBase64(_ b64: String) -> Bool {
        guard let raw = Data(base64Encoded: b64),
              let source = String(data: raw, encoding: .utf8)
        else { return false }
        let wrapped = "(function(){\n\(source)\nreturn process;\n})()"
        guard let context = JSContext() else { return false }
        return wrapped.withCString { cString in
            guard let scriptRef = JSStringCreateWithUTF8CString(cString) else {
                return false
            }
            defer { JSStringRelease(scriptRef) }
            return JSCheckScriptSyntax(
                context.jsGlobalContextRef,
                scriptRef,
                nil,
                0,
                nil
            )
        }
    }
}
