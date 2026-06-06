//
//  MITMRuleSetParser.swift
//  Anywhere
//
//  Created by NodePassProject on 5/8/26.
//

import Foundation
import JavaScriptCore

/// The full import-format and scripting reference lives in `Documentations/MITM.md`.
enum MITMRuleSetParser {
    static func parse(_ text: String) -> MITMRuleSet {
        var name = ""
        var suffixes: [String] = []
        var rules: [MITMRule] = []

        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }
            if line.hasPrefix("#") || line.hasPrefix("//") { continue }

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
            } else if let rule = parseRuleLine(line) {
                rules.append(rule)
            }
        }

        return MITMRuleSet(
            name: name,
            domainSuffixes: suffixes,
            rules: rules
        )
    }

    private static let recognizedHeaders: Set<String> = [
        "name",
        "hostname",
    ]

    /// Splits a `<key> = <value>` line on its first `=`. The key is
    /// lowercased and matched against ``recognizedHeaders``; an
    /// unrecognized key returns nil so the caller falls through and tries
    /// the line as a rule. The value is trimmed of surrounding whitespace
    /// and otherwise returned verbatim.
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

    /// Parses the numeric sub-mode and trailing fields of a `rewrite`
    /// (operation `0`) rule into a ``MITMRewriteAction``:
    ///
    ///     0  transparent       <full-url>     rewrite the URL (+ dial on host change)
    ///     1  302 redirect      <full-url>     synthesize a 302 to the URL
    ///     2  200 reject (text) [<content>]    synthesize a text/plain 200
    ///     3  200 reject (gif)                 synthesize the canned 1×1 GIF
    ///     4  200 reject (data) [<base64>]     synthesize an octet-stream 200
    ///
    /// Returns nil on an unknown sub-mode, a missing/invalid URL (modes 0/1),
    /// or the wrong field count, so the line is dropped like any other
    /// unparseable rule.
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

    /// Validates that ``raw`` is an absolute URL with a host (the replacement
    /// is always a full URL). Returns the trimmed string, or nil. The runtime
    /// re-parses and wire-safety-validates it in ``MITMRewritePolicy``.
    private static func validRewriteURL(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty,
              let comps = URLComponents(string: trimmed),
              let host = comps.host, !host.isEmpty else { return nil }
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

        // Every rule leads with a URL pattern (a regex over the whole
        // request URL) that gates whether the operation fires.
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

        // Scripting operations live in a separate 100+ id range, set apart from
        // the native edits above.
        case 100:  // script — fields: urlPattern, base64
            guard args.count == 2 else { return nil }
            let urlPattern = args[0]
            guard !urlPattern.isEmpty, isValidRegex(urlPattern) else { return nil }
            let b64 = args[1]
            guard !b64.isEmpty, isValidScriptBase64(b64) else { return nil }
            return MITMRule(
                phase: phase,
                urlPattern: urlPattern,
                operation: .script(scriptBase64: b64)
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

    /// Parses the action token and its trailing fields of a `body-json`
    /// (operation `5`) rule into a ``MITMJSONOperation``. Field layout per
    /// action (each field CSV-quoted like any other):
    ///
    ///     add                      <path>, <value>
    ///     replace                  <path>, <value>
    ///     delete                   <path>
    ///     replace-recursive        <key>, <value>
    ///     delete-recursive         <key>
    ///     remove-where-key-exists  <path>, <key>
    ///     remove-where-field-in    <path>, <field>, <values>
    ///
    /// Action tokens are matched case-insensitively and accept both the
    /// hyphenated form and a bare alias (`replaceRecursive`). `<value>` /
    /// `<values>` are JSON literals (`true`, `42`, `{"a":1}`); a string
    /// that isn't valid JSON is taken literally (see ``MITMJSONPatch``).
    /// Returns nil on an unknown action or the wrong field count, so the
    /// line is dropped like any other unparseable rule.
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

    private static func phase(from raw: Int) -> MITMPhase? {
        switch raw {
        case 0: return .httpRequest
        case 1: return .httpResponse
        default: return nil
        }
    }

    /// CSV-style split. A field that begins with `"` is read until the
    /// matching unescaped `"`, with `""` inside a quoted field producing a
    /// literal `"`. Whitespace around unquoted fields is trimmed; whitespace
    /// inside a quoted field is preserved.
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

    /// Validates a `search` field for the replace operations, which run the
    /// substitution through `String.replacing` and so compile to a Swift
    /// ``Regex`` rather than an `NSRegularExpression`. Checked with the same
    /// engine the runtime uses so an importable rule is one that will run.
    private static func isValidSearchRegex(_ search: String) -> Bool {
        (try? Regex(search)) != nil
    }

    /// Validates a `script` field: base64 → UTF-8 → JavaScript parse.
    /// Wraps the source in the same IIFE the runtime uses so a rule
    /// that imports cleanly here is one the runtime can compile.
    /// Parse-only — does not evaluate, so user code with side effects
    /// is not run at import time.
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
