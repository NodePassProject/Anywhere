//
//  MITMRuleSetParser.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/8/26.
//

import Foundation

/// Text-based importer for ``MITMRuleSet``s.
///
/// The text is a flat sequence of header lines and rule lines, in any
/// order. Header lines have the shape `<key> = <value>` and supply the
/// set's metadata. Rule lines use the same CSV format the editor's
/// previous "import rules" feature used.
///
///     name     = My Rule Set
///     hostname = example.com, *.api.example.com
///     redirect = upstream.example.com:443
///     0, 0, ^https://example\.com/old, https://example.com/new
///     1, 1, X-Powered-By, Anywhere
///
/// Recognized keys:
///
/// - `name`     — display name for the rule set
/// - `hostname` — comma-separated list of domain suffixes
/// - `redirect` — `host` or `host:port` for a per-set rewrite target
///
/// Unrecognized header keys are ignored. Comment lines start with `#`
/// or `//`. Lines that fail to parse as either a header or a rule are
/// dropped silently so a partially-valid file still imports what it can.
///
/// Rule line format:
///
///     <phase>, <operation>, <field1> [, <field2> [, <field3> ] ]
///
/// Phase: `0` = request, `1` = response.
///
/// Operations and their trailing fields:
///
/// | ID | Operation       | Phase           | Fields                |
/// | -- | --------------- | --------------- | --------------------- |
/// | `0` | url-replace    | request only    | pattern, replacement  |
/// | `1` | header-add     | both            | name, value           |
/// | `2` | header-delete  | both            | name                  |
/// | `3` | header-replace | both            | pattern, name, value  |
/// | `4` | body-replace   | both            | pattern, replacement  |
///
/// Fields are separated by `,`. Whitespace around unquoted fields is
/// trimmed. A field that begins with `"` is read until the matching `"`,
/// with `""` inside a quoted field producing a literal `"` — so values
/// containing commas can be wrapped in double quotes.
///
/// Pattern semantics for `body-replace`: the runtime applies the
/// pattern byte-for-byte to the decompressed body (gzip/deflate/br are
/// decoded first). Bodies are viewed through Latin-1, where every byte
/// 0x00–0xFF corresponds to one code point U+0000–U+00FF, so ASCII
/// patterns match the same bytes they always did. Non-ASCII bytes —
/// UTF-8 multibyte sequences for CJK or emoji, GBK / Shift-JIS text,
/// raw binary — must be addressed via `\xHH` escapes inside the
/// pattern, not as Unicode characters. (Patterns for `url-replace`
/// and `header-replace` operate on header / request-target text and
/// follow the usual NSRegularExpression Unicode semantics.)
enum MITMRuleSetParser {
    static func parse(_ text: String) -> MITMRuleSet {
        var name = ""
        var suffixes: [String] = []
        var target: MITMRewriteTarget?
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
                case "redirect":
                    target = parseRedirect(header.value)
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
            rewriteTarget: target,
            rules: rules
        )
    }

    private static let recognizedHeaders: Set<String> = ["name", "hostname", "redirect"]

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

    /// Parses `host` or `host:port`. Returns nil only when the value is
    /// empty after trimming.
    private static func parseRedirect(_ value: String) -> MITMRewriteTarget? {
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        if let colon = trimmed.lastIndex(of: ":") {
            let hostPart = String(trimmed[..<colon]).trimmingCharacters(in: .whitespaces)
            let portPart = String(trimmed[trimmed.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if !hostPart.isEmpty, let port = UInt16(portPart) {
                return MITMRewriteTarget(host: hostPart, port: port)
            }
        }
        return MITMRewriteTarget(host: trimmed, port: nil)
    }

    // MARK: - Rule line parsing

    private static func parseRuleLine(_ trimmed: String) -> MITMRule? {
        let fields = splitCSV(trimmed)
        guard fields.count >= 2 else { return nil }
        guard let phaseInt = Int(fields[0]),
              let phase = phase(from: phaseInt) else { return nil }
        guard let opInt = Int(fields[1]) else { return nil }
        let args = Array(fields.dropFirst(2))

        switch opInt {
        case 0:  // url-replace, request-only regardless of phase column
            guard args.count == 2 else { return nil }
            let pattern = args[0]
            guard !pattern.isEmpty, isValidRegex(pattern) else { return nil }
            return MITMRule(phase: .httpRequest, operation: .urlReplace(pattern: pattern, path: args[1]))

        case 1:  // header-add
            guard args.count == 2 else { return nil }
            let name = args[0]
            guard !name.isEmpty else { return nil }
            return MITMRule(phase: phase, operation: .headerAdd(name: name, value: args[1]))

        case 2:  // header-delete
            guard args.count == 1 else { return nil }
            let name = args[0]
            guard !name.isEmpty else { return nil }
            return MITMRule(phase: phase, operation: .headerDelete(name: name))

        case 3:  // header-replace
            guard args.count == 3 else { return nil }
            let pattern = args[0]
            let name = args[1]
            guard !pattern.isEmpty, !name.isEmpty, isValidRegex(pattern) else { return nil }
            return MITMRule(phase: phase, operation: .headerReplace(pattern: pattern, name: name, value: args[2]))

        case 4:  // body-replace
            guard args.count == 2 else { return nil }
            let pattern = args[0]
            guard !pattern.isEmpty, isValidRegex(pattern) else { return nil }
            return MITMRule(phase: phase, operation: .bodyReplace(pattern: pattern, body: args[1]))

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
}
