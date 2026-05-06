//
//  MITMRuleParser.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/6/26.
//

import Foundation

/// Text-based importer for ``MITMRule``s.
///
/// Each non-empty, non-comment line becomes one rule. Fields are separated
/// by `,`; whitespace around unquoted fields is trimmed. A field that
/// begins with `"` is read until the matching `"`, with a doubled `""`
/// producing a literal quote — so values containing commas can be wrapped
/// in double quotes.
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
/// Comment lines start with `#` or `//`. Lines that fail validation are
/// skipped silently so a partially-valid file imports the rules it can.
enum MITMRuleParser {
    static func parse(_ text: String) -> [MITMRule] {
        text
            .components(separatedBy: .newlines)
            .compactMap { parseLine($0) }
    }

    private static func parseLine(_ line: String) -> MITMRule? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        if trimmed.hasPrefix("#") || trimmed.hasPrefix("//") { return nil }

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
