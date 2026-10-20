//
//  MITMCaptureTemplate.swift
//  Anywhere
//
//  Created by NodePassProject on 6/18/26.
//

import Foundation

/// Capture refs: `$0` whole match, `$1`…`$9` single-digit groups, `${10}` braced for
/// any index, `$$` a literal `$`; any other `$` stays literal.
nonisolated struct MITMCaptureTemplate: Equatable {
    private enum Token: Equatable {
        case literal(String)
        case group(Int)
    }

    private let tokens: [Token]

    /// True when any `$N` reference is present; lets callers pick the static vs templated path.
    let referencesCaptures: Bool

    init(_ raw: String) {
        var tokens: [Token] = []
        var literal = ""
        var referencesCaptures = false
        let characters = Array(raw)
        var i = 0

        func flushLiteral() {
            if !literal.isEmpty {
                tokens.append(.literal(literal))
                literal = ""
            }
        }
        func appendGroup(_ index: Int) {
            flushLiteral()
            tokens.append(.group(index))
            referencesCaptures = true
        }

        while i < characters.count {
            let character = characters[i]
            guard character == "$" else {
                literal.append(character)
                i += 1
                continue
            }
            let next = i + 1 < characters.count ? characters[i + 1] : nil
            switch next {
            case "$":
                literal.append("$")
                i += 2
            case .some(let digit) where digit.isASCII && digit.isNumber:
                appendGroup(digit.wholeNumberValue ?? 0)
                i += 2
            case "{":
                var j = i + 2
                var digits = ""
                while j < characters.count, characters[j].isASCII, characters[j].isNumber {
                    digits.append(characters[j])
                    j += 1
                }
                if !digits.isEmpty, j < characters.count, characters[j] == "}", let index = Int(digits) {
                    appendGroup(index)
                    i = j + 1
                } else {
                    literal.append("$")
                    i += 1
                }
            default:
                literal.append("$")
                i += 1
            }
        }
        flushLiteral()

        self.tokens = tokens
        self.referencesCaptures = referencesCaptures
    }

    func expand(_ captureLookup: (Int) -> String?) -> String {
        // Fast path: literal-only template, the common case.
        if tokens.count == 1, case .literal(let text) = tokens[0] { return text }
        var out = ""
        for token in tokens {
            switch token {
            case .literal(let text):
                out += text
            case .group(let index):
                if let value = captureLookup(index) { out += value }
            }
        }
        return out
    }

    /// Expands against an array of capture strings (index 0 = whole match).
    func expand(captures: [String?]) -> String {
        expand { index in (index >= 0 && index < captures.count) ? captures[index] : nil }
    }

    /// Expands against a Swift `Regex` match's output (index 0 = whole match).
    func expand(output: AnyRegexOutput) -> String {
        expand { index in
            guard index >= 0, index < output.count else { return nil }
            return output[index].substring.map(String.init)
        }
    }

    /// Verbatim replacement when no captures are referenced (`$$` already reduced to `$`),
    /// else `nil`; lets the hot path use a constant with `String.replacing(_:with:)`.
    var staticReplacement: String? {
        referencesCaptures ? nil : expand { _ in nil }
    }
}
