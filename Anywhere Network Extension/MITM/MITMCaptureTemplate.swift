//
//  MITMCaptureTemplate.swift
//  Anywhere
//
//  Created by NodePassProject on 6/18/26.
//

import Foundation

/// Capture refs: `$0` whole match, `$1`…`$9` single-digit groups, `${10}` braced for
/// any index, `$$` a literal `$`; any other `$` stays literal.
struct MITMCaptureTemplate: Equatable {
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
        var refsCaptures = false
        let chars = Array(raw)
        var i = 0

        func flushLiteral() {
            if !literal.isEmpty {
                tokens.append(.literal(literal))
                literal = ""
            }
        }
        func appendGroup(_ idx: Int) {
            flushLiteral()
            tokens.append(.group(idx))
            refsCaptures = true
        }

        while i < chars.count {
            let c = chars[i]
            guard c == "$" else {
                literal.append(c)
                i += 1
                continue
            }
            let next = i + 1 < chars.count ? chars[i + 1] : nil
            switch next {
            case "$":
                literal.append("$")
                i += 2
            case .some(let d) where d.isASCII && d.isNumber:
                appendGroup(d.wholeNumberValue ?? 0)
                i += 2
            case "{":
                var j = i + 2
                var digits = ""
                while j < chars.count, chars[j].isASCII, chars[j].isNumber {
                    digits.append(chars[j])
                    j += 1
                }
                if !digits.isEmpty, j < chars.count, chars[j] == "}", let idx = Int(digits) {
                    appendGroup(idx)
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
        self.referencesCaptures = refsCaptures
    }

    /// Expands the template; a `nil` from `group` (out-of-range/non-participating) contributes "".
    func expand(_ group: (Int) -> String?) -> String {
        // Fast path: literal-only template, the common case.
        if tokens.count == 1, case .literal(let s) = tokens[0] { return s }
        var out = ""
        for token in tokens {
            switch token {
            case .literal(let s):
                out += s
            case .group(let idx):
                if let value = group(idx) { out += value }
            }
        }
        return out
    }

    /// Expands against an array of capture strings (index 0 = whole match).
    func expand(captures: [String?]) -> String {
        expand { idx in (idx >= 0 && idx < captures.count) ? captures[idx] : nil }
    }

    /// Expands against a Swift `Regex` match's output (index 0 = whole match).
    func expand(output: AnyRegexOutput) -> String {
        expand { idx in
            guard idx >= 0, idx < output.count else { return nil }
            return output[idx].substring.map(String.init)
        }
    }

    /// Verbatim replacement when no captures are referenced (`$$` already reduced to `$`),
    /// else `nil`; lets the hot path use a constant with `String.replacing(_:with:)`.
    var staticReplacement: String? {
        referencesCaptures ? nil : expand { _ in nil }
    }
}
