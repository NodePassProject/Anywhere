//
//  MITMCaptureTemplate.swift
//  Anywhere
//
//  Created by NodePassProject on 6/18/26.
//

import Foundation

nonisolated struct MITMCaptureTemplate: Equatable {
    private enum Token: Equatable {
        case literal(String)
        case group(Int)
    }

    private let tokens: [Token]

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

    func expand(captures: [String?]) -> String {
        expand { index in (index >= 0 && index < captures.count) ? captures[index] : nil }
    }

    func regularExpressionTemplate(captureGroupCount: Int) -> String {
        var out = ""
        var followsGroup = false
        for token in tokens {
            switch token {
            case .literal(let text):
                var escaped = NSRegularExpression.escapedTemplate(for: text)
                if followsGroup, let first = escaped.first, first.isASCII, first.isNumber {
                    escaped.insert("\\", at: escaped.startIndex)
                }
                out += escaped
                followsGroup = false
            case .group(let index):
                guard index <= captureGroupCount else { continue }
                out += "$\(index)"
                followsGroup = true
            }
        }
        return out
    }
}
