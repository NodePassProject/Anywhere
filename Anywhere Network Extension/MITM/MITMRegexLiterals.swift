//
//  MITMRegexLiterals.swift
//  Anywhere
//
//  Created by NodePassProject on 10/23/26.
//

import Foundation

nonisolated enum MITMRegexLiterals {
    private static let minimumRunLength = 3
    private static let maximumRuns = 3

    private static let classEscapes = Set("dDwWsSbBAzZGhHvVRXtnrfea".unicodeScalars)
    private static let metacharacters = Set("\\^$.|?*+()[]{}".unicodeScalars)

    static func required(in pattern: String) -> [String]? {
        guard !pattern.contains("\\Q"), !pattern.contains("\\E") else { return nil }
        let scalars = Array(pattern.unicodeScalars)
        var runs: [String] = []
        var run = String.UnicodeScalarView()

        func endRun() {
            if run.count >= minimumRunLength { runs.append(String(run)) }
            run = String.UnicodeScalarView()
        }

        var index = 0
        while index < scalars.count {
            let scalar = scalars[index]
            var literal: Unicode.Scalar?
            switch scalar {
            case "(":
                endRun()
                guard let next = skipGroup(scalars, from: index) else { return nil }
                index = next
            case "[":
                endRun()
                guard let next = skipClass(scalars, from: index) else { return nil }
                index = next
            case ".", "^", "$":
                endRun()
                index += 1
            case "\\":
                guard index + 1 < scalars.count else { return nil }
                let escaped = scalars[index + 1]
                if isPrintableASCII(escaped), !isAlphanumeric(escaped) {
                    literal = escaped
                } else if classEscapes.contains(escaped) {
                    endRun()
                } else {
                    return nil
                }
                index += 2
            case _ where metacharacters.contains(scalar):
                return nil
            case _ where isPrintableASCII(scalar):
                literal = scalar
                index += 1
            default:
                endRun()
                index += 1
            }
            if let literal { run.append(literal) }

            guard index < scalars.count else { break }
            let minimumRepeats: Int
            switch scalars[index] {
            case "?", "*":
                minimumRepeats = 0
                index += 1
            case "+":
                minimumRepeats = 1
                index += 1
            case "{":
                guard let (minimum, next) = parseInterval(scalars, from: index) else { return nil }
                minimumRepeats = minimum
                index = next
            default:
                continue
            }
            if index < scalars.count, scalars[index] == "?" || scalars[index] == "+" { index += 1 }
            if literal != nil, minimumRepeats == 0 { run.removeLast() }
            endRun()
        }
        endRun()
        guard !runs.isEmpty else { return nil }
        return Array(runs.sorted { $0.unicodeScalars.count > $1.unicodeScalars.count }.prefix(maximumRuns))
    }

    private static func skipGroup(_ scalars: [Unicode.Scalar], from start: Int) -> Int? {
        var index = start + 1
        if index < scalars.count, scalars[index] == "?" {
            guard index + 1 < scalars.count else { return nil }
            switch scalars[index + 1] {
            case ":", "=", "!", ">", "<": break
            default: return nil
            }
        }
        var depth = 1
        while index < scalars.count {
            switch scalars[index] {
            case "\\":
                index += 2
            case "[":
                guard let next = skipClass(scalars, from: index) else { return nil }
                index = next
            case "(":
                depth += 1
                index += 1
            case ")":
                depth -= 1
                index += 1
                if depth == 0 { return index }
            default:
                index += 1
            }
        }
        return nil
    }

    private static func skipClass(_ scalars: [Unicode.Scalar], from start: Int) -> Int? {
        var index = start + 1
        if index < scalars.count, scalars[index] == "^" { index += 1 }
        guard index < scalars.count, scalars[index] != "]" else { return nil }
        var depth = 1
        while index < scalars.count {
            switch scalars[index] {
            case "\\":
                index += 2
            case "[":
                depth += 1
                index += 1
            case "]":
                depth -= 1
                index += 1
                if depth == 0 { return index }
            default:
                index += 1
            }
        }
        return nil
    }

    private static func parseInterval(_ scalars: [Unicode.Scalar], from start: Int) -> (Int, Int)? {
        var index = start + 1
        var minimum = 0
        var digits = 0
        while index < scalars.count, let digit = decimalValue(scalars[index]) {
            guard digits < 9 else { return nil }
            minimum = minimum * 10 + digit
            digits += 1
            index += 1
        }
        guard digits > 0, index < scalars.count else { return nil }
        if scalars[index] == "," {
            index += 1
            while index < scalars.count, decimalValue(scalars[index]) != nil { index += 1 }
        }
        guard index < scalars.count, scalars[index] == "}" else { return nil }
        return (minimum, index + 1)
    }

    private static func decimalValue(_ scalar: Unicode.Scalar) -> Int? {
        (0x30...0x39).contains(scalar.value) ? Int(scalar.value - 0x30) : nil
    }

    private static func isPrintableASCII(_ scalar: Unicode.Scalar) -> Bool {
        (0x20...0x7E).contains(scalar.value)
    }

    private static func isAlphanumeric(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x30...0x39, 0x41...0x5A, 0x61...0x7A: return true
        default: return false
        }
    }
}
