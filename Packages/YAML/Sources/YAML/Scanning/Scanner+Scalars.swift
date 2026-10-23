//
//  Scanner+Scalars.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

// MARK: - Block scalars

extension Scanner {
    private enum Chomping {
        case strip
        case clip
        case keep
    }

    mutating func scanBlockScalar(isLiteral: Bool) throws(YAMLError) -> Token {
        let startMark = mark
        skip()

        var chomping = Chomping.clip
        var increment = 0
        if matches("+") || matches("-") {
            chomping = matches("+") ? .keep : .strip
            skip()
            if isDigit() {
                increment = try scanIndentationIndicator(startMark: startMark)
            }
        } else if isDigit() {
            increment = try scanIndentationIndicator(startMark: startMark)
            if matches("+") || matches("-") {
                chomping = matches("+") ? .keep : .strip
                skip()
            }
        }

        while isBlank() {
            skip()
        }
        if matches("#") {
            while !isBreakOrEnd() {
                skip()
            }
        }
        guard isBreakOrEnd() else {
            throw error(
                "did not find expected comment or line break",
                context: "while scanning a block scalar",
                contextMark: startMark
            )
        }
        skipLineBreak()

        var endMark = mark
        var contentIndent = 0
        if increment > 0 {
            contentIndent = indent >= 0 ? indent + increment : increment
        }

        var string: [UInt8] = []
        var leadingBreak: [UInt8] = []
        var trailingBreaks: [UInt8] = []
        try scanBlockScalarBreaks(indent: &contentIndent, breaks: &trailingBreaks, startMark: startMark, endMark: &endMark)

        var isLeadingBlank = false
        while mark.column == contentIndent && !isEnd() {
            let isTrailingBlank = isBlank()
            if !isLiteral && leadingBreak.first == UInt8(ascii: "\n") && !isLeadingBlank && !isTrailingBlank {
                if trailingBreaks.isEmpty {
                    string.append(UInt8(ascii: " "))
                }
            } else {
                string += leadingBreak
            }
            leadingBreak.removeAll(keepingCapacity: true)
            string += trailingBreaks
            trailingBreaks.removeAll(keepingCapacity: true)

            isLeadingBlank = isBlank()
            while !isBreakOrEnd() {
                read(into: &string)
            }
            readLineBreak(into: &leadingBreak)
            try scanBlockScalarBreaks(indent: &contentIndent, breaks: &trailingBreaks, startMark: startMark, endMark: &endMark)
        }

        if chomping != .strip {
            string += leadingBreak
        }
        if chomping == .keep {
            string += trailingBreaks
        }

        let style: ScalarStyle = isLiteral ? .literal : .folded
        return Token(kind: .scalar(String(decoding: string, as: UTF8.self), style: style), startMark: startMark, endMark: endMark)
    }

    private mutating func scanIndentationIndicator(startMark: Mark) throws(YAMLError) -> Int {
        guard !matches("0") else {
            throw error("found an indentation indicator equal to 0", context: "while scanning a block scalar", contextMark: startMark)
        }
        let increment = Int(byte() - UInt8(ascii: "0"))
        skip()
        return increment
    }

    private mutating func scanBlockScalarBreaks(
        indent contentIndent: inout Int,
        breaks: inout [UInt8],
        startMark: Mark,
        endMark: inout Mark
    ) throws(YAMLError) {
        var maximumIndent = 0
        endMark = mark

        while true {
            while (contentIndent == 0 || mark.column < contentIndent) && matches(" ") {
                skip()
            }
            maximumIndent = max(maximumIndent, mark.column)

            if (contentIndent == 0 || mark.column < contentIndent) && matches("\t") {
                throw error(
                    "found a tab character where an indentation space is expected",
                    context: "while scanning a block scalar",
                    contextMark: startMark
                )
            }

            guard isBreak() else { break }
            readLineBreak(into: &breaks)
            endMark = mark
        }

        if contentIndent == 0 {
            contentIndent = max(maximumIndent, indent + 1, 1)
        }
    }
}

// MARK: - Quoted scalars

extension Scanner {
    mutating func scanFlowScalar(isSingleQuoted: Bool) throws(YAMLError) -> Token {
        let startMark = mark
        let quote: Unicode.Scalar = isSingleQuoted ? "'" : "\""
        skip()

        var string: [UInt8] = []
        var leadingBreak: [UInt8] = []
        var trailingBreaks: [UInt8] = []
        var whitespaces: [UInt8] = []

        while true {
            if isDocumentIndicator("-") || isDocumentIndicator(".") {
                throw error("found unexpected document indicator", context: "while scanning a quoted scalar", contextMark: startMark)
            }
            if isEnd() {
                throw error("found unexpected end of stream", context: "while scanning a quoted scalar", contextMark: startMark)
            }

            var hasLeadingBlanks = false
            while !isWhitespaceOrEnd() {
                if isSingleQuoted && matches("'") && matches("'", at: 1) {
                    string.append(UInt8(ascii: "'"))
                    skip()
                    skip()
                } else if matches(quote) {
                    break
                } else if !isSingleQuoted && matches("\\") && isBreak(at: 1) {
                    skip()
                    skipLineBreak()
                    hasLeadingBlanks = true
                    break
                } else if !isSingleQuoted && matches("\\") {
                    try scanEscapeSequence(startMark: startMark, into: &string)
                } else {
                    read(into: &string)
                }
            }

            if matches(quote) {
                break
            }

            while isBlank() || isBreak() {
                if isBlank() {
                    if hasLeadingBlanks {
                        skip()
                    } else {
                        read(into: &whitespaces)
                    }
                } else if hasLeadingBlanks {
                    readLineBreak(into: &trailingBreaks)
                } else {
                    whitespaces.removeAll(keepingCapacity: true)
                    readLineBreak(into: &leadingBreak)
                    hasLeadingBlanks = true
                }
            }

            if hasLeadingBlanks {
                Self.foldLineBreaks(leadingBreak: &leadingBreak, trailingBreaks: &trailingBreaks, into: &string)
            } else {
                string += whitespaces
                whitespaces.removeAll(keepingCapacity: true)
            }
        }

        skip()
        let style: ScalarStyle = isSingleQuoted ? .singleQuoted : .doubleQuoted
        return Token(kind: .scalar(String(decoding: string, as: UTF8.self), style: style), startMark: startMark, endMark: mark)
    }

    private mutating func scanEscapeSequence(startMark: Mark, into string: inout [UInt8]) throws(YAMLError) {
        let codeLength: Int
        switch Unicode.Scalar(byte(at: 1)) {
        case "x":
            codeLength = 2
        case "u":
            codeLength = 4
        case "U":
            codeLength = 8
        case let escape:
            guard let character = Self.escapedCharacters[escape] else {
                throw error("found unknown escape character", context: "while parsing a quoted scalar", contextMark: startMark)
            }
            string += character.utf8
            codeLength = 0
        }
        skip()
        skip()

        guard codeLength > 0 else { return }

        var value: UInt32 = 0
        for offset in 0..<codeLength {
            guard let digit = hexDigitValue(at: offset) else {
                throw error("did not find expected hexdecimal number", context: "while parsing a quoted scalar", contextMark: startMark)
            }
            value = value << 4 | digit
        }
        guard let character = Unicode.Scalar(value) else {
            throw error("found invalid Unicode character escape code", context: "while parsing a quoted scalar", contextMark: startMark)
        }
        string += String(character).utf8
        for _ in 0..<codeLength {
            skip()
        }
    }

    private static let escapedCharacters: [Unicode.Scalar: String] = [
        "0": "\0",
        "a": "\u{07}",
        "b": "\u{08}",
        "t": "\t",
        "\t": "\t",
        "n": "\n",
        "v": "\u{0B}",
        "f": "\u{0C}",
        "r": "\r",
        "e": "\u{1B}",
        " ": " ",
        "\"": "\"",
        "/": "/",
        "\\": "\\",
        "N": "\u{85}",
        "_": "\u{A0}",
        "L": "\u{2028}",
        "P": "\u{2029}",
    ]
}

// MARK: - Plain scalars

extension Scanner {
    mutating func scanPlainScalar() throws(YAMLError) -> Token {
        let startMark = mark
        var endMark = mark
        let minimumIndent = indent + 1

        var string: [UInt8] = []
        var leadingBreak: [UInt8] = []
        var trailingBreaks: [UInt8] = []
        var whitespaces: [UInt8] = []
        var hasLeadingBlanks = false

        while true {
            if isDocumentIndicator("-") || isDocumentIndicator(".") || matches("#") {
                break
            }

            while !isWhitespaceOrEnd() {
                if flowLevel > 0 && matches(":") && Self.flowIndicators.contains(byte(at: 1)) {
                    throw error("found unexpected ':'", context: "while scanning a plain scalar", contextMark: startMark)
                }
                if (matches(":") && isWhitespaceOrEnd(at: 1)) || (flowLevel > 0 && Self.flowTerminators.contains(byte())) {
                    break
                }

                if hasLeadingBlanks {
                    Self.foldLineBreaks(leadingBreak: &leadingBreak, trailingBreaks: &trailingBreaks, into: &string)
                    hasLeadingBlanks = false
                } else if !whitespaces.isEmpty {
                    string += whitespaces
                    whitespaces.removeAll(keepingCapacity: true)
                }

                read(into: &string)
                endMark = mark
            }

            guard isBlank() || isBreak() else { break }

            while isBlank() || isBreak() {
                if isBlank() {
                    if hasLeadingBlanks && mark.column < minimumIndent && matches("\t") {
                        throw error(
                            "found a tab character that violates indentation",
                            context: "while scanning a plain scalar",
                            contextMark: startMark
                        )
                    }
                    if hasLeadingBlanks {
                        skip()
                    } else {
                        read(into: &whitespaces)
                    }
                } else if hasLeadingBlanks {
                    readLineBreak(into: &trailingBreaks)
                } else {
                    whitespaces.removeAll(keepingCapacity: true)
                    readLineBreak(into: &leadingBreak)
                    hasLeadingBlanks = true
                }
            }

            if flowLevel == 0 && mark.column < minimumIndent {
                break
            }
        }

        if hasLeadingBlanks {
            isSimpleKeyAllowed = true
        }

        return Token(kind: .scalar(String(decoding: string, as: UTF8.self), style: .plain), startMark: startMark, endMark: endMark)
    }

    private static let flowTerminators = Array(",[]{}".utf8)
    private static let flowIndicators = Array(",?[]{}".utf8)
}

// MARK: - Line folding

extension Scanner {
    private static func foldLineBreaks(leadingBreak: inout [UInt8], trailingBreaks: inout [UInt8], into string: inout [UInt8]) {
        if leadingBreak.first == UInt8(ascii: "\n") {
            if trailingBreaks.isEmpty {
                string.append(UInt8(ascii: " "))
            } else {
                string += trailingBreaks
            }
        } else {
            string += leadingBreak
            string += trailingBreaks
        }
        leadingBreak.removeAll(keepingCapacity: true)
        trailingBreaks.removeAll(keepingCapacity: true)
    }
}
