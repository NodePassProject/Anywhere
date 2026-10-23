//
//  Scanner.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

struct Scanner {
    struct SimpleKey {
        var isPossible = false
        var isRequired = false
        var tokenNumber = 0
        var mark = Mark()
    }

    static let simpleKeyLengthLimit = 1024

    static let indicators = Array("-?:,[]{}#&*!|>'\"%@`".utf8)

    let input: [UInt8]
    var position: Int
    var mark = Mark()

    var tokens: [Token] = []
    var tokensHead = 0
    var tokensParsed = 0
    var isTokenAvailable = false
    var isStreamStartProduced = false

    var indent = -1
    var indents: [Int] = []
    var flowLevel = 0
    var isSimpleKeyAllowed = false
    var simpleKeys: [SimpleKey] = []

    init(_ text: String) throws(YAMLError) {
        input = Array(text.utf8)
        position = input.starts(with: [0xEF, 0xBB, 0xBF]) ? 3 : 0
        try validateInput()
    }

    mutating func peekToken() throws(YAMLError) -> Token {
        if !isTokenAvailable {
            try fetchMoreTokens()
        }
        return tokens[tokensHead]
    }

    mutating func skipToken() {
        isTokenAvailable = false
        tokensParsed += 1
        tokensHead += 1
        if tokensHead == tokens.count {
            tokens.removeAll(keepingCapacity: true)
            tokensHead = 0
        }
    }

    func error(_ problem: String, context: String? = nil, contextMark: Mark? = nil) -> YAMLError {
        YAMLError(problem: problem, mark: mark, context: context, contextMark: contextMark)
    }
}

// MARK: - Input validation

extension Scanner {
    private func validateInput() throws(YAMLError) {
        var index = position
        while index < input.count {
            let byte = input[index]
            if byte < 0x80 {
                guard (0x20...0x7E).contains(byte) || byte == 0x09 || byte == 0x0A || byte == 0x0D else {
                    throw YAMLError(problem: "control characters are not allowed", mark: mark(at: index))
                }
                index += 1
                continue
            }

            let length = Self.sequenceLength(leadingByte: byte)
            var value = UInt32(byte) & (0xFF >> (length + 1))
            for offset in 1..<length {
                value = value << 6 | UInt32(input[index + offset] & 0x3F)
            }
            switch value {
            case 0x85, 0xA0...0xD7FF, 0xE000...0xFFFD, 0x10000...0x10FFFF:
                index += length
            default:
                throw YAMLError(problem: "control characters are not allowed", mark: mark(at: index))
            }
        }
    }

    private func mark(at index: Int) -> Mark {
        var mark = Mark()
        var previous: Unicode.Scalar?
        for scalar in String(decoding: input[position..<index], as: UTF8.self).unicodeScalars {
            switch scalar {
            case "\n" where previous == "\r":
                break
            case "\n", "\r", "\u{85}", "\u{2028}", "\u{2029}":
                mark.line += 1
                mark.column = 0
            default:
                mark.column += 1
            }
            mark.index += 1
            previous = scalar
        }
        return mark
    }
}

// MARK: - Token queue

extension Scanner {
    private mutating func fetchMoreTokens() throws(YAMLError) {
        while true {
            if tokensHead < tokens.count {
                try staleSimpleKeys()
                let isHeadUndecided = simpleKeys.contains { $0.isPossible && $0.tokenNumber == tokensParsed }
                if !isHeadUndecided {
                    break
                }
            }
            try fetchNextToken()
        }
        isTokenAvailable = true
    }

    private mutating func fetchNextToken() throws(YAMLError) {
        guard isStreamStartProduced else {
            fetchStreamStart()
            return
        }

        scanToNextToken()
        try staleSimpleKeys()
        unrollIndent(toColumn: mark.column)

        if isEnd() {
            return try fetchStreamEnd()
        }
        if mark.column == 0 && matches("%") {
            return try fetchDirective()
        }
        if isDocumentIndicator("-") {
            return try fetchDocumentIndicator(.documentStart)
        }
        if isDocumentIndicator(".") {
            return try fetchDocumentIndicator(.documentEnd)
        }
        if matches("[") {
            return try fetchFlowCollectionStart(.flowSequenceStart)
        }
        if matches("{") {
            return try fetchFlowCollectionStart(.flowMappingStart)
        }
        if matches("]") {
            return try fetchFlowCollectionEnd(.flowSequenceEnd)
        }
        if matches("}") {
            return try fetchFlowCollectionEnd(.flowMappingEnd)
        }
        if matches(",") {
            return try fetchFlowEntry()
        }
        if matches("-") && isWhitespaceOrEnd(at: 1) {
            return try fetchBlockEntry()
        }
        if matches("?") && (flowLevel > 0 || isWhitespaceOrEnd(at: 1)) {
            return try fetchKey()
        }
        if matches(":") && (flowLevel > 0 || isWhitespaceOrEnd(at: 1)) {
            return try fetchValue()
        }
        if matches("*") {
            return try fetchAnchor(isAlias: true)
        }
        if matches("&") {
            return try fetchAnchor(isAlias: false)
        }
        if matches("!") {
            return try fetchTag()
        }
        if matches("|") && flowLevel == 0 {
            return try fetchBlockScalar(isLiteral: true)
        }
        if matches(">") && flowLevel == 0 {
            return try fetchBlockScalar(isLiteral: false)
        }
        if matches("'") {
            return try fetchFlowScalar(isSingleQuoted: true)
        }
        if matches("\"") {
            return try fetchFlowScalar(isSingleQuoted: false)
        }
        if canStartPlainScalar {
            return try fetchPlainScalar()
        }
        throw error(
            "found character that cannot start any token",
            context: "while scanning for the next token",
            contextMark: mark
        )
    }

    private var canStartPlainScalar: Bool {
        if !isWhitespaceOrEnd() && !Self.indicators.contains(byte()) {
            return true
        }
        if matches("-") && !isBlank(at: 1) {
            return true
        }
        return flowLevel == 0 && (matches("?") || matches(":")) && !isWhitespaceOrEnd(at: 1)
    }

    private mutating func scanToNextToken() {
        while true {
            if mark.column == 0 && isByteOrderMark() {
                skip()
            }
            while matches(" ") || ((flowLevel > 0 || !isSimpleKeyAllowed) && matches("\t")) {
                skip()
            }
            if matches("#") {
                while !isBreakOrEnd() {
                    skip()
                }
            }
            guard isBreak() else { return }
            skipLineBreak()
            if flowLevel == 0 {
                isSimpleKeyAllowed = true
            }
        }
    }
}

// MARK: - Simple keys

extension Scanner {
    mutating func staleSimpleKeys() throws(YAMLError) {
        for index in simpleKeys.indices where simpleKeys[index].isPossible {
            let key = simpleKeys[index]
            guard key.mark.line < mark.line || key.mark.index + Self.simpleKeyLengthLimit < mark.index else {
                continue
            }
            if key.isRequired {
                throw error("could not find expected ':'", context: "while scanning a simple key", contextMark: key.mark)
            }
            simpleKeys[index].isPossible = false
        }
    }

    mutating func saveSimpleKey() throws(YAMLError) {
        guard isSimpleKeyAllowed else { return }
        let key = SimpleKey(
            isPossible: true,
            isRequired: flowLevel == 0 && indent == mark.column,
            tokenNumber: tokensParsed + tokens.count - tokensHead,
            mark: mark
        )
        try removeSimpleKey()
        simpleKeys[simpleKeys.count - 1] = key
    }

    mutating func removeSimpleKey() throws(YAMLError) {
        let key = simpleKeys[simpleKeys.count - 1]
        if key.isPossible && key.isRequired {
            throw error("could not find expected ':'", context: "while scanning a simple key", contextMark: key.mark)
        }
        simpleKeys[simpleKeys.count - 1].isPossible = false
    }

    mutating func increaseFlowLevel() {
        simpleKeys.append(SimpleKey())
        flowLevel += 1
    }

    mutating func decreaseFlowLevel() {
        guard flowLevel > 0 else { return }
        flowLevel -= 1
        simpleKeys.removeLast()
    }
}

// MARK: - Indentation

extension Scanner {
    mutating func rollIndent(toColumn column: Int, tokenNumber: Int? = nil, kind: Token.Kind, mark: Mark) {
        guard flowLevel == 0, indent < column else { return }
        indents.append(indent)
        indent = column
        let token = Token(kind: kind, startMark: mark, endMark: mark)
        if let tokenNumber {
            tokens.insert(token, at: tokensHead + tokenNumber - tokensParsed)
        } else {
            tokens.append(token)
        }
    }

    mutating func unrollIndent(toColumn column: Int) {
        guard flowLevel == 0 else { return }
        while indent > column {
            tokens.append(Token(kind: .blockEnd, startMark: mark, endMark: mark))
            indent = indents.removeLast()
        }
    }
}
