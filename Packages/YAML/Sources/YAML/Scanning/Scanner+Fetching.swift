//
//  Scanner+Fetching.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

// MARK: - Stream and document

extension Scanner {
    mutating func fetchStreamStart() {
        indent = -1
        simpleKeys.append(SimpleKey())
        isSimpleKeyAllowed = true
        isStreamStartProduced = true
        tokens.append(Token(kind: .streamStart, startMark: mark, endMark: mark))
    }

    mutating func fetchStreamEnd() throws(YAMLError) {
        if mark.column != 0 {
            mark.column = 0
            mark.line += 1
        }
        unrollIndent(toColumn: -1)
        try removeSimpleKey()
        isSimpleKeyAllowed = false
        tokens.append(Token(kind: .streamEnd, startMark: mark, endMark: mark))
    }

    mutating func fetchDirective() throws(YAMLError) {
        unrollIndent(toColumn: -1)
        try removeSimpleKey()
        isSimpleKeyAllowed = false
        tokens.append(try scanDirective())
    }

    mutating func fetchDocumentIndicator(_ kind: Token.Kind) throws(YAMLError) {
        unrollIndent(toColumn: -1)
        try removeSimpleKey()
        isSimpleKeyAllowed = false
        let startMark = mark
        skip()
        skip()
        skip()
        tokens.append(Token(kind: kind, startMark: startMark, endMark: mark))
    }
}

// MARK: - Collections

extension Scanner {
    mutating func fetchFlowCollectionStart(_ kind: Token.Kind) throws(YAMLError) {
        try saveSimpleKey()
        increaseFlowLevel()
        isSimpleKeyAllowed = true
        fetchIndicator(kind)
    }

    mutating func fetchFlowCollectionEnd(_ kind: Token.Kind) throws(YAMLError) {
        try removeSimpleKey()
        decreaseFlowLevel()
        isSimpleKeyAllowed = false
        fetchIndicator(kind)
    }

    mutating func fetchFlowEntry() throws(YAMLError) {
        try removeSimpleKey()
        isSimpleKeyAllowed = true
        fetchIndicator(.flowEntry)
    }

    mutating func fetchBlockEntry() throws(YAMLError) {
        if flowLevel == 0 {
            guard isSimpleKeyAllowed else {
                throw error("block sequence entries are not allowed in this context")
            }
            rollIndent(toColumn: mark.column, kind: .blockSequenceStart, mark: mark)
        }
        try removeSimpleKey()
        isSimpleKeyAllowed = true
        fetchIndicator(.blockEntry)
    }

    mutating func fetchKey() throws(YAMLError) {
        if flowLevel == 0 {
            guard isSimpleKeyAllowed else {
                throw error("mapping keys are not allowed in this context")
            }
            rollIndent(toColumn: mark.column, kind: .blockMappingStart, mark: mark)
        }
        try removeSimpleKey()
        isSimpleKeyAllowed = flowLevel == 0
        fetchIndicator(.key)
    }

    mutating func fetchValue() throws(YAMLError) {
        let key = simpleKeys[simpleKeys.count - 1]
        if key.isPossible {
            let keyToken = Token(kind: .key, startMark: key.mark, endMark: key.mark)
            tokens.insert(keyToken, at: tokensHead + key.tokenNumber - tokensParsed)
            rollIndent(toColumn: key.mark.column, tokenNumber: key.tokenNumber, kind: .blockMappingStart, mark: key.mark)
            simpleKeys[simpleKeys.count - 1].isPossible = false
            isSimpleKeyAllowed = false
        } else {
            if flowLevel == 0 {
                guard isSimpleKeyAllowed else {
                    throw error("mapping values are not allowed in this context")
                }
                rollIndent(toColumn: mark.column, kind: .blockMappingStart, mark: mark)
            }
            isSimpleKeyAllowed = flowLevel == 0
        }
        fetchIndicator(.value)
    }

    private mutating func fetchIndicator(_ kind: Token.Kind) {
        let startMark = mark
        skip()
        tokens.append(Token(kind: kind, startMark: startMark, endMark: mark))
    }
}

// MARK: - Node properties and scalars

extension Scanner {
    mutating func fetchAnchor(isAlias: Bool) throws(YAMLError) {
        try saveSimpleKey()
        isSimpleKeyAllowed = false
        tokens.append(try scanAnchor(isAlias: isAlias))
    }

    mutating func fetchTag() throws(YAMLError) {
        try saveSimpleKey()
        isSimpleKeyAllowed = false
        tokens.append(try scanTag())
    }

    mutating func fetchBlockScalar(isLiteral: Bool) throws(YAMLError) {
        try removeSimpleKey()
        isSimpleKeyAllowed = true
        tokens.append(try scanBlockScalar(isLiteral: isLiteral))
    }

    mutating func fetchFlowScalar(isSingleQuoted: Bool) throws(YAMLError) {
        try saveSimpleKey()
        isSimpleKeyAllowed = false
        tokens.append(try scanFlowScalar(isSingleQuoted: isSingleQuoted))
    }

    mutating func fetchPlainScalar() throws(YAMLError) {
        try saveSimpleKey()
        isSimpleKeyAllowed = false
        tokens.append(try scanPlainScalar())
    }
}
