//
//  Parser+Collections.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

// MARK: - Block collections

extension Parser {
    mutating func parseBlockSequenceEntry(isFirst: Bool) throws(YAMLError) -> Event {
        if isFirst {
            marks.append(try scanner.peekToken().startMark)
            scanner.skipToken()
        }

        var token = try scanner.peekToken()
        switch token.kind {
        case .blockEntry:
            let mark = token.endMark
            scanner.skipToken()
            token = try scanner.peekToken()
            switch token.kind {
            case .blockEntry, .blockEnd:
                state = .blockSequenceEntry
                return emptyScalar(at: mark)
            default:
                states.append(.blockSequenceEntry)
                return try parseNode(isBlock: true, allowsIndentlessSequence: false)
            }

        case .blockEnd:
            state = states.removeLast()
            marks.removeLast()
            scanner.skipToken()
            return Event(kind: .sequenceEnd, startMark: token.startMark, endMark: token.endMark)

        default:
            throw YAMLError(
                problem: "did not find expected '-' indicator",
                mark: token.startMark,
                context: "while parsing a block collection",
                contextMark: marks.removeLast()
            )
        }
    }

    mutating func parseIndentlessSequenceEntry() throws(YAMLError) -> Event {
        var token = try scanner.peekToken()
        guard case .blockEntry = token.kind else {
            state = states.removeLast()
            return Event(kind: .sequenceEnd, startMark: token.startMark, endMark: token.startMark)
        }

        let mark = token.endMark
        scanner.skipToken()
        token = try scanner.peekToken()
        switch token.kind {
        case .blockEntry, .key, .value, .blockEnd:
            state = .indentlessSequenceEntry
            return emptyScalar(at: mark)
        default:
            states.append(.indentlessSequenceEntry)
            return try parseNode(isBlock: true, allowsIndentlessSequence: false)
        }
    }

    mutating func parseBlockMappingKey(isFirst: Bool) throws(YAMLError) -> Event {
        if isFirst {
            marks.append(try scanner.peekToken().startMark)
            scanner.skipToken()
        }

        var token = try scanner.peekToken()
        switch token.kind {
        case .key:
            let mark = token.endMark
            scanner.skipToken()
            token = try scanner.peekToken()
            switch token.kind {
            case .key, .value, .blockEnd:
                state = .blockMappingValue
                return emptyScalar(at: mark)
            default:
                states.append(.blockMappingValue)
                return try parseNode(isBlock: true, allowsIndentlessSequence: true)
            }

        case .blockEnd:
            state = states.removeLast()
            marks.removeLast()
            scanner.skipToken()
            return Event(kind: .mappingEnd, startMark: token.startMark, endMark: token.endMark)

        default:
            throw YAMLError(
                problem: "did not find expected key",
                mark: token.startMark,
                context: "while parsing a block mapping",
                contextMark: marks.removeLast()
            )
        }
    }

    mutating func parseBlockMappingValue() throws(YAMLError) -> Event {
        var token = try scanner.peekToken()
        guard case .value = token.kind else {
            state = .blockMappingKey
            return emptyScalar(at: token.startMark)
        }

        let mark = token.endMark
        scanner.skipToken()
        token = try scanner.peekToken()
        switch token.kind {
        case .key, .value, .blockEnd:
            state = .blockMappingKey
            return emptyScalar(at: mark)
        default:
            states.append(.blockMappingKey)
            return try parseNode(isBlock: true, allowsIndentlessSequence: true)
        }
    }
}

// MARK: - Flow sequences

extension Parser {
    mutating func parseFlowSequenceEntry(isFirst: Bool) throws(YAMLError) -> Event {
        if isFirst {
            marks.append(try scanner.peekToken().startMark)
            scanner.skipToken()
        }

        var token = try scanner.peekToken()
        if !token.isFlowSequenceEnd {
            if !isFirst {
                guard case .flowEntry = token.kind else {
                    throw YAMLError(
                        problem: "did not find expected ',' or ']'",
                        mark: token.startMark,
                        context: "while parsing a flow sequence",
                        contextMark: marks.removeLast()
                    )
                }
                scanner.skipToken()
                token = try scanner.peekToken()
            }

            if case .key = token.kind {
                state = .flowSequenceEntryMappingKey
                let start = Event.CollectionStart(anchor: nil, tag: nil, isImplicit: true, style: .flow)
                return Event(kind: .mappingStart(start), startMark: token.startMark, endMark: token.endMark)
            }
            if !token.isFlowSequenceEnd {
                states.append(.flowSequenceEntry)
                return try parseNode(isBlock: false, allowsIndentlessSequence: false)
            }
        }

        state = states.removeLast()
        marks.removeLast()
        scanner.skipToken()
        return Event(kind: .sequenceEnd, startMark: token.startMark, endMark: token.endMark)
    }

    mutating func parseFlowSequenceEntryMappingKey() throws(YAMLError) -> Event {
        let mark = try scanner.peekToken().endMark
        scanner.skipToken()

        let token = try scanner.peekToken()
        switch token.kind {
        case .value, .flowEntry, .flowSequenceEnd:
            state = .flowSequenceEntryMappingValue
            return emptyScalar(at: mark)
        default:
            states.append(.flowSequenceEntryMappingValue)
            return try parseNode(isBlock: false, allowsIndentlessSequence: false)
        }
    }

    mutating func parseFlowSequenceEntryMappingValue() throws(YAMLError) -> Event {
        var token = try scanner.peekToken()
        if case .value = token.kind {
            scanner.skipToken()
            token = try scanner.peekToken()
            switch token.kind {
            case .flowEntry, .flowSequenceEnd:
                break
            default:
                states.append(.flowSequenceEntryMappingEnd)
                return try parseNode(isBlock: false, allowsIndentlessSequence: false)
            }
        }
        state = .flowSequenceEntryMappingEnd
        return emptyScalar(at: token.startMark)
    }

    mutating func parseFlowSequenceEntryMappingEnd() throws(YAMLError) -> Event {
        let token = try scanner.peekToken()
        state = .flowSequenceEntry
        return Event(kind: .mappingEnd, startMark: token.startMark, endMark: token.startMark)
    }
}

// MARK: - Flow mappings

extension Parser {
    mutating func parseFlowMappingKey(isFirst: Bool) throws(YAMLError) -> Event {
        if isFirst {
            marks.append(try scanner.peekToken().startMark)
            scanner.skipToken()
        }

        var token = try scanner.peekToken()
        if !token.isFlowMappingEnd {
            if !isFirst {
                guard case .flowEntry = token.kind else {
                    throw YAMLError(
                        problem: "did not find expected ',' or '}'",
                        mark: token.startMark,
                        context: "while parsing a flow mapping",
                        contextMark: marks.removeLast()
                    )
                }
                scanner.skipToken()
                token = try scanner.peekToken()
            }

            if case .key = token.kind {
                scanner.skipToken()
                token = try scanner.peekToken()
                switch token.kind {
                case .value, .flowEntry, .flowMappingEnd:
                    state = .flowMappingValue
                    return emptyScalar(at: token.startMark)
                default:
                    states.append(.flowMappingValue)
                    return try parseNode(isBlock: false, allowsIndentlessSequence: false)
                }
            }
            if !token.isFlowMappingEnd {
                states.append(.flowMappingEmptyValue)
                return try parseNode(isBlock: false, allowsIndentlessSequence: false)
            }
        }

        state = states.removeLast()
        marks.removeLast()
        scanner.skipToken()
        return Event(kind: .mappingEnd, startMark: token.startMark, endMark: token.endMark)
    }

    mutating func parseFlowMappingValue(isEmpty: Bool) throws(YAMLError) -> Event {
        var token = try scanner.peekToken()
        guard !isEmpty else {
            state = .flowMappingKey
            return emptyScalar(at: token.startMark)
        }

        if case .value = token.kind {
            scanner.skipToken()
            token = try scanner.peekToken()
            switch token.kind {
            case .flowEntry, .flowMappingEnd:
                break
            default:
                states.append(.flowMappingKey)
                return try parseNode(isBlock: false, allowsIndentlessSequence: false)
            }
        }
        state = .flowMappingKey
        return emptyScalar(at: token.startMark)
    }
}

private extension Token {
    var isFlowSequenceEnd: Bool {
        guard case .flowSequenceEnd = kind else { return false }
        return true
    }

    var isFlowMappingEnd: Bool {
        guard case .flowMappingEnd = kind else { return false }
        return true
    }
}
