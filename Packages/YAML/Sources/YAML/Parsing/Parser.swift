//
//  Parser.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

struct Parser {
    enum State {
        case streamStart
        case implicitDocumentStart
        case documentStart
        case documentContent
        case documentEnd
        case blockNode
        case blockNodeOrIndentlessSequence
        case flowNode
        case blockSequenceFirstEntry
        case blockSequenceEntry
        case indentlessSequenceEntry
        case blockMappingFirstKey
        case blockMappingKey
        case blockMappingValue
        case flowSequenceFirstEntry
        case flowSequenceEntry
        case flowSequenceEntryMappingKey
        case flowSequenceEntryMappingValue
        case flowSequenceEntryMappingEnd
        case flowMappingFirstKey
        case flowMappingKey
        case flowMappingValue
        case flowMappingEmptyValue
        case end
    }

    var scanner: Scanner
    var state = State.streamStart
    var states: [State] = []
    var marks: [Mark] = []
    var tagDirectives: [TagDirective] = []

    init(_ text: String) throws(YAMLError) {
        scanner = try Scanner(text)
    }

    mutating func nextEvent() throws(YAMLError) -> Event? {
        switch state {
        case .streamStart:
            return try parseStreamStart()
        case .implicitDocumentStart:
            return try parseDocumentStart(isImplicit: true)
        case .documentStart:
            return try parseDocumentStart(isImplicit: false)
        case .documentContent:
            return try parseDocumentContent()
        case .documentEnd:
            return try parseDocumentEnd()
        case .blockNode:
            return try parseNode(isBlock: true, allowsIndentlessSequence: false)
        case .blockNodeOrIndentlessSequence:
            return try parseNode(isBlock: true, allowsIndentlessSequence: true)
        case .flowNode:
            return try parseNode(isBlock: false, allowsIndentlessSequence: false)
        case .blockSequenceFirstEntry:
            return try parseBlockSequenceEntry(isFirst: true)
        case .blockSequenceEntry:
            return try parseBlockSequenceEntry(isFirst: false)
        case .indentlessSequenceEntry:
            return try parseIndentlessSequenceEntry()
        case .blockMappingFirstKey:
            return try parseBlockMappingKey(isFirst: true)
        case .blockMappingKey:
            return try parseBlockMappingKey(isFirst: false)
        case .blockMappingValue:
            return try parseBlockMappingValue()
        case .flowSequenceFirstEntry:
            return try parseFlowSequenceEntry(isFirst: true)
        case .flowSequenceEntry:
            return try parseFlowSequenceEntry(isFirst: false)
        case .flowSequenceEntryMappingKey:
            return try parseFlowSequenceEntryMappingKey()
        case .flowSequenceEntryMappingValue:
            return try parseFlowSequenceEntryMappingValue()
        case .flowSequenceEntryMappingEnd:
            return try parseFlowSequenceEntryMappingEnd()
        case .flowMappingFirstKey:
            return try parseFlowMappingKey(isFirst: true)
        case .flowMappingKey:
            return try parseFlowMappingKey(isFirst: false)
        case .flowMappingValue:
            return try parseFlowMappingValue(isEmpty: false)
        case .flowMappingEmptyValue:
            return try parseFlowMappingValue(isEmpty: true)
        case .end:
            return nil
        }
    }

    func emptyScalar(at mark: Mark) -> Event {
        let scalar = Event.Scalar(value: "", anchor: nil, tag: nil, style: .plain, isPlainImplicit: true, isQuotedImplicit: false)
        return Event(kind: .scalar(scalar), startMark: mark, endMark: mark)
    }
}

// MARK: - Stream and documents

extension Parser {
    private mutating func parseStreamStart() throws(YAMLError) -> Event {
        let token = try scanner.peekToken()
        guard case .streamStart = token.kind else {
            throw YAMLError(problem: "did not find expected <stream-start>", mark: token.startMark)
        }
        state = .implicitDocumentStart
        scanner.skipToken()
        return Event(kind: .streamStart, startMark: token.startMark, endMark: token.startMark)
    }

    private mutating func parseDocumentStart(isImplicit: Bool) throws(YAMLError) -> Event {
        var token = try scanner.peekToken()

        if !isImplicit {
            while case .documentEnd = token.kind {
                scanner.skipToken()
                token = try scanner.peekToken()
            }
        }

        switch token.kind {
        case .streamEnd:
            state = .end
            scanner.skipToken()
            return Event(kind: .streamEnd, startMark: token.startMark, endMark: token.endMark)

        case .versionDirective, .tagDirective, .documentStart:
            return try parseExplicitDocumentStart()

        default:
            guard isImplicit else {
                return try parseExplicitDocumentStart()
            }
            _ = try processDirectives()
            states.append(.documentEnd)
            state = .blockNode
            let kind = Event.Kind.documentStart(version: nil, tagDirectives: [], isImplicit: true)
            return Event(kind: kind, startMark: token.startMark, endMark: token.startMark)
        }
    }

    private mutating func parseExplicitDocumentStart() throws(YAMLError) -> Event {
        let startMark = try scanner.peekToken().startMark
        let directives = try processDirectives()
        let token = try scanner.peekToken()
        guard case .documentStart = token.kind else {
            throw YAMLError(problem: "did not find expected <document start>", mark: token.startMark)
        }
        states.append(.documentEnd)
        state = .documentContent
        scanner.skipToken()
        let kind = Event.Kind.documentStart(version: directives.version, tagDirectives: directives.tags, isImplicit: false)
        return Event(kind: kind, startMark: startMark, endMark: token.endMark)
    }

    private mutating func parseDocumentContent() throws(YAMLError) -> Event {
        let token = try scanner.peekToken()
        switch token.kind {
        case .versionDirective, .tagDirective, .documentStart, .documentEnd, .streamEnd:
            state = states.removeLast()
            return emptyScalar(at: token.startMark)
        default:
            return try parseNode(isBlock: true, allowsIndentlessSequence: false)
        }
    }

    private mutating func parseDocumentEnd() throws(YAMLError) -> Event {
        let token = try scanner.peekToken()
        var endMark = token.startMark
        var isImplicit = true
        if case .documentEnd = token.kind {
            endMark = token.endMark
            isImplicit = false
            scanner.skipToken()
        }
        tagDirectives.removeAll()
        state = .documentStart
        return Event(kind: .documentEnd(isImplicit: isImplicit), startMark: token.startMark, endMark: endMark)
    }

    private mutating func processDirectives() throws(YAMLError) -> (version: VersionDirective?, tags: [TagDirective]) {
        var version: VersionDirective?
        var tags: [TagDirective] = []
        var token = try scanner.peekToken()

        directives: while true {
            switch token.kind {
            case .versionDirective(let major, let minor):
                guard version == nil else {
                    throw YAMLError(problem: "found duplicate %YAML directive", mark: token.startMark)
                }
                guard major == 1, minor == 1 || minor == 2 else {
                    throw YAMLError(problem: "found incompatible YAML document", mark: token.startMark)
                }
                version = VersionDirective(major: major, minor: minor)
            case .tagDirective(let handle, let prefix):
                let directive = TagDirective(handle: handle, prefix: prefix)
                try appendTagDirective(directive, allowsDuplicates: false, mark: token.startMark)
                tags.append(directive)
            default:
                break directives
            }
            scanner.skipToken()
            token = try scanner.peekToken()
        }

        for directive in Self.defaultTagDirectives {
            try appendTagDirective(directive, allowsDuplicates: true, mark: token.startMark)
        }
        return (version, tags)
    }

    private static let defaultTagDirectives = [
        TagDirective(handle: "!", prefix: "!"),
        TagDirective(handle: "!!", prefix: "tag:yaml.org,2002:"),
    ]

    private mutating func appendTagDirective(_ directive: TagDirective, allowsDuplicates: Bool, mark: Mark) throws(YAMLError) {
        guard !tagDirectives.contains(where: { $0.handle == directive.handle }) else {
            if allowsDuplicates {
                return
            }
            throw YAMLError(problem: "found duplicate %TAG directive", mark: mark)
        }
        tagDirectives.append(directive)
    }
}

// MARK: - Nodes

extension Parser {
    mutating func parseNode(isBlock: Bool, allowsIndentlessSequence: Bool) throws(YAMLError) -> Event {
        var token = try scanner.peekToken()

        if case .alias(let anchor) = token.kind {
            state = states.removeLast()
            scanner.skipToken()
            return Event(kind: .alias(anchor: anchor), startMark: token.startMark, endMark: token.endMark)
        }

        let startMark = token.startMark
        var endMark = token.startMark
        var anchor: String?
        var tagToken: (handle: String, suffix: String, mark: Mark)?

        switch token.kind {
        case .anchor(let name):
            anchor = name
            endMark = token.endMark
            scanner.skipToken()
            token = try scanner.peekToken()
            if case .tag(let handle, let suffix) = token.kind {
                tagToken = (handle, suffix, token.startMark)
                endMark = token.endMark
                scanner.skipToken()
                token = try scanner.peekToken()
            }
        case .tag(let handle, let suffix):
            tagToken = (handle, suffix, token.startMark)
            endMark = token.endMark
            scanner.skipToken()
            token = try scanner.peekToken()
            if case .anchor(let name) = token.kind {
                anchor = name
                endMark = token.endMark
                scanner.skipToken()
                token = try scanner.peekToken()
            }
        default:
            break
        }

        var tag: String?
        if let tagToken {
            tag = try resolveTag(handle: tagToken.handle, suffix: tagToken.suffix, mark: tagToken.mark, nodeMark: startMark)
        }
        let isImplicit = tag?.isEmpty ?? true

        func collectionStart(_ style: CollectionStyle) -> Event.CollectionStart {
            Event.CollectionStart(anchor: anchor, tag: tag, isImplicit: isImplicit, style: style)
        }

        switch token.kind {
        case .blockEntry where allowsIndentlessSequence:
            state = .indentlessSequenceEntry
            return Event(kind: .sequenceStart(collectionStart(.block)), startMark: startMark, endMark: token.endMark)

        case .scalar(let value, let style):
            let isPlainImplicit = (style == .plain && tag == nil) || tag == "!"
            let scalar = Event.Scalar(
                value: value,
                anchor: anchor,
                tag: tag,
                style: style,
                isPlainImplicit: isPlainImplicit,
                isQuotedImplicit: !isPlainImplicit && tag == nil
            )
            state = states.removeLast()
            scanner.skipToken()
            return Event(kind: .scalar(scalar), startMark: startMark, endMark: token.endMark)

        case .flowSequenceStart:
            state = .flowSequenceFirstEntry
            return Event(kind: .sequenceStart(collectionStart(.flow)), startMark: startMark, endMark: token.endMark)

        case .flowMappingStart:
            state = .flowMappingFirstKey
            return Event(kind: .mappingStart(collectionStart(.flow)), startMark: startMark, endMark: token.endMark)

        case .blockSequenceStart where isBlock:
            state = .blockSequenceFirstEntry
            return Event(kind: .sequenceStart(collectionStart(.block)), startMark: startMark, endMark: token.endMark)

        case .blockMappingStart where isBlock:
            state = .blockMappingFirstKey
            return Event(kind: .mappingStart(collectionStart(.block)), startMark: startMark, endMark: token.endMark)

        default:
            guard anchor != nil || tag != nil else {
                throw YAMLError(
                    problem: "did not find expected node content",
                    mark: token.startMark,
                    context: isBlock ? "while parsing a block node" : "while parsing a flow node",
                    contextMark: startMark
                )
            }
            let scalar = Event.Scalar(
                value: "",
                anchor: anchor,
                tag: tag,
                style: .plain,
                isPlainImplicit: isImplicit,
                isQuotedImplicit: false
            )
            state = states.removeLast()
            return Event(kind: .scalar(scalar), startMark: startMark, endMark: endMark)
        }
    }

    private func resolveTag(handle: String, suffix: String, mark: Mark, nodeMark: Mark) throws(YAMLError) -> String {
        guard !handle.isEmpty else {
            return suffix
        }
        guard let directive = tagDirectives.first(where: { $0.handle == handle }) else {
            throw YAMLError(problem: "found undefined tag handle", mark: mark, context: "while parsing a node", contextMark: nodeMark)
        }
        return directive.prefix + suffix
    }
}
