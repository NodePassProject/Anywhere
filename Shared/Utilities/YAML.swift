//
//  YAML.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation

enum YAML {
    enum NodeType: Sendable {
        case undefined
        case null
        case scalar
        case sequence
        case map
    }

    enum ParseError: Error, LocalizedError {
        case initializationFailed
        case parse(String)

        var errorDescription: String? {
            switch self {
            case .initializationFailed: return "Failed to initialize the YAML parser"
            case .parse(let message):   return message
            }
        }
    }

    final class Node {
        enum Storage {
            case undefined
            case null
            case scalar(String)
            case sequence([Node])
            case map([(key: Node, value: Node)])
        }

        let storage: Storage

        init(_ storage: Storage = .undefined) {
            self.storage = storage
        }

        var type: NodeType {
            switch storage {
            case .undefined: return .undefined
            case .null:      return .null
            case .scalar:    return .scalar
            case .sequence:  return .sequence
            case .map:       return .map
            }
        }

        /// The scalar text, or "" for non-scalar nodes.
        var scalar: String {
            if case .scalar(let value) = storage { return value }
            return ""
        }

        /// Mapping lookup by key. Returns an undefined node when the key is
        /// absent or the receiver isn't a mapping.
        subscript(key: String) -> Node {
            guard case .map(let pairs) = storage else { return Node() }
            for pair in pairs where pair.key.scalar == key {
                return pair.value
            }
            return Node()
        }

        /// Sequence (and key/value pair) indexing. Returns an undefined node
        /// when out of range or the receiver isn't a sequence.
        subscript(index: Int) -> Node {
            guard case .sequence(let elements) = storage,
                  index >= 0, index < elements.count else { return Node() }
            return elements[index]
        }
    }

    /// Parses the first document of `input` into a `Node` tree.
    static func load(_ input: String) throws -> Node {
        var parser = yaml_parser_t()
        guard yaml_parser_initialize(&parser) == 1 else {
            throw ParseError.initializationFailed
        }
        defer { yaml_parser_delete(&parser) }

        let bytes = Array(input.utf8)
        return try withUnsafeMutablePointer(to: &parser) { parserPtr in
            try bytes.withUnsafeBufferPointer { buffer in
                yaml_parser_set_input_string(parserPtr, buffer.baseAddress, buffer.count)
                return try Loader(parser: parserPtr).loadDocument()
            }
        }
    }
}

// MARK: - Sequence conformance

extension YAML.Node: Sequence {
    func makeIterator() -> AnyIterator<YAML.Node> {
        switch storage {
        case .sequence(let elements):
            var iterator = elements.makeIterator()
            return AnyIterator { iterator.next() }
        case .map(let pairs):
            var iterator = pairs.makeIterator()
            return AnyIterator {
                guard let pair = iterator.next() else { return nil }
                return YAML.Node(.sequence([pair.key, pair.value]))
            }
        default:
            return AnyIterator { nil }
        }
    }
}

// MARK: - libyaml event consumer

private final class Loader {
    private let parser: UnsafeMutablePointer<yaml_parser_t>
    private var anchors: [String: YAML.Node] = [:]

    init(parser: UnsafeMutablePointer<yaml_parser_t>) {
        self.parser = parser
    }

    /// Reads one event. The caller owns it and must `yaml_event_delete` it.
    private func nextEvent() throws -> yaml_event_t {
        var event = yaml_event_t()
        guard yaml_parser_parse(parser, &event) == 1 else {
            let message: String
            if let problem = parser.pointee.problem {
                let line = parser.pointee.problem_mark.line + 1
                let column = parser.pointee.problem_mark.column + 1
                message = "\(String(cString: problem)) at line \(line), column \(column)"
            } else {
                message = "YAML parse error"
            }
            throw YAML.ParseError.parse(message)
        }
        return event
    }

    /// Skips stream/document framing and returns the document's root node.
    func loadDocument() throws -> YAML.Node {
        while true {
            var event = try nextEvent()
            let type = event.type
            yaml_event_delete(&event)
            if type == YAML_STREAM_END_EVENT {
                return YAML.Node()                       // empty input
            }
            if type == YAML_DOCUMENT_START_EVENT {
                return try parseNode() ?? YAML.Node()
            }
            // STREAM_START and anything else: keep advancing.
        }
    }

    /// Builds the node for the next event, or nil when that event closes a
    /// container (so callers can loop until nil).
    private func parseNode() throws -> YAML.Node? {
        var event = try nextEvent()
        defer { yaml_event_delete(&event) }

        switch event.type {
        case YAML_SEQUENCE_END_EVENT, YAML_MAPPING_END_EVENT,
             YAML_DOCUMENT_END_EVENT, YAML_STREAM_END_EVENT, YAML_NO_EVENT:
            return nil

        case YAML_ALIAS_EVENT:
            return anchors[string(event.data.alias.anchor)] ?? YAML.Node()

        case YAML_SCALAR_EVENT:
            let value = scalarString(event)
            let isPlain = event.data.scalar.style == YAML_PLAIN_SCALAR_STYLE
            let node = (isPlain && Loader.isNull(value)) ? YAML.Node(.null) : YAML.Node(.scalar(value))
            register(event.data.scalar.anchor, node)
            return node

        case YAML_SEQUENCE_START_EVENT:
            let anchor = event.data.sequence_start.anchor
            var elements: [YAML.Node] = []
            while let child = try parseNode() { elements.append(child) }
            let node = YAML.Node(.sequence(elements))
            register(anchor, node)
            return node

        case YAML_MAPPING_START_EVENT:
            let anchor = event.data.mapping_start.anchor
            var pairs: [(key: YAML.Node, value: YAML.Node)] = []
            while let key = try parseNode() {
                guard let value = try parseNode() else { break }
                pairs.append((key, value))
            }
            let node = YAML.Node(.map(pairs))
            register(anchor, node)
            return node

        default:
            return YAML.Node()
        }
    }

    private func register(_ anchor: UnsafeMutablePointer<UInt8>?, _ node: YAML.Node) {
        let name = string(anchor)
        if !name.isEmpty { anchors[name] = node }
    }

    private func string(_ pointer: UnsafeMutablePointer<UInt8>?) -> String {
        guard let pointer else { return "" }
        return String(cString: pointer)
    }

    private func scalarString(_ event: yaml_event_t) -> String {
        guard let value = event.data.scalar.value else { return "" }
        return String(decoding: UnsafeBufferPointer(start: value, count: event.data.scalar.length), as: UTF8.self)
    }

    /// YAML core-schema null in plain style.
    private static func isNull(_ value: String) -> Bool {
        switch value {
        case "", "~", "null", "Null", "NULL": return true
        default: return false
        }
    }
}
