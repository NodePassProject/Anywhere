//
//  Composer.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

struct Composer {
    static let maximumDepth = 128

    private struct OpenCollection {
        let anchor: String?
        let isMapping: Bool
        let startMark: Mark

        var children: [Node] = []
        var childDepth = 0

        var node: Node {
            guard isMapping else {
                return .sequence(children)
            }
            let pairs = stride(from: 0, to: children.count, by: 2).map { index in
                Node.Pair(key: children[index], value: children[index + 1])
            }
            return .mapping(pairs)
        }
    }

    private var parser: Parser
    private var anchors: [String: (node: Node, depth: Int)] = [:]

    init(_ text: String) throws(YAMLError) {
        parser = try Parser(text)
    }

    mutating func composeDocument() throws(YAMLError) -> Node? {
        while let event = try parser.nextEvent() {
            guard case .documentStart = event.kind else { continue }
            anchors.removeAll()
            let root = try composeNode()
            _ = try parser.nextEvent()
            return root
        }
        return nil
    }

    private mutating func composeNode() throws(YAMLError) -> Node {
        var openCollections: [OpenCollection] = []

        while let event = try parser.nextEvent() {
            let node: Node
            let depth: Int

            switch event.kind {
            case .alias(let anchor):
                guard let target = anchors[anchor] else {
                    throw YAMLError(problem: "found undefined alias", mark: event.startMark)
                }
                (node, depth) = target

            case .scalar(let scalar):
                node = Self.resolve(scalar)
                depth = 0
                register(node, depth: depth, as: scalar.anchor)

            case .sequenceStart(let start), .mappingStart(let start):
                guard openCollections.count < Self.maximumDepth else {
                    throw depthError(at: event.startMark)
                }
                let isMapping = if case .mappingStart = event.kind { true } else { false }
                openCollections.append(OpenCollection(anchor: start.anchor, isMapping: isMapping, startMark: event.startMark))
                continue

            case .sequenceEnd, .mappingEnd:
                let collection = openCollections.removeLast()
                node = collection.node
                depth = collection.childDepth + 1
                register(node, depth: depth, as: collection.anchor)

            case .streamStart, .streamEnd, .documentStart, .documentEnd:
                preconditionFailure("The parser emitted \(event.kind) inside a node")
            }

            guard let parentIndex = openCollections.indices.last else {
                return node
            }
            guard openCollections.count + depth <= Self.maximumDepth else {
                throw depthError(at: openCollections[parentIndex].startMark)
            }
            openCollections[parentIndex].children.append(node)
            openCollections[parentIndex].childDepth = max(openCollections[parentIndex].childDepth, depth)
        }
        preconditionFailure("The parser ended the stream inside a node")
    }

    private mutating func register(_ node: Node, depth: Int, as anchor: String?) {
        guard let anchor else { return }
        anchors[anchor] = (node, depth)
    }

    private func depthError(at mark: Mark) -> YAMLError {
        YAMLError(problem: "found collections nested deeper than \(Self.maximumDepth) levels", mark: mark)
    }

    private static func resolve(_ scalar: Event.Scalar) -> Node {
        switch scalar.tag {
        case nil where scalar.style == .plain && nullSpellings.contains(scalar.value),
             "tag:yaml.org,2002:null":
            return .null
        default:
            return .scalar(scalar.value)
        }
    }

    private static let nullSpellings: Set<String> = ["", "~", "null", "Null", "NULL"]
}
