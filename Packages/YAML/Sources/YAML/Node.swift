//
//  Node.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

public enum Node: Hashable, Sendable {
    case null
    case scalar(String)
    case sequence([Node])
    case mapping([Pair])
}

extension Node {
    public struct Pair: Hashable, Sendable {
        public var key: Node
        public var value: Node

        public init(key: Node, value: Node) {
            self.key = key
            self.value = value
        }
    }
}

// MARK: - Accessors

extension Node {
    public var isNull: Bool {
        self == .null
    }

    public var string: String? {
        guard case .scalar(let value) = self else { return nil }
        return value
    }

    public var sequence: [Node]? {
        guard case .sequence(let elements) = self else { return nil }
        return elements
    }

    public var mapping: [Pair]? {
        guard case .mapping(let pairs) = self else { return nil }
        return pairs
    }

    public subscript(key: String) -> Node? {
        guard case .mapping(let pairs) = self else { return nil }
        return pairs.first { $0.key.string == key }?.value
    }
}
