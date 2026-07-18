//
//  MITMJSONPatch.swift
//  Anywhere
//
//  Created by NodePassProject on 5/31/26.
//

import Foundation

nonisolated enum MITMJSONPatch {
    enum PathSegment: Equatable {
        case key(String)
        case index(Int)
    }

    enum LeafMode { case add, replace, delete }
    
    struct JSONLiteral: Sendable {
        private let fragment: Data
        
        init(_ value: Any) {
            fragment = (try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed]))
                ?? Data("null".utf8)
        }
        
        func materialize() -> Any {
            (try? JSONSerialization.jsonObject(with: fragment, options: [.mutableContainers, .fragmentsAllowed]))
                ?? NSNull()
        }
    }

    enum CompiledOperation: Sendable {
        case add(path: [PathSegment], value: JSONLiteral)
        case replace(path: [PathSegment], value: JSONLiteral)
        case delete(path: [PathSegment])
        case replaceRecursive(key: String, value: JSONLiteral)
        case deleteRecursive(key: String)
        case removeWhereKeyExists(path: [PathSegment], key: String)
        case removeWhereFieldIn(path: [PathSegment], field: String, values: [JSONLiteral])
    }

    // MARK: - Compilation
    
    static func compile(_ operation: MITMJSONOperation) -> CompiledOperation? {
        switch operation {
        case .add(let path, let value):
            guard let segments = parseJSONPath(path) else { return nil }
            return .add(path: segments, value: JSONLiteral(parseValue(value)))
        case .replace(let path, let value):
            guard let segments = parseJSONPath(path) else { return nil }
            return .replace(path: segments, value: JSONLiteral(parseValue(value)))
        case .delete(let path):
            guard let segments = parseJSONPath(path) else { return nil }
            return .delete(path: segments)
        case .replaceRecursive(let key, let value):
            return .replaceRecursive(key: key, value: JSONLiteral(parseValue(value)))
        case .deleteRecursive(let key):
            return .deleteRecursive(key: key)
        case .removeWhereKeyExists(let path, let key):
            guard let segments = parseJSONPath(path) else { return nil }
            return .removeWhereKeyExists(path: segments, key: key)
        case .removeWhereFieldIn(let path, let field, let values):
            guard let segments = parseJSONPath(path) else { return nil }
            return .removeWhereFieldIn(path: segments, field: field, values: parseValues(values).map(JSONLiteral.init))
        }
    }
    
    static func parseValue(_ raw: String) -> Any {
        if let parsed = try? JSONSerialization.jsonObject(
            with: Data(raw.utf8),
            options: [.fragmentsAllowed]
        ) {
            return parsed
        }
        return raw
    }
    
    static func parseValues(_ raw: String) -> [Any] {
        if let parsed = try? JSONSerialization.jsonObject(
            with: Data(raw.utf8),
            options: [.fragmentsAllowed]
        ) {
            if let array = parsed as? [Any] { return array }
            return [parsed]
        }
        return [raw]
    }

    // MARK: - Application
    
    static func applyAll(_ operations: [CompiledOperation], to body: Data) -> Data {
        guard !operations.isEmpty else { return body }
        guard var root = parse(body) else { return body }
        let before = snapshot(root)
        for operation in operations {
            apply(operation, to: &root)
        }
        guard !documentsEqual(before, root) else { return body }
        guard let out = serialize(root) else { return body }
        return out
    }
    
    private static func apply(_ operation: CompiledOperation, to root: inout Any) {
        switch operation {
        case .add(let path, let value):
            root = applyAtPath(root, segments: path, mode: .add, value: value.materialize())
        case .replace(let path, let value):
            root = applyAtPath(root, segments: path, mode: .replace, value: value.materialize())
        case .delete(let path):
            root = applyAtPath(root, segments: path, mode: .delete, value: nil)
        case .replaceRecursive(let key, let value):
            replaceKeyRecursive(root, key: key, value: value.materialize())
        case .deleteRecursive(let key):
            deleteKeyRecursive(root, key: key)
        case .removeWhereKeyExists(let path, let key):
            guard let array = resolveNode(root, segments: path) as? NSMutableArray else { return }
            let kept = array.filter { ($0 as? NSDictionary)?.object(forKey: key) == nil }
            array.setArray(kept)
        case .removeWhereFieldIn(let path, let field, let values):
            guard let array = resolveNode(root, segments: path) as? NSMutableArray else { return }
            let materialized = values.map { $0.materialize() }
            let kept = array.filter { element in
                guard let object = element as? NSDictionary,
                      let fieldValue = object.object(forKey: field) else { return true }
                return !materialized.contains { valueEquals($0, fieldValue) }
            }
            array.setArray(kept)
        }
    }

    // MARK: - Parse / serialize
    
    static func parse(_ data: Data) -> Any? {
        guard !data.isEmpty else { return nil }
        return try? JSONSerialization.jsonObject(with: data, options: [.mutableContainers, .fragmentsAllowed])
    }
    
    static func serialize(_ object: Any) -> Data? {
        guard isJSONEncodable(object) else { return nil }
        return try? JSONSerialization.data(withJSONObject: object, options: [.fragmentsAllowed, .withoutEscapingSlashes])
    }
    
    private static func isJSONEncodable(_ object: Any, depth: Int = 0) -> Bool {
        guard depth < maxRecursionDepth else { return false }
        switch object {
        case let number as NSNumber:
            return number.doubleValue.isFinite
        case is NSString:
            return true
        case is NSNull:
            return true
        case let array as NSArray:
            for element in array where !isJSONEncodable(element, depth: depth + 1) { return false }
            return true
        case let dictionary as NSDictionary:
            for (key, value) in dictionary {
                guard key is NSString, isJSONEncodable(value, depth: depth + 1) else { return false }
            }
            return true
        default:
            return false
        }
    }

    // MARK: - JSONPath
    
    static func parseJSONPath(_ raw: String) -> [PathSegment]? {
        var segments: [PathSegment] = []
        var characters = Substring(raw)
        if characters.first == "$" { characters = characters.dropFirst() }
        while let c = characters.first {
            if c == "." {
                characters = characters.dropFirst()
                var name = ""
                while let d = characters.first, d != ".", d != "[" {
                    name.append(d)
                    characters = characters.dropFirst()
                }
                if name.isEmpty { return nil }
                segments.append(.key(name))
            } else if c == "[" {
                characters = characters.dropFirst()
                var inner = ""
                // Scan past a quoted key first: it may contain `]` (`["a]b"]`).
                if let quote = characters.first, quote == "\"" || quote == "'" {
                    inner.append(quote)
                    characters = characters.dropFirst()
                    while let d = characters.first, d != quote {
                        inner.append(d)
                        characters = characters.dropFirst()
                    }
                    guard characters.first == quote else { return nil }
                    inner.append(quote)
                    characters = characters.dropFirst()
                }
                while let d = characters.first, d != "]" {
                    inner.append(d)
                    characters = characters.dropFirst()
                }
                guard characters.first == "]" else { return nil }
                characters = characters.dropFirst()
                let token = inner.trimmingCharacters(in: .whitespaces)
                if token.count >= 2,
                   (token.first == "\"" && token.last == "\"") || (token.first == "'" && token.last == "'") {
                    segments.append(.key(String(token.dropFirst().dropLast())))
                } else if !token.isEmpty, token.allSatisfy({ $0.isASCII && $0.isNumber }) {
                    // Int(_:) fails only on overflow — reject rather than fall through to .key.
                    guard let index = Int(token) else { return nil }
                    segments.append(.index(index))
                } else if !token.isEmpty {
                    segments.append(.key(token))
                } else {
                    return nil
                }
            } else {
                var name = ""
                while let d = characters.first, d != ".", d != "[" {
                    name.append(d)
                    characters = characters.dropFirst()
                }
                if name.isEmpty { return nil }
                segments.append(.key(name))
            }
        }
        return segments
    }
    
    private static func childNode(_ node: Any?, _ segment: PathSegment) -> Any? {
        guard let node else { return nil }
        switch segment {
        case .key(let key):
            return (node as? NSDictionary)?.object(forKey: key)
        case .index(let index):
            guard let array = node as? NSArray, index >= 0, index < array.count else { return nil }
            return array[index]
        }
    }
    
    static func resolveNode(_ root: Any, segments: [PathSegment]) -> Any? {
        var node: Any? = root
        for segment in segments {
            node = childNode(node, segment)
        }
        return node
    }
    
    static func applyAtPath(_ root: Any, segments: [PathSegment], mode: LeafMode, value: Any?) -> Any {
        if segments.isEmpty {
            switch mode {
            case .add, .replace: return value.map { deepCopy($0) } ?? root
            case .delete: return root
            }
        }
        var node: Any? = root
        for segment in segments.dropLast() {
            node = childNode(node, segment)
        }
        guard let parent = node, let leaf = segments.last else { return root }
        switch leaf {
        case .key(let key):
            guard let dictionary = parent as? NSMutableDictionary else { return root }
            switch mode {
            case .add:
                if let value { dictionary.setObject(deepCopy(value), forKey: key as NSString) }
            case .replace:
                if dictionary.object(forKey: key) != nil, let value {
                    dictionary.setObject(deepCopy(value), forKey: key as NSString)
                }
            case .delete:
                dictionary.removeObject(forKey: key)
            }
        case .index(let index):
            guard let array = parent as? NSMutableArray else { return root }
            let count = array.count
            switch mode {
            case .add:
                if let value {
                    if index >= 0, index < count { array.replaceObject(at: index, with: deepCopy(value)) }
                    else if index == count { array.add(deepCopy(value)) }
                }
            case .replace:
                if let value, index >= 0, index < count { array.replaceObject(at: index, with: deepCopy(value)) }
            case .delete:
                if index >= 0, index < count { array.removeObject(at: index) }
            }
        }
        return root
    }
    
    private static let maxRecursionDepth = 600
    
    static func replaceKeyRecursive(_ node: Any?, key: String, value: Any, depth: Int = 0) {
        guard depth < maxRecursionDepth else { return }
        if let dictionary = node as? NSMutableDictionary {
            for k in dictionary.allKeys {
                guard let ks = k as? String, ks != key else { continue }
                replaceKeyRecursive(dictionary.object(forKey: ks), key: key, value: value, depth: depth + 1)
            }
            if dictionary.object(forKey: key) != nil {
                dictionary.setObject(deepCopy(value), forKey: key as NSString)
            }
        } else if let array = node as? NSMutableArray {
            for element in array { replaceKeyRecursive(element, key: key, value: value, depth: depth + 1) }
        }
    }

    static func deleteKeyRecursive(_ node: Any?, key: String, depth: Int = 0) {
        guard depth < maxRecursionDepth else { return }
        if let dictionary = node as? NSMutableDictionary {
            dictionary.removeObject(forKey: key)
            for k in dictionary.allKeys {
                if let ks = k as? String { deleteKeyRecursive(dictionary.object(forKey: ks), key: key, depth: depth + 1) }
            }
        } else if let array = node as? NSMutableArray {
            for element in array { deleteKeyRecursive(element, key: key, depth: depth + 1) }
        }
    }

    // MARK: - Helpers
    
    private static func isBooleanNumber(_ value: Any) -> Bool {
        return CFGetTypeID(value as CFTypeRef) == CFBooleanGetTypeID()
    }
    
    static func valueEquals(_ lhs: Any, _ rhs: Any) -> Bool {
        if isBooleanNumber(lhs) != isBooleanNumber(rhs) { return false }
        return (lhs as AnyObject).isEqual(rhs)
    }

    static func snapshot(_ value: Any) -> Any {
        return deepCopy(value)
    }
    
    static func documentsEqual(_ lhs: Any, _ rhs: Any, depth: Int = 0) -> Bool {
        // Past the ceiling, report "changed" — safe in both directions.
        guard depth < maxRecursionDepth else { return false }
        switch (lhs, rhs) {
        case let (l as NSDictionary, r as NSDictionary):
            guard l.count == r.count else { return false }
            for key in l.allKeys {
                guard let lv = l.object(forKey: key), let rv = r.object(forKey: key),
                      documentsEqual(lv, rv, depth: depth + 1) else { return false }
            }
            return true
        case let (l as NSArray, r as NSArray):
            guard l.count == r.count else { return false }
            for i in 0..<l.count where !documentsEqual(l[i], r[i], depth: depth + 1) {
                return false
            }
            return true
        default:
            return valueEquals(lhs, rhs)
        }
    }
    
    private static func deepCopy(_ value: Any, depth: Int = 0) -> Any {
        guard depth < maxRecursionDepth else { return value }
        switch value {
        case let dictionary as NSDictionary:
            let copy = NSMutableDictionary()
            for key in dictionary.allKeys {
                guard let key = key as? NSCopying, let child = dictionary.object(forKey: key) else { continue }
                copy.setObject(deepCopy(child, depth: depth + 1), forKey: key)
            }
            return copy
        case let array as NSArray:
            let copy = NSMutableArray()
            for element in array { copy.add(deepCopy(element, depth: depth + 1)) }
            return copy
        default:
            return value
        }
    }
}
