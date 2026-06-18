//
//  MITMJSONPatch.swift
//  Anywhere
//
//  Created by NodePassProject on 5/31/26.
//

import Foundation

/// Declarative JSON body editing. Fail-closed: any miss yields the body unchanged.
enum MITMJSONPatch {

    // MARK: - Path model

    /// One step of a parsed JSONPath; no wildcards or `..` descent.
    enum PathSegment: Equatable {
        case key(String)
        case index(Int)
    }

    enum LeafMode { case add, replace, delete }

    // MARK: - Compiled operation

    enum CompiledOp {
        case add(path: [PathSegment], value: Any)
        case replace(path: [PathSegment], value: Any)
        case delete(path: [PathSegment])
        case replaceRecursive(key: String, value: Any)
        case deleteRecursive(key: String)
        case removeWhereKeyExists(path: [PathSegment], key: String)
        case removeWhereFieldIn(path: [PathSegment], field: String, values: [Any])
    }

    // MARK: - Compilation

    /// Returns nil only for a malformed path; a non-JSON value compiles to a literal string.
    static func compile(_ operation: MITMJSONOperation) -> CompiledOp? {
        switch operation {
        case .add(let path, let value):
            guard let segments = parseJSONPath(path) else { return nil }
            return .add(path: segments, value: parseValue(value))
        case .replace(let path, let value):
            guard let segments = parseJSONPath(path) else { return nil }
            return .replace(path: segments, value: parseValue(value))
        case .delete(let path):
            guard let segments = parseJSONPath(path) else { return nil }
            return .delete(path: segments)
        case .replaceRecursive(let key, let value):
            return .replaceRecursive(key: key, value: parseValue(value))
        case .deleteRecursive(let key):
            return .deleteRecursive(key: key)
        case .removeWhereKeyExists(let path, let key):
            guard let segments = parseJSONPath(path) else { return nil }
            return .removeWhereKeyExists(path: segments, key: key)
        case .removeWhereFieldIn(let path, let field, let values):
            guard let segments = parseJSONPath(path) else { return nil }
            return .removeWhereFieldIn(path: segments, field: field, values: parseValues(values))
        }
    }

    /// Parses an authored value as JSON; a non-JSON string becomes a literal string. Never nil.
    static func parseValue(_ raw: String) -> Any {
        if let parsed = try? JSONSerialization.jsonObject(
            with: Data(raw.utf8),
            options: [.fragmentsAllowed]
        ) {
            return parsed
        }
        return raw
    }

    /// Normalizes to an array: JSON array → elements, scalar or non-JSON string → one element.
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

    /// Applies every compiled edit in order; fail-closed on non-JSON, no-op edits, or re-serialization failure.
    static func applyAll(_ ops: [CompiledOp], to body: Data) -> Data {
        guard !ops.isEmpty else { return body }
        guard var root = parse(body) else { return body }
        // Return original bytes when nothing changed: re-serializing could reshape 64-bit IDs / high-precision decimals.
        let before = snapshot(root)
        for op in ops {
            apply(op, to: &root)
        }
        guard !documentsEqual(before, root) else { return body }
        guard let out = serialize(root) else { return body }
        return out
    }

    /// Root is `inout` so empty-path add/replace can swap the root wholesale.
    private static func apply(_ op: CompiledOp, to root: inout Any) {
        switch op {
        case .add(let path, let value):
            root = applyAtPath(root, segments: path, mode: .add, value: value)
        case .replace(let path, let value):
            root = applyAtPath(root, segments: path, mode: .replace, value: value)
        case .delete(let path):
            root = applyAtPath(root, segments: path, mode: .delete, value: nil)
        case .replaceRecursive(let key, let value):
            replaceKeyRecursive(root, key: key, value: value)
        case .deleteRecursive(let key):
            deleteKeyRecursive(root, key: key)
        case .removeWhereKeyExists(let path, let key):
            guard let array = resolveNode(root, segments: path) as? NSMutableArray else { return }
            let kept = array.filter { ($0 as? NSDictionary)?.object(forKey: key) == nil }
            array.setArray(kept)
        case .removeWhereFieldIn(let path, let field, let values):
            guard let array = resolveNode(root, segments: path) as? NSMutableArray else { return }
            let kept = array.filter { element in
                guard let object = element as? NSDictionary,
                      let fieldValue = object.object(forKey: field) else { return true }
                return !values.contains { valueEquals($0, fieldValue) }
            }
            array.setArray(kept)
        }
    }

    // MARK: - Parse / serialize

    /// Parses with mutable containers and `.fragmentsAllowed`; nil for empty/malformed input.
    /// NSNumber round-tripping isn't contractual, so only changed documents are re-serialized.
    static func parse(_ data: Data) -> Any? {
        guard !data.isEmpty else { return nil }
        return try? JSONSerialization.jsonObject(with: data, options: [.mutableContainers, .fragmentsAllowed])
    }

    /// Nil for an un-serializable graph. JSONSerialization raises an ObjC NSException (uncatchable
    /// by `try?`) on non-finite NSNumbers or non-string keys, so `isJSONEncodable` guards first.
    static func serialize(_ object: Any) -> Data? {
        guard isJSONEncodable(object) else { return nil }
        return try? JSONSerialization.data(withJSONObject: object, options: [.fragmentsAllowed, .withoutEscapingSlashes])
    }

    /// Verifies a graph can be serialized without raising: finite NSNumbers, string keys only.
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

    /// Splits a JSONPath into segments; leading `$` optional, brackets take quoted/bare
    /// keys or numeric indices. Nil for malformed input; empty result means the document root.
    static func parseJSONPath(_ raw: String) -> [PathSegment]? {
        var segments: [PathSegment] = []
        var chars = Substring(raw)
        if chars.first == "$" { chars = chars.dropFirst() }
        while let c = chars.first {
            if c == "." {
                chars = chars.dropFirst()
                var name = ""
                while let d = chars.first, d != ".", d != "[" {
                    name.append(d)
                    chars = chars.dropFirst()
                }
                if name.isEmpty { return nil }
                segments.append(.key(name))
            } else if c == "[" {
                chars = chars.dropFirst()
                var inner = ""
                // Scan past a quoted key first: it may contain `]` (`["a]b"]`).
                if let quote = chars.first, quote == "\"" || quote == "'" {
                    inner.append(quote)
                    chars = chars.dropFirst()
                    while let d = chars.first, d != quote {
                        inner.append(d)
                        chars = chars.dropFirst()
                    }
                    guard chars.first == quote else { return nil }
                    inner.append(quote)
                    chars = chars.dropFirst()
                }
                while let d = chars.first, d != "]" {
                    inner.append(d)
                    chars = chars.dropFirst()
                }
                guard chars.first == "]" else { return nil }
                chars = chars.dropFirst()
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
                while let d = chars.first, d != ".", d != "[" {
                    name.append(d)
                    chars = chars.dropFirst()
                }
                if name.isEmpty { return nil }
                segments.append(.key(name))
            }
        }
        return segments
    }

    /// Descends one segment; nil on type mismatch or out-of-bounds. Negative indices fail closed, not "last element".
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

    /// Resolves a full path to its node, or nil. Empty segments = document root.
    static func resolveNode(_ root: Any, segments: [PathSegment]) -> Any? {
        var node: Any? = root
        for segment in segments {
            node = childNode(node, segment)
        }
        return node
    }

    /// Applies add/replace/delete at the path leaf; every miss is a no-op. Inserted values are
    /// deep-copied — the shared CompiledOp payload must never be mutated through a document.
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

    /// Depth ceiling for recursive walkers. Exceeds JSONSerialization's parse-depth limit (~512)
    /// so deep sub-trees aren't silently skipped; 600 stays within NE stack bounds.
    private static let maxRecursionDepth = 600

    /// Overwrites every existing `key` member at any depth (replace, not insert);
    /// children are visited first so the replacement value is never descended into.
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

    /// Removes every `key` member at any depth.
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

    /// True for a JSON boolean (CFBoolean-backed); NSNumber's `isEqual` equates `true`/`1`, which JSON does not.
    private static func isBooleanNumber(_ value: Any) -> Bool {
        return CFGetTypeID(value as CFTypeRef) == CFBooleanGetTypeID()
    }

    /// JSON-value equality: `isEqual` (equates `1`/`1.0`) with boolean-vs-number mismatches rejected first.
    static func valueEquals(_ lhs: Any, _ rhs: Any) -> Bool {
        if isBooleanNumber(lhs) != isBooleanNumber(rhs) { return false }
        return (lhs as AnyObject).isEqual(rhs)
    }

    static func snapshot(_ value: Any) -> Any {
        return deepCopy(value)
    }

    /// Structural equality via `valueEquals` at the leaves so a `true`↔`1` edit isn't misclassified as a no-op.
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

    /// Deep copy sharing no mutable node with the source; copies stay mutable for later edits.
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
