//
//  MITMJSONPatch.swift
//  Anywhere
//
//  Created by NodePassProject on 5/31/26.
//

import Foundation

/// Native, declarative JSON body editing — the engine behind
/// ``MITMOperation/bodyJSON`` (import operation id `5`). It is the
/// rule-configured analog of the ``Anywhere.json`` script API: the same
/// edit catalog and the same total / fail-closed contract, expressed as
/// compiled native code instead of JavaScript so a body rewrite needs no
/// `JSContext`.
///
/// The path-walking core (``parseJSONPath``, ``applyAtPath``,
/// ``replaceKeyRecursive`` …) is the single source of truth for JSON edit
/// semantics: ``MITMScriptEngine``'s `Anywhere.json` blocks delegate to it
/// too, so the native operation and the scripted API can never drift.
///
/// **Bytes in, bytes out.** ``applyAll`` parses the body once, applies
/// every compiled edit in order against one mutable document, and
/// re-serializes once (compact, slashes unescaped — it's going on the
/// wire). A body that isn't JSON, a path that doesn't resolve, a type
/// mismatch, or a value that can't be re-serialized all yield the body
/// **unchanged**; a rewrite rule routinely fires on a response whose shape
/// it doesn't fully control, and a hard failure there would be worse than
/// a no-op.
enum MITMJSONPatch {

    // MARK: - Path model

    /// One step of a parsed JSONPath: an object member (``key``) or an
    /// array element (``index``). No wildcards or `..` descent — recursive
    /// matching is ``replaceRecursive`` / ``deleteRecursive``, which take a
    /// bare key name rather than a path.
    enum PathSegment: Equatable {
        case key(String)
        case index(Int)
    }

    /// What ``applyAtPath`` does to the addressed leaf.
    enum LeafMode { case add, replace, delete }

    // MARK: - Compiled operation

    /// A ``MITMJSONOperation`` with its path pre-parsed to ``PathSegment``s
    /// and its JSON value pre-parsed to a Foundation object, done once at
    /// rule-load time so the per-message hot path neither re-parses the
    /// path string nor re-decodes the value literal.
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

    /// Compiles a model operation, pre-parsing its path and value. Returns
    /// nil only when the path is malformed (the rule is then dropped with a
    /// logged diagnostic by the caller); values never fail — an authored
    /// string that isn't valid JSON is taken as a literal JSON string (see
    /// ``parseValue``), so `value = Anywhere` compiles to the string
    /// `"Anywhere"`.
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

    /// Turns an authored value string into its Foundation JSON form. Tries
    /// to parse it as a JSON fragment first (`true`, `42`, `"text"`,
    /// `{"a":1}`, `[1,2]`, `null`); when that fails, the raw string is the
    /// value verbatim, so the everyday `value = Anywhere` yields the string
    /// `"Anywhere"` without the author having to quote it. Never returns
    /// nil — an empty string yields the empty JSON string `""`.
    static func parseValue(_ raw: String) -> Any {
        if let parsed = try? JSONSerialization.jsonObject(
            with: Data(raw.utf8),
            options: [.fragmentsAllowed]
        ) {
            return parsed
        }
        return raw
    }

    /// Normalizes the `values` argument of ``removeWhereFieldIn`` into a
    /// Swift array: a JSON array becomes its elements, a lone JSON scalar
    /// becomes a one-element array, and a string that isn't JSON becomes a
    /// one-element array holding that literal string.
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

    /// Applies every compiled edit, in order, to ``body``. Parses once,
    /// mutates one shared document, serializes once. Returns the body
    /// **unchanged** when the list is empty, the body isn't JSON, or the
    /// edited document can't be re-serialized — matching ``Anywhere.json``'s
    /// total contract so a rule that fires on an unexpected body shape
    /// degrades to a no-op rather than corrupting the wire.
    static func applyAll(_ ops: [CompiledOp], to body: Data) -> Data {
        guard !ops.isEmpty else { return body }
        guard var root = parse(body) else { return body }
        for op in ops {
            apply(op, to: &root)
        }
        guard let out = serialize(root) else { return body }
        return out
    }

    /// Applies a single compiled edit to a parsed, mutable document. The
    /// root is `inout` so an op can edit a container in place (the common
    /// case) or swap the root wholesale (an empty-path add/replace).
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

    /// `JSON.parse` via Foundation, with mutable containers so the ops can
    /// edit nodes in place and `.fragmentsAllowed` so a top-level scalar
    /// body (`42`, `"x"`, `true`) still parses. Returns nil for empty or
    /// malformed input.
    ///
    /// KNOWN LIMITATION: ``JSONSerialization`` decodes every JSON number into
    /// an ``NSNumber``, so integers beyond 2^53 / full Int64 range and
    /// high-precision decimals are not preserved exactly on re-serialize — a
    /// 64-bit ID like `7203685625435718144` can come back altered. Because
    /// ``applyAll`` re-serializes the whole document, this can reshape numbers
    /// even in parts of the body no op touched. Exact round-tripping would
    /// need a number-lexeme-preserving JSON parser (a larger change). Bodies
    /// that match no rule never reach here, so unmatched traffic is unaffected.
    static func parse(_ data: Data) -> Any? {
        guard !data.isEmpty else { return nil }
        return try? JSONSerialization.jsonObject(with: data, options: [.mutableContainers, .fragmentsAllowed])
    }

    /// `JSON.stringify` via Foundation. Compact, slashes left unescaped to
    /// match how servers actually emit URLs in JSON, and
    /// `.fragmentsAllowed` to round-trip a scalar root. Returns nil when the
    /// graph can't be represented as JSON (a NaN/∞ `NSNumber`, a non-string
    /// dictionary key), which the caller turns into a body-unchanged
    /// pass-through.
    static func serialize(_ object: Any) -> Data? {
        return try? JSONSerialization.data(withJSONObject: object, options: [.fragmentsAllowed, .withoutEscapingSlashes])
    }

    // MARK: - JSONPath

    /// Splits a JSONPath into segments. Tolerant by design: a leading `$`
    /// is optional, brackets accept a bare or quoted key or a numeric
    /// index, and a path written without the `$.` prefix (`"data.items"`)
    /// still parses. Returns nil only for genuinely malformed input — an
    /// empty dotted segment (`"a..b"`, a trailing `"."`) or an empty `"[]"`
    /// — so the caller can warn instead of silently addressing the wrong
    /// node. An empty result (`"$"` or `""`) means "the document root".
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
                } else if let index = Int(token) {
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

    /// Descends one segment. Object keys index a dictionary; numeric
    /// segments index an array (bounds-checked). Any other pairing — a key
    /// into an array, an index into an object, a step off the end, a step
    /// into a scalar — returns nil, which unwinds the whole walk to a
    /// no-op.
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

    /// Resolves a full path to its node (or nil). Empty segments means the
    /// root. Used by the `removeWhere…` ops to find the target array.
    static func resolveNode(_ root: Any, segments: [PathSegment]) -> Any? {
        var node: Any? = root
        for segment in segments {
            node = childNode(node, segment)
        }
        return node
    }

    /// Applies add/replace/delete at the leaf of ``segments``. Walks to the
    /// leaf's parent container, then acts per ``mode``. Returns the root —
    /// usually the same object mutated in place, except an empty-path
    /// add/replace which swaps the root for ``value``. Every miss (absent
    /// parent, wrong container type, out-of-range index) is a no-op.
    ///
    /// Inserted values are deep-copied: the same ``value`` may be a
    /// long-lived ``CompiledOp`` payload reused across every intercepted
    /// message, so handing the document a private copy keeps a later edit
    /// (or a later message) from mutating the shared compiled value.
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

    /// Depth ceiling for the recursive whole-tree walkers below. JSON from an
    /// untrusted upstream can be nested deeply (within ``JSONSerialization``'s
    /// own parse limit); recursing that far would overflow the Network
    /// Extension's small stack and crash it. Past this depth the walkers stop
    /// descending — a graceful no-op on the deep sub-tree, never a crash.
    /// Real-world JSON nests far shallower.
    private static let maxRecursionDepth = 256

    /// Overwrites every ``key`` member at any depth with ``value``.
    /// Children are visited before the key is set so the replacement is
    /// never itself descended into; the key is only overwritten where it
    /// already exists (recursive replace, not recursive insert). Each site
    /// receives its own deep copy (see ``applyAtPath``).
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

    /// Removes every ``key`` member at any depth, then recurses into what
    /// remains.
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

    /// JSON-value equality for the `removeWhere…` predicates. Both sides
    /// are Foundation JSON leaves (`NSNumber` / `NSString` / `NSNull`), so
    /// `isEqual` is exactly right — and it treats `1` and `1.0` as equal,
    /// which is what a rule comparing against a numeric literal expects.
    static func valueEquals(_ lhs: Any, _ rhs: Any) -> Bool {
        return (lhs as AnyObject).isEqual(rhs)
    }

    /// Recursively copies JSON containers so an inserted value shares no
    /// mutable node with the document it came from. Scalars (`NSString` /
    /// `NSNumber` / `NSNull`) are immutable and returned as-is; only
    /// dictionaries and arrays are duplicated, into their mutable forms so
    /// subsequent edits along the same path still work.
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
