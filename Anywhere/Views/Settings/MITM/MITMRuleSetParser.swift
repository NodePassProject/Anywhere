//
//  MITMRuleSetParser.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/8/26.
//

import Foundation
import JavaScriptCore

/// Text-based importer for ``MITMRuleSet``s.
///
/// The text is a flat sequence of header lines and rule lines, in any
/// order. Header lines have the shape `<key> = <value>` and supply the
/// set's metadata. Rule lines use the same CSV format the editor's
/// previous "import rules" feature used.
///
///     name     = My Rule Set
///     hostname = example.com, *.api.example.com
///     redirect = upstream.example.com:443
///     0, 0, ^https://example\.com/old, https://example.com/new
///     1, 1, X-Powered-By, Anywhere
///
/// Recognized keys:
///
/// - `name`         — display name for the rule set
/// - `hostname`     — comma-separated list of domain suffixes
/// - `redirect`     — transparent rewrite target: `host` or `host:port`
/// - `redirect-302` — synthesize a 302 response with
///                    `Location: https://<host>[:<port>]<original-path>`
/// - `reject-200`   — synthesize a 200 response. Value is `<kind>` or
///                    `<kind> <content>`. Kind is `text`, `gif`, or `data`.
///                    For `text`, content is the literal UTF-8 body. For
///                    `gif`, content is ignored (1×1 transparent GIF).
///                    For `data`, content is base64 (decoded at apply time).
/// - `content-type` — optional Content-Type override for `reject-200`.
///
/// `redirect`, `redirect-302`, and `reject-200` are mutually exclusive;
/// the last one to appear wins.
///
/// Unrecognized header keys are ignored. Comment lines start with `#`
/// or `//`. Lines that fail to parse as either a header or a rule are
/// dropped silently so a partially-valid file still imports what it can.
///
/// Rule line format:
///
///     <phase>, <operation>, <field1> [, <field2> [, <field3> ] ]
///
/// Phase: `0` = request, `1` = response.
///
/// Operations and their trailing fields:
///
/// | ID | Operation       | Phase           | Fields                |
/// | -- | --------------- | --------------- | --------------------- |
/// | `0` | url-replace    | request only    | pattern, replacement  |
/// | `1` | header-add     | both            | name, value           |
/// | `2` | header-delete  | both            | name                  |
/// | `3` | header-replace | both            | pattern, name, value  |
/// | `4` | script         | both            | [types,] base64       |
/// | `5` | stream-script  | both            | [types,] base64       |
///
/// Fields are separated by `,`. Whitespace around unquoted fields is
/// trimmed. A field that begins with `"` is read until the matching `"`,
/// with `""` inside a quoted field producing a literal `"` — so values
/// containing commas can be wrapped in double quotes. Patterns for
/// `url-replace` and `header-replace` are NSRegularExpression with the
/// usual Unicode semantics.
///
/// `script` carries a base64-encoded UTF-8 JavaScript source defining
/// `function process(ctx)`. The runtime invokes it with a mutable
/// message-context object: the script can mutate `ctx.body`
/// (`Uint8Array`, in-place or by assignment), `ctx.url`, `ctx.method`,
/// `ctx.status`, and `ctx.headers` (an array of `[name, value]`
/// pairs). Scripts are stored base64-encoded so newlines and quoting
/// in the source survive the line-based rule format. See
/// ``MITMScriptEngine`` for the full runtime contract, including the
/// `Anywhere.utf8 / base64 / hex / store` helper globals, the
/// `Anywhere.done() / Anywhere.exit()` short-circuit hooks, and the
/// request-phase-only `Anywhere.respond({status, headers, body})`
/// hook that drops the upstream request and writes a synthesized
/// response straight back to the client.
///
/// `script` lines optionally lead the base64 with a comma-separated
/// list of exact `Content-Type` primary values that the script
/// applies to. Wrap the field in double quotes so the inner commas
/// are not interpreted as CSV separators:
///
///     1, 4, "text/html, application/json", <base64>
///
/// Matching is case-insensitive and ignores parameters (everything
/// from `;` onward). When the types field is omitted (single trailing
/// argument), the runtime falls back to the default textual-MIME
/// allowlist in ``MITMBodyCodec/isRewritableType``. An empty quoted
/// types field disables the rule entirely (no Content-Type matches).
///
/// `stream-script` (op `5`) uses the same field shape as `script` but
/// invokes the script once per HTTP/2 DATA frame or HTTP/1 chunked
/// chunk — the body is never buffered, HTTP-level compression is not
/// decoded, and the head's URL/method/status/headers are not
/// mutable. The script's `process(ctx)` receives an immutable view of
/// the head plus a mutable `ctx.body` (this frame's payload),
/// `ctx.frame = { index, end }`, and `ctx.state` (a JS object
/// persisted across frames of the same stream). HTTP/1 Content-Length
/// bodies are skipped — the head has already committed to a byte
/// count we can't change mid-stream.
enum MITMRuleSetParser {
    static func parse(_ text: String) -> MITMRuleSet {
        var name = ""
        var suffixes: [String] = []
        var target: MITMRewriteTarget?
        var contentTypeOverride: String?
        var rules: [MITMRule] = []

        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }
            if line.hasPrefix("#") || line.hasPrefix("//") { continue }

            if let header = parseHeader(line) {
                switch header.key {
                case "name":
                    name = header.value
                case "hostname":
                    suffixes = header.value
                        .split(separator: ",")
                        .map { $0.trimmingCharacters(in: .whitespaces) }
                        .filter { !$0.isEmpty }
                case "redirect":
                    target = parseAuthority(header.value, action: .transparent)
                case "redirect-302":
                    target = parseAuthority(header.value, action: .redirect302)
                case "reject-200":
                    target = parseReject200(header.value)
                case "content-type":
                    contentTypeOverride = header.value
                default:
                    break
                }
            } else if let rule = parseRuleLine(line) {
                rules.append(rule)
            }
        }

        if let override = contentTypeOverride,
           !override.isEmpty,
           target?.action == .reject200,
           var body = target?.rejectBody {
            body.contentType = override
            target?.rejectBody = body
        }

        return MITMRuleSet(
            name: name,
            domainSuffixes: suffixes,
            rewriteTarget: target,
            rules: rules
        )
    }

    private static let recognizedHeaders: Set<String> = [
        "name",
        "hostname",
        "redirect",
        "redirect-302",
        "reject-200",
        "content-type",
    ]

    private static func parseHeader(_ line: String) -> (key: String, value: String)? {
        guard let equal = line.firstIndex(of: "=") else { return nil }
        let key = line[line.startIndex..<equal]
            .trimmingCharacters(in: .whitespaces)
            .lowercased()
        guard recognizedHeaders.contains(key) else { return nil }
        let value = String(line[line.index(after: equal)...])
            .trimmingCharacters(in: .whitespaces)
        return (key, value)
    }

    /// Parses `host` or `host:port` for the transparent and 302 redirect
    /// modes. Returns nil only when the value is empty after trimming.
    private static func parseAuthority(_ value: String, action: MITMRewriteAction) -> MITMRewriteTarget? {
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        if let colon = trimmed.lastIndex(of: ":") {
            let hostPart = String(trimmed[..<colon]).trimmingCharacters(in: .whitespaces)
            let portPart = String(trimmed[trimmed.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if !hostPart.isEmpty, let port = UInt16(portPart) {
                return MITMRewriteTarget(action: action, host: hostPart, port: port)
            }
        }
        return MITMRewriteTarget(action: action, host: trimmed, port: nil)
    }

    /// Parses `reject-200` value. Format: `<kind>` or `<kind> <content>`,
    /// where kind is `text`, `gif`, or `data`. The first whitespace run
    /// separates kind from content; everything after is the content
    /// (preserved verbatim, except a single trailing CR is removed). An
    /// unknown kind falls back to ``MITMRejectBody/Kind/text``.
    private static func parseReject200(_ value: String) -> MITMRewriteTarget {
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else {
            return MITMRewriteTarget(action: .reject200, rejectBody: MITMRejectBody())
        }
        let parts = trimmed.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
        let rawKind = parts.first.map(String.init)?.lowercased() ?? "text"
        let content = parts.count > 1 ? String(parts[1]) : ""
        let kind: MITMRejectBody.Kind
        switch rawKind {
        case "gif": kind = .gif
        case "data": kind = .data
        default: kind = .text
        }
        return MITMRewriteTarget(
            action: .reject200,
            rejectBody: MITMRejectBody(kind: kind, contents: content)
        )
    }

    // MARK: - Rule line parsing

    private static func parseRuleLine(_ trimmed: String) -> MITMRule? {
        let fields = splitCSV(trimmed)
        guard fields.count >= 2 else { return nil }
        guard let phaseInt = Int(fields[0]),
              let phase = phase(from: phaseInt) else { return nil }
        guard let opInt = Int(fields[1]) else { return nil }
        let args = Array(fields.dropFirst(2))

        switch opInt {
        case 0:  // url-replace, request-only regardless of phase column
            guard args.count == 2 else { return nil }
            let pattern = args[0]
            guard !pattern.isEmpty, isValidRegex(pattern) else { return nil }
            return MITMRule(phase: .httpRequest, operation: .urlReplace(pattern: pattern, path: args[1]))

        case 1:  // header-add
            guard args.count == 2 else { return nil }
            let name = args[0]
            guard !name.isEmpty else { return nil }
            return MITMRule(phase: phase, operation: .headerAdd(name: name, value: args[1]))

        case 2:  // header-delete
            guard args.count == 1 else { return nil }
            let name = args[0]
            guard !name.isEmpty else { return nil }
            return MITMRule(phase: phase, operation: .headerDelete(name: name))

        case 3:  // header-replace
            guard args.count == 3 else { return nil }
            let pattern = args[0]
            let name = args[1]
            guard !pattern.isEmpty, !name.isEmpty, isValidRegex(pattern) else { return nil }
            return MITMRule(phase: phase, operation: .headerReplace(pattern: pattern, name: name, value: args[2]))

        case 4:  // script
            guard args.count == 1 || args.count == 2 else { return nil }
            // 1 arg: base64 only (default allowlist).
            // 2 args: types, base64.
            let b64 = args.last ?? ""
            guard !b64.isEmpty, isValidScriptBase64(b64) else { return nil }
            let contentTypes: [String]? = args.count == 2 ? parseContentTypes(args[0]) : nil
            return MITMRule(
                phase: phase,
                operation: .script(scriptBase64: b64, contentTypes: contentTypes)
            )

        case 5:  // stream-script
            guard args.count == 1 || args.count == 2 else { return nil }
            let b64 = args.last ?? ""
            guard !b64.isEmpty, isValidScriptBase64(b64) else { return nil }
            let contentTypes: [String]? = args.count == 2 ? parseContentTypes(args[0]) : nil
            return MITMRule(
                phase: phase,
                operation: .streamScript(scriptBase64: b64, contentTypes: contentTypes)
            )

        default:
            return nil
        }
    }

    private static func phase(from raw: Int) -> MITMPhase? {
        switch raw {
        case 0: return .httpRequest
        case 1: return .httpResponse
        default: return nil
        }
    }

    /// CSV-style split. A field that begins with `"` is read until the
    /// matching unescaped `"`, with `""` inside a quoted field producing a
    /// literal `"`. Whitespace around unquoted fields is trimmed; whitespace
    /// inside a quoted field is preserved.
    private static func splitCSV(_ input: String) -> [String] {
        var fields: [String] = []
        var current = ""
        var i = input.startIndex
        while true {
            while i < input.endIndex, input[i] == " " || input[i] == "\t" {
                i = input.index(after: i)
            }
            if i < input.endIndex, input[i] == "\"" {
                i = input.index(after: i)
                while i < input.endIndex {
                    let ch = input[i]
                    if ch == "\"" {
                        let next = input.index(after: i)
                        if next < input.endIndex, input[next] == "\"" {
                            current.append("\"")
                            i = input.index(after: next)
                        } else {
                            i = next
                            break
                        }
                    } else {
                        current.append(ch)
                        i = input.index(after: i)
                    }
                }
                while i < input.endIndex, input[i] == " " || input[i] == "\t" {
                    i = input.index(after: i)
                }
            } else {
                while i < input.endIndex, input[i] != "," {
                    current.append(input[i])
                    i = input.index(after: i)
                }
                current = current.trimmingCharacters(in: .whitespaces)
            }
            fields.append(current)
            current = ""
            if i >= input.endIndex { break }
            i = input.index(after: i)
        }
        return fields
    }

    private static func isValidRegex(_ pattern: String) -> Bool {
        (try? NSRegularExpression(pattern: pattern, options: [])) != nil
    }

    /// Parses the optional `script` Content-Type list. Splits on
    /// `,`, lowercases, trims, and drops empties. An all-whitespace
    /// field still produces a non-nil empty array so the rule honors
    /// the user's "match nothing" intent rather than silently reverting
    /// to the default allowlist.
    private static func parseContentTypes(_ field: String) -> [String] {
        field
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { !$0.isEmpty }
    }

    /// Validates a `script` field: base64 → UTF-8 → JavaScript parse.
    /// Wraps the source in the same IIFE the runtime uses so a rule
    /// that imports cleanly here is one the runtime can compile.
    /// Parse-only — does not evaluate, so user code with side effects
    /// is not run at import time.
    private static func isValidScriptBase64(_ b64: String) -> Bool {
        guard let raw = Data(base64Encoded: b64),
              let source = String(data: raw, encoding: .utf8)
        else { return false }
        let wrapped = "(function(){\n\(source)\nreturn process;\n})()"
        guard let context = JSContext() else { return false }
        return wrapped.withCString { cString in
            guard let scriptRef = JSStringCreateWithUTF8CString(cString) else {
                return false
            }
            defer { JSStringRelease(scriptRef) }
            return JSCheckScriptSyntax(
                context.jsGlobalContextRef,
                scriptRef,
                nil,
                0,
                nil
            )
        }
    }
}
