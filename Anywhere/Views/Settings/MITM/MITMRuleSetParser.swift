//
//  MITMRuleSetParser.swift
//  Anywhere
//
//  Created by NodePassProject on 5/8/26.
//

import Foundation
import JavaScriptCore

/// Import-only parser that turns the text representation of a
/// ``MITMRuleSet`` into a value ``ImportMITMRuleSetView`` can install.
/// There is no serializer; the text comes from a user paste or a
/// downloaded URL and is treated as untrusted — wire-safety validation
/// of header and URL bytes happens later, in ``MITMRewritePolicy`` (for
/// static rules) and ``MITMScriptEngine`` (for script output).
///
/// The text is a flat sequence of header lines and rule lines, in any
/// order. Header lines have the shape `<key> = <value>` and supply the
/// set's metadata. Rule lines are comma-separated fields describing a
/// single rewrite operation.
///
///     name     = My Rule Set
///     hostname = example.com, api.example.org
///     redirect = upstream.example.com:443
///     0, 0, ^/old, /new
///     1, 1, ^/api/, X-Powered-By, Anywhere
///
/// Header keys are matched case-insensitively; the value is trimmed of
/// surrounding whitespace and otherwise kept verbatim. Recognized keys:
///
/// - `name`         — display name for the rule set. The importer
///                    requires a non-empty name.
/// - `hostname`     — comma-separated domain suffixes the set applies to.
///                    Matching is by suffix, so `example.com` also covers
///                    `www.example.com`; wildcards are not supported. When
///                    suffixes overlap, the most specific one wins (see
///                    ``MITMRewritePolicy``).
/// - `redirect`     — transparent upstream: dial `host` or `host:port`
///                    instead of the original destination and rewrite the
///                    request's authority, while the client still sees the
///                    original host's certificate. See
///                    ``MITMRewriteAction/transparent``.
/// - `redirect-302` — synthesize a `302 Found` whose `Location` is
///                    `https://<host>[:<port>]<original-request-target>`
///                    (the port is emitted only when set and not 443).
/// - `reject-200`   — synthesize a `200 OK`. Value is `<kind>` or
///                    `<kind> <content>`, where kind is `text`, `gif`, or
///                    `data`. For `text`, content is the literal UTF-8
///                    body; for `gif`, content is ignored and a 1×1
///                    transparent GIF is emitted; for `data`, content is
///                    base64, decoded when the response is synthesized.
///                    Empty content yields a short non-empty default body.
/// - `content-type` — Content-Type override applied to `reject-200` only;
///                    ignored for the other actions.
///
/// `redirect`, `redirect-302`, and `reject-200` are mutually exclusive;
/// if more than one appears, the last one wins. The latter two synthesize
/// the reply on the inner leg and bypass the rewrite pipeline, so any rule
/// lines in the same set never fire (``MITMRewritePolicy`` logs the
/// combination at load time).
///
/// Unrecognized header keys are ignored. Comment lines start with `#` or
/// `//`. Parsing never fails: a line that is neither a recognized header
/// nor a valid rule is dropped silently, so a partially-valid file still
/// imports what it can.
///
/// Rule line format:
///
///     <phase>, <operation>, <field1> [, <field2> [, <field3> ] ]
///
/// Phase: `0` = request, `1` = response.
///
/// Operations and their trailing fields:
///
/// | ID  | Operation      | Phase        | Fields                |
/// | --- | -------------- | ------------ | --------------------- |
/// | `0` | url-replace    | request only | pattern, replacement  |
/// | `1` | header-add     | both         | pattern, name, value  |
/// | `2` | header-delete  | both         | pattern, name         |
/// | `3` | header-replace | both         | pattern, name, value  |
/// | `4` | script         | both         | pattern, base64       |
/// | `5` | stream-script  | both         | pattern, base64       |
///
/// `url-replace` is always a request-phase rule; its phase column is
/// ignored. Every other operation applies to whichever phase the column
/// names. A rule whose field count does not match the table is dropped.
///
/// Fields are separated by `,`. Whitespace around an unquoted field is
/// trimmed. A field that begins with `"` is read until the matching `"`,
/// with `""` inside a quoted field producing a literal `"` — so a value
/// containing commas or leading/trailing spaces can be wrapped in double
/// quotes.
///
/// Every rule leads with a `pattern`: an `NSRegularExpression` (default
/// Unicode semantics) tested against the request target's path-and-query.
/// The operation only fires when the pattern matches; the set's
/// `hostname` already scopes the host, so the pattern refines by path.
/// Use `.*` to match every request. For `url-replace` the same pattern is
/// also the substitution regex: every match in the request target is
/// replaced by the `replacement` template, which may reference capture
/// groups (`$1`, `$2`, …). A rule whose pattern is empty or fails to
/// compile as a regex is dropped.
///
/// `header-replace` matches the target header by `name`
/// (case-insensitive) and overwrites its value with `value`, ignoring
/// the header's current value; a header that is not present is left
/// alone.
///
/// `script` carries a base64-encoded UTF-8 JavaScript source defining
/// `function process(ctx)`. The runtime invokes it with a mutable
/// message-context object: the script can mutate `ctx.body`
/// (a `Uint8Array`, in place or by assignment), `ctx.url`, `ctx.method`,
/// `ctx.status`, and `ctx.headers` (an array of `[name, value]` pairs);
/// `ctx.phase` is read-only. Scripts are stored base64-encoded so
/// newlines and quoting in the source survive the line-based rule format.
/// See ``MITMScriptEngine`` for the full runtime contract, including the
/// `Anywhere.codec` namespace (`utf8` / `base64` / `base64url` / `hex` /
/// `protobuf`), the `Anywhere.crypto`, `Anywhere.jwt`, `Anywhere.json`,
/// `Anywhere.store`, and `Anywhere.log` namespaces, the `Anywhere.done()`
/// / `Anywhere.exit()` short-circuit directives, and the
/// request-phase-only `Anywhere.respond({status, headers, body})`
/// directive that drops the upstream request and writes a synthesized
/// response straight back to the client.
///
/// A `script` rule's only fields are the `pattern` and the base64:
///
///     1, 4, ^/api/, <base64>
///
/// `stream-script` (op `5`) uses the same field shape as `script` but
/// invokes the script once per HTTP/2 DATA frame or HTTP/1 chunked
/// chunk — the body is never buffered, HTTP-level compression is not
/// decoded, and the head's URL/method/status/headers are not mutable.
/// The script's `process(ctx)` receives an immutable view of the head
/// plus a mutable `ctx.body` (this frame's payload),
/// `ctx.frame = { index, end }` (the 0-based frame index and an `end`
/// flag set on the final frame), and `ctx.state` (a JS object persisted
/// across frames of the same stream). HTTP/1 Content-Length bodies are
/// not streamed — the head has already committed to a byte count that
/// can't change mid-stream.
///
/// Both script kinds are dropped at import when the base64 does not decode
/// to syntactically valid UTF-8 JavaScript; whether `process` is actually
/// defined and callable is checked by ``MITMScriptEngine`` at runtime.
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

    /// Splits a `<key> = <value>` line on its first `=`. The key is
    /// lowercased and matched against ``recognizedHeaders``; an
    /// unrecognized key returns nil so the caller falls through and tries
    /// the line as a rule. The value is trimmed of surrounding whitespace
    /// and otherwise returned verbatim.
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

    /// Parses `host`, `host:port`, `[ipv6]`, or `[ipv6]:port` for the
    /// transparent and 302 redirect modes. Bracketed IPv6 is the
    /// canonical URI form (RFC 3986 §3.2.2); unbracketed strings with
    /// more than one `:` are treated as bare IPv6 hosts with no port,
    /// since splitting on the last colon would otherwise eat the final
    /// hextet (``2001:db8::1`` → ``host=2001:db8:`` + ``port=1``).
    /// Returns nil only when the value is empty after trimming.
    private static func parseAuthority(_ value: String, action: MITMRewriteAction) -> MITMRewriteTarget? {
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }

        // Bracketed IPv6: ``[::1]`` or ``[::1]:443``. The brackets are
        // URI syntax only; the stored host loses them so it matches the
        // form upstream resolvers expect.
        if trimmed.hasPrefix("[") {
            if let closeBracket = trimmed.firstIndex(of: "]") {
                let hostStart = trimmed.index(after: trimmed.startIndex)
                let host = String(trimmed[hostStart..<closeBracket])
                let afterBracket = trimmed[trimmed.index(after: closeBracket)...]
                if afterBracket.isEmpty {
                    return MITMRewriteTarget(action: action, host: host, port: nil)
                }
                if afterBracket.hasPrefix(":"),
                   let port = UInt16(afterBracket.dropFirst()) {
                    return MITMRewriteTarget(action: action, host: host, port: port)
                }
            }
            // Malformed bracketed input — keep as-is rather than guessing.
            return MITMRewriteTarget(action: action, host: trimmed, port: nil)
        }

        // Unbracketed. Exactly one ``:`` means ``host:port``; more than
        // one means an IPv6 literal the user wrote without brackets.
        var colonCount = 0
        for ch in trimmed where ch == ":" { colonCount += 1 }
        if colonCount == 1, let colon = trimmed.lastIndex(of: ":") {
            let hostPart = String(trimmed[..<colon]).trimmingCharacters(in: .whitespaces)
            let portPart = String(trimmed[trimmed.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if !hostPart.isEmpty, let port = UInt16(portPart) {
                return MITMRewriteTarget(action: action, host: hostPart, port: port)
            }
        }
        return MITMRewriteTarget(action: action, host: trimmed, port: nil)
    }

    /// Parses a `reject-200` value of the form `<kind>` or
    /// `<kind> <content>`. Kind is `text`, `gif`, or `data`; the first
    /// space separates it from the content, and everything after that
    /// space is the content, taken verbatim. An unknown or missing kind
    /// falls back to ``MITMRejectBody/Kind/text``. The content is decoded
    /// and interpreted only when the response is synthesized — literal
    /// UTF-8 for `text`, base64 for `data`, ignored for `gif` — so this
    /// stage neither validates nor decodes it. An empty value yields an
    /// empty ``MITMRejectBody`` of kind `text`.
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

        // Every rule leads with a URL pattern (a regex over the
        // request-target's path-and-query) that gates whether the
        // operation fires. For url-replace it doubles as the
        // substitution regex.
        switch opInt {
        case 0:  // url-replace, request-only regardless of phase column
            guard args.count == 2 else { return nil }
            let pattern = args[0]
            guard !pattern.isEmpty, isValidRegex(pattern) else { return nil }
            return MITMRule(phase: .httpRequest, pattern: pattern, operation: .urlReplace(path: args[1]))

        case 1:  // header-add
            guard args.count == 3 else { return nil }
            let pattern = args[0]
            let name = args[1]
            guard !pattern.isEmpty, isValidRegex(pattern), !name.isEmpty else { return nil }
            return MITMRule(phase: phase, pattern: pattern, operation: .headerAdd(name: name, value: args[2]))

        case 2:  // header-delete
            guard args.count == 2 else { return nil }
            let pattern = args[0]
            let name = args[1]
            guard !pattern.isEmpty, isValidRegex(pattern), !name.isEmpty else { return nil }
            return MITMRule(phase: phase, pattern: pattern, operation: .headerDelete(name: name))

        case 3:  // header-replace, by name (the old header-value pattern is gone)
            guard args.count == 3 else { return nil }
            let pattern = args[0]
            let name = args[1]
            guard !pattern.isEmpty, isValidRegex(pattern), !name.isEmpty else { return nil }
            return MITMRule(phase: phase, pattern: pattern, operation: .headerReplace(name: name, value: args[2]))

        case 4:  // script — fields: pattern, base64
            guard args.count == 2 else { return nil }
            let pattern = args[0]
            guard !pattern.isEmpty, isValidRegex(pattern) else { return nil }
            let b64 = args[1]
            guard !b64.isEmpty, isValidScriptBase64(b64) else { return nil }
            return MITMRule(
                phase: phase,
                pattern: pattern,
                operation: .script(scriptBase64: b64)
            )

        case 5:  // stream-script — fields: pattern, base64
            guard args.count == 2 else { return nil }
            let pattern = args[0]
            guard !pattern.isEmpty, isValidRegex(pattern) else { return nil }
            let b64 = args[1]
            guard !b64.isEmpty, isValidScriptBase64(b64) else { return nil }
            return MITMRule(
                phase: phase,
                pattern: pattern,
                operation: .streamScript(scriptBase64: b64)
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
