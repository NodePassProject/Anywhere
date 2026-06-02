//
//  MITMBodyReplace.swift
//  Anywhere
//
//  Created by NodePassProject on 5/31/26.
//

import Foundation

/// Native regex find-and-replace over a text message body — the engine
/// behind ``MITMOperation/bodyReplace`` (import operation id `4`): a compiled
/// ``Regex`` matched anywhere in the body, with each match swapped for the
/// **literal** replacement string (no `$1` capture expansion — the
/// substitution goes through `String.replacing(_:with:)`).
///
/// **Bytes in, bytes out.** ``applyAll`` decodes the body as UTF-8 once,
/// applies every compiled edit in rule order against the running string, and
/// re-encodes once. The contract is **total / fail-closed**, matching
/// ``MITMJSONPatch``: a body that isn't valid UTF-8 yields the body
/// **unchanged**, and a search that matches nothing is simply a no-op — a
/// rewrite rule routinely fires on a response whose bytes it doesn't fully
/// control, and corrupting the wire there would be worse than doing nothing.
enum MITMBodyReplace {

    /// A ``MITMOperation/bodyReplace`` with its ``search`` pre-compiled to a
    /// ``Regex`` at rule-load time, so the per-message hot path neither
    /// re-parses nor re-compiles the pattern. ``replacement`` is the literal
    /// string each match is swapped for.
    struct CompiledOp {
        let search: Regex<AnyRegexOutput>
        let replacement: String
    }

    /// Compiles a model operation, pre-parsing its ``search`` regex. Returns
    /// nil only when the pattern won't compile (the rule is then dropped with
    /// a logged diagnostic by the caller); the replacement is never validated
    /// — it carries no wire-safety constraint the way a header value or
    /// request target does, since the result is a body whose length is
    /// recomputed downstream.
    static func compile(search: String, replacement: String) -> CompiledOp? {
        guard let regex = try? Regex(search) else { return nil }
        return CompiledOp(search: regex, replacement: replacement)
    }

    /// Applies every compiled edit, in order, to ``body``. Decodes UTF-8
    /// once, replaces every match of each op against the running string (so
    /// successive edits compose), and re-encodes UTF-8. Returns the body
    /// **unchanged** when the list is empty or the body isn't valid UTF-8.
    static func applyAll(_ ops: [CompiledOp], to body: Data) -> Data {
        guard !ops.isEmpty else { return body }
        guard var text = String(data: body, encoding: .utf8) else { return body }
        for op in ops {
            text = text.replacing(op.search, with: op.replacement)
        }
        return Data(text.utf8)
    }
}
