//
//  MITMScriptTransform.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/9/26.
//

import Foundation
import JavaScriptCore

/// Applies the script subset of a compiled rule list to a buffered,
/// decompressed HTTP message. The HTTP/1.1 and HTTP/2 rewriters share
/// this entry point so the rule-application loop lives in one place.
///
/// **Single-rule semantics.** At most one ``.script`` and at most one
/// ``.streamScript`` may fire on a given message. When multiple rules
/// of the same kind match the in-flight Content-Type, the last one in
/// rule order wins — later definitions overwrite earlier ones. This
/// avoids state-collision hazards a chain would create: the JS
/// engine's ``Anywhere.store`` keys are scoped to the rule set (not
/// the rule), and the per-stream ``FrameCursor.state`` slot for
/// ``streamScript`` is single-valued, so chaining two scripts on the
/// same content type would have them stomping each other's persistent
/// state on every frame.
///
/// Each script rule carries its own ``BodyContentTypeFilter``; the
/// message's `Content-Type` is checked at the entry point so rules
/// whose filter doesn't match the in-flight payload are skipped
/// without entering the JS engine.
enum MITMScriptTransform {

    /// Result of running a buffered ``.script`` rule on a message.
    /// Distinguishes the normal rewrite path (``message``) from a
    /// request-phase `Anywhere.respond(...)` short-circuit
    /// (``synthesizedResponse``). Streaming-script rules don't produce
    /// this outcome — see ``applyFrame``.
    enum Outcome {
        /// Use the (possibly mutated) message as the rewrite result;
        /// emit to the upstream leg as usual.
        case message(MITMScriptEngine.Message)
        /// Request-phase script called `Anywhere.respond(...)`. Drop
        /// the request without forwarding upstream and synthesize this
        /// response back to the client.
        case synthesizedResponse(MITMScriptEngine.SynthesizedResponse)
    }

    /// True when at least one ``.script`` rule in ``rules`` would fire
    /// for a message with the given ``contentType``. Rewriters consult
    /// this at head-completion time to decide whether to defer head
    /// emission (and, for bodied messages, buffer the body).
    ///
    /// Streaming rules win when both apply (see ``hasStreamScriptRule``)
    /// so callers should check the streaming variant first and only
    /// fall through to the buffered path when no stream rule matches.
    static func hasScriptRule(in rules: [CompiledMITMRule], contentType: String?) -> Bool {
        rules.contains { rule in
            switch rule.operation {
            case .script(_, _, let filter):
                return filter.matches(contentType)
            case .streamScript, .urlReplace, .headerAdd, .headerDelete, .headerReplace:
                return false
            }
        }
    }

    /// True when at least one ``.streamScript`` rule in ``rules``
    /// would fire for a message with the given ``contentType``. Both
    /// rewriters consult this at head-completion time to decide
    /// whether to enter per-frame streaming mode (emit head
    /// immediately, no body buffering, no HTTP-level decompression).
    static func hasStreamScriptRule(in rules: [CompiledMITMRule], contentType: String?) -> Bool {
        rules.contains { rule in
            switch rule.operation {
            case .streamScript(_, _, let filter):
                return filter.matches(contentType)
            case .script, .urlReplace, .headerAdd, .headerDelete, .headerReplace:
                return false
            }
        }
    }

    /// Runs the single ``.script`` rule whose filter matches the
    /// message's `Content-Type`, picking the last matching rule when
    /// several would qualify (overwrite semantics; see the type-level
    /// note). Header-only rules are no-ops here (they ran at head
    /// time). Returns ``Outcome/message`` carrying the input unchanged
    /// when no rule matches or ``engineProvider`` is nil; returns
    /// ``Outcome/synthesizedResponse`` when a request-phase script
    /// called `Anywhere.respond(...)`.
    static func apply(
        _ message: MITMScriptEngine.Message,
        rules: [CompiledMITMRule],
        engineProvider: MITMScriptEngine.Provider? = nil
    ) -> Outcome {
        let contentType = firstHeaderValue(message.headers, name: "content-type")
        guard let match = lastMatchingScriptSource(in: rules, contentType: contentType),
              let engineProvider
        else { return .message(message) }
        let outcome = engineProvider.get().apply(
            message,
            source: match.source,
            sourceKey: match.sourceKey
        )
        switch outcome {
        case .modified(let updated):  return .message(updated)
        case .done(let updated):      return .message(updated)
        case .exit:                   return .message(message)
        case .respond(let response):  return .synthesizedResponse(response)
        }
    }

    /// Per-stream cursor for ``applyFrame``: the script's persistent
    /// state object and a sticky "skip remainder" flag set when a
    /// previous frame returned ``FrameOutcome/done`` or ``exit``. The
    /// caller owns one of these per active stream and threads it
    /// through each frame.
    ///
    /// With single-rule semantics the ``state`` slot has unambiguous
    /// ownership: it belongs to the one ``.streamScript`` rule that
    /// matched the stream's Content-Type at head time. Earlier
    /// matching rules don't run on this stream and so can't trample
    /// the slot.
    final class FrameCursor {
        var state: JSValue?
        /// True once a script directive said "we're done with this
        /// stream" — subsequent frames bypass the script entirely.
        var bypass: Bool = false
        init() {}
    }

    /// Result of running the matching streaming-script rule on one
    /// frame.
    struct StreamFrameResult {
        let body: Data
        let bypass: Bool
    }

    /// Runs the single matching ``.streamScript`` rule against one
    /// frame, picking the last matching rule when several qualify
    /// (overwrite semantics). ``Anywhere.done`` short-circuits and
    /// sets ``cursor.bypass`` so the caller stops feeding subsequent
    /// frames to the script. ``Anywhere.exit`` reverts to the input
    /// frame and also sets ``bypass``.
    static func applyFrame(
        _ frame: Data,
        rules: [CompiledMITMRule],
        contentType: String?,
        frameContext: MITMScriptEngine.FrameContext,
        cursor: FrameCursor,
        engineProvider: MITMScriptEngine.Provider?
    ) -> StreamFrameResult {
        guard let match = lastMatchingStreamScriptSource(in: rules, contentType: contentType),
              let engineProvider
        else { return StreamFrameResult(body: frame, bypass: false) }
        let outcome = engineProvider.get().applyFrame(
            frame,
            source: match.source,
            sourceKey: match.sourceKey,
            frameContext: frameContext,
            state: cursor.state
        )
        switch outcome {
        case .modified(let body, let state):
            cursor.state = state
            return StreamFrameResult(body: body, bypass: false)
        case .done(let body):
            cursor.bypass = true
            return StreamFrameResult(body: body, bypass: true)
        case .exit:
            cursor.bypass = true
            return StreamFrameResult(body: frame, bypass: true)
        }
    }

    // MARK: - Last-match selection

    /// Match for a script lookup: the source the engine compiles plus
    /// the precomputed cache key the engine uses to dedup compilation
    /// across calls.
    private struct ScriptMatch {
        let source: String
        let sourceKey: Int
    }

    /// Returns the source of the last ``.script`` rule whose filter
    /// matches ``contentType``, or nil when none match. Walks rules
    /// back-to-front so the first hit is the winner.
    private static func lastMatchingScriptSource(
        in rules: [CompiledMITMRule],
        contentType: String?
    ) -> ScriptMatch? {
        for rule in rules.reversed() {
            if case .script(let source, let sourceKey, let filter) = rule.operation,
               filter.matches(contentType) {
                return ScriptMatch(source: source, sourceKey: sourceKey)
            }
        }
        return nil
    }

    /// Returns the source of the last ``.streamScript`` rule whose
    /// filter matches ``contentType``, or nil when none match.
    private static func lastMatchingStreamScriptSource(
        in rules: [CompiledMITMRule],
        contentType: String?
    ) -> ScriptMatch? {
        for rule in rules.reversed() {
            if case .streamScript(let source, let sourceKey, let filter) = rule.operation,
               filter.matches(contentType) {
                return ScriptMatch(source: source, sourceKey: sourceKey)
            }
        }
        return nil
    }

    private static func firstHeaderValue(_ headers: [(name: String, value: String)], name: String) -> String? {
        let target = name.lowercased()
        for (n, v) in headers where n.lowercased() == target {
            return v
        }
        return nil
    }
}
