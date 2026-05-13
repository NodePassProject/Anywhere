//
//  MITMBodyTransform.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/9/26.
//

import Foundation

/// Applies the body-touching subset of a compiled rule list to a
/// buffered, decompressed body. The HTTP/1.1 and HTTP/2 rewriters share
/// this entry point so the rule-application loop lives in one place.
///
/// The only body-touching operation today is ``CompiledMITMOperation/bodyScript``,
/// which hands the bytes to ``MITMScriptEngine`` as a `Uint8Array`.
/// Multiple script rules run in array order, each rule's output
/// feeding the next; ``MITMScriptEngine/Outcome/done`` and
/// ``MITMScriptEngine/Outcome/exit`` short-circuit the chain.
///
/// Each body-script rule carries its own ``BodyContentTypeFilter``;
/// the message's `Content-Type` is checked once at the entry point so
/// rules whose filter doesn't match the in-flight payload are skipped
/// without entering the JS engine.
enum MITMBodyTransform {

    /// True when at least one body-script rule in ``rules`` would fire
    /// for a message with the given ``contentType``. Both rewriters
    /// consult this at head-completion time to decide whether the
    /// body needs to be buffered at all — when every script's filter
    /// rejects the type, buffering is wasted work.
    static func hasBodyRule(in rules: [CompiledMITMRule], contentType: String?) -> Bool {
        rules.contains { rule in
            switch rule.operation {
            case .bodyScript(_, let filter):
                return filter.matches(contentType)
            case .urlReplace, .headerAdd, .headerDelete, .headerReplace:
                return false
            }
        }
    }

    /// Applies every body-touching rule in ``rules`` whose
    /// Content-Type filter accepts ``contentType``. Rules are applied
    /// in array order; the rest of the list is preserved verbatim
    /// (header-only rules are no-ops here). Returns the input
    /// unchanged when no rule matches.
    ///
    /// Script rules are skipped silently when ``engineProvider`` or
    /// ``context`` is nil — call sites that want script support pass
    /// both. The provider is consulted lazily so a session that never
    /// hits a script rule never spins up a ``JSContext``.
    static func apply(
        _ data: Data,
        rules: [CompiledMITMRule],
        contentType: String?,
        engineProvider: MITMScriptEngine.Provider? = nil,
        context: MITMScriptEngine.Context? = nil
    ) -> Data {
        let original = data
        var current = data
        for rule in rules {
            switch rule.operation {
            case .bodyScript(let source, let filter):
                guard filter.matches(contentType) else { continue }
                guard let engineProvider, let context else { continue }
                let outcome = engineProvider.get().apply(
                    current,
                    source: source,
                    requestContext: context
                )
                switch outcome {
                case .modified(let body):
                    current = body
                case .done(let body):
                    return body
                case .exit:
                    return original
                }
            case .urlReplace, .headerAdd, .headerDelete, .headerReplace:
                continue
            }
        }
        return current
    }
}
