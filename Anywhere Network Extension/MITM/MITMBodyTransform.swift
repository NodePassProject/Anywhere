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
enum MITMBodyTransform {

    /// True when at least one rule in ``rules`` would touch the body.
    /// Both rewriters consult this at head-completion time to decide
    /// whether the body needs to be buffered at all.
    static func hasBodyRule(in rules: [CompiledMITMRule]) -> Bool {
        rules.contains { rule in
            switch rule.operation {
            case .bodyScript: return true
            case .urlReplace, .headerAdd, .headerDelete, .headerReplace:
                return false
            }
        }
    }

    /// Applies every body-touching rule in ``rules`` to ``data`` in
    /// array order. Returns the input unchanged when no rule matches.
    ///
    /// Script rules are skipped silently when ``engineProvider`` or
    /// ``context`` is nil — call sites that want script support pass
    /// both. The provider is consulted lazily so a session that never
    /// hits a script rule never spins up a ``JSContext``.
    static func apply(
        _ data: Data,
        rules: [CompiledMITMRule],
        engineProvider: MITMScriptEngine.Provider? = nil,
        context: MITMScriptEngine.Context? = nil
    ) -> Data {
        let original = data
        var current = data
        for rule in rules {
            switch rule.operation {
            case .bodyScript(let source):
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
