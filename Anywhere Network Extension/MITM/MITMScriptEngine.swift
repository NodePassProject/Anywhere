//
//  MITMScriptEngine.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/9/26.
//

import Foundation
import JavaScriptCore

private let logger = AnywhereLogger(category: "MITM")

/// Per-``MITMSession`` JavaScript runtime for the
/// ``CompiledMITMOperation/bodyScript`` rule. One ``JSContext`` is reused
/// across every script invocation on the connection; compiled functions
/// are cached by source content so duplicate scripts share work.
///
/// Watchdog: ``JSContextGroupSetExecutionTimeLimit`` is private API on
/// Apple platforms, so v1 ships without one. Scripts arrive through the
/// rule importer and are treated as trusted author code; the
/// ``MITMBodyCodec/maxBufferedBodyBytes`` cap bounds the working set
/// even in the worst case.
final class MITMScriptEngine {

    /// Snapshot of the in-flight HTTP message that the script may
    /// inspect via the `ctx` argument to `function process(body, ctx)`.
    /// `method` and `url` are nil on the response phase; `headers`
    /// preserves duplicates and order. ``ruleSetID`` is the scope key
    /// `Anywhere.store` uses; nil disables the store for the call.
    struct Context {
        let phase: MITMPhase
        let method: String?
        let url: String?
        let headers: [(name: String, value: String)]
        let ruleSetID: UUID?
    }

    /// Result of a single ``apply(_:source:requestContext:)`` call.
    /// ``MITMBodyTransform`` branches on this to chain rules normally,
    /// short-circuit with a final body, or roll back to the body as it
    /// entered the rule chain.
    enum Outcome {
        /// Normal return. Feed ``body`` to the next rule.
        case modified(body: Data)
        /// Script called `Anywhere.done(value)`. Use ``body``; skip the
        /// remaining rules in the chain.
        case done(body: Data)
        /// Script called `Anywhere.exit()`. Revert to the body as it
        /// entered the rule chain; skip the remaining rules.
        case exit
    }

    /// Internal tag set by the `Anywhere.done` / `Anywhere.exit`
    /// blocks; ``apply(_:source:requestContext:)`` reads it after the
    /// JS function returns and converts it to ``Outcome``.
    fileprivate enum Directive {
        case done(Data)
        case exit
    }

    private let context: JSContext
    private var compiled: [String: JSValue] = [:]

    /// Scope key the `Anywhere.store` globals consult on each call.
    /// Stashed by ``apply(_:source:requestContext:)`` immediately
    /// before invoking the user function and cleared on return so a
    /// stray store call from a nested or re-entrant invocation cannot
    /// leak into the wrong scope.
    fileprivate var currentScope: UUID?

    /// Directive set by `Anywhere.done` / `Anywhere.exit`. ``apply``
    /// inspects this after the JS function returns; when set, the
    /// directive wins over whatever the function returned.
    fileprivate var currentDirective: Directive?

    init() {
        let vm = JSVirtualMachine()!
        self.context = JSContext(virtualMachine: vm)
        self.context.exceptionHandler = { _, exception in
            logger.warning("[MITM][JS] uncaught: \(exception?.toString() ?? "<unknown>")")
        }
        installAnywhereGlobals()
    }

    /// Runs ``source`` against ``data``. Returns the rewritten body, or
    /// ``data`` unchanged when the script throws, returns nothing, or
    /// the returned value cannot be coerced to bytes.
    func apply(_ data: Data, source: String, requestContext ctx: Context) -> Outcome {
        guard let function = compileIfNeeded(source) else { return .modified(body: data) }
        currentScope = ctx.ruleSetID
        currentDirective = nil
        defer {
            currentScope = nil
            currentDirective = nil
        }
        let bodyArg = Self.makeUint8Array(in: context, from: data)
        let ctxArg = makeContextValue(ctx)
        let result = function.call(withArguments: [bodyArg, ctxArg])
        // Directive wins over both the function's return value and any
        // exception thrown after the directive was set — `done`/`exit`
        // are explicit user intent.
        if let directive = currentDirective {
            context.exception = nil
            switch directive {
            case .done(let body): return .done(body: body)
            case .exit:           return .exit
            }
        }
        if context.exception != nil {
            // exceptionHandler already logged.
            context.exception = nil
            return .modified(body: data)
        }
        guard let result else { return .modified(body: data) }
        return .modified(body: Self.bytesFromValue(result, in: context) ?? data)
    }

    // MARK: - Compilation

    private func compileIfNeeded(_ source: String) -> JSValue? {
        if let cached = compiled[source] { return cached }
        // IIFE wrap so the user's `function process(...)` lives in its
        // own scope; we capture the function as the IIFE return value
        // rather than polluting globalThis.
        let wrapped = "(function(){\n\(source)\nreturn process;\n})()"
        let value = context.evaluateScript(wrapped)
        if context.exception != nil {
            context.exception = nil
            return nil
        }
        guard let value, !value.isUndefined, !value.isNull else {
            logger.warning("[MITM][JS] script did not define process(body, ctx)")
            return nil
        }
        compiled[source] = value
        return value
    }

    // MARK: - Context bridging

    private func makeContextValue(_ ctx: Context) -> JSValue {
        let obj = JSValue(newObjectIn: context)!
        obj.setObject(
            ctx.phase == .httpRequest ? "request" : "response",
            forKeyedSubscript: "phase" as NSString
        )
        if let method = ctx.method {
            obj.setObject(method, forKeyedSubscript: "method" as NSString)
        }
        if let url = ctx.url {
            obj.setObject(url, forKeyedSubscript: "url" as NSString)
        }
        // Headers as an array of [name, value] pairs preserves both
        // duplicates and emit order; users can build a map if they want.
        let pairs: [[String]] = ctx.headers.map { [$0.name, $0.value] }
        obj.setObject(pairs, forKeyedSubscript: "headers" as NSString)
        return obj
    }

    // MARK: - Anywhere globals

    private func installAnywhereGlobals() {
        let anywhere = JSValue(newObjectIn: context)!

        let utf8 = JSValue(newObjectIn: context)!
        let utf8Encode: @convention(block) (String) -> JSValue = { str in
            let ctx = JSContext.current()!
            return Self.makeUint8Array(in: ctx, from: Data(str.utf8))
        }
        let utf8Decode: @convention(block) (JSValue) -> String = { val in
            let ctx = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: ctx) ?? Data()
            return String(data: bytes, encoding: .utf8) ?? ""
        }
        utf8.setObject(utf8Encode, forKeyedSubscript: "encode" as NSString)
        utf8.setObject(utf8Decode, forKeyedSubscript: "decode" as NSString)
        anywhere.setObject(utf8, forKeyedSubscript: "utf8" as NSString)

        let base64 = JSValue(newObjectIn: context)!
        let base64Encode: @convention(block) (JSValue) -> String = { val in
            let ctx = JSContext.current()!
            return (Self.bytesFromValue(val, in: ctx) ?? Data()).base64EncodedString()
        }
        let base64Decode: @convention(block) (String) -> JSValue = { str in
            let ctx = JSContext.current()!
            return Self.makeUint8Array(in: ctx, from: Data(base64Encoded: str) ?? Data())
        }
        base64.setObject(base64Encode, forKeyedSubscript: "encode" as NSString)
        base64.setObject(base64Decode, forKeyedSubscript: "decode" as NSString)
        anywhere.setObject(base64, forKeyedSubscript: "base64" as NSString)

        let hex = JSValue(newObjectIn: context)!
        let hexEncode: @convention(block) (JSValue) -> String = { val in
            let ctx = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: ctx) ?? Data()
            return bytes.map { String(format: "%02x", $0) }.joined()
        }
        let hexDecode: @convention(block) (String) -> JSValue = { str in
            let ctx = JSContext.current()!
            return Self.makeUint8Array(in: ctx, from: Self.decodeHex(str))
        }
        hex.setObject(hexEncode, forKeyedSubscript: "encode" as NSString)
        hex.setObject(hexDecode, forKeyedSubscript: "decode" as NSString)
        anywhere.setObject(hex, forKeyedSubscript: "hex" as NSString)

        let store = JSValue(newObjectIn: context)!
        let storeGet: @convention(block) (String) -> JSValue = { [weak self] key in
            let ctx = JSContext.current()!
            guard let scope = self?.currentScope,
                  let bytes = MITMScriptStore.shared.get(scope: scope, key: key)
            else { return JSValue(undefinedIn: ctx) }
            return Self.makeUint8Array(in: ctx, from: bytes)
        }
        let storeGetString: @convention(block) (String) -> JSValue = { [weak self] key in
            let ctx = JSContext.current()!
            guard let scope = self?.currentScope,
                  let bytes = MITMScriptStore.shared.get(scope: scope, key: key),
                  let str = String(data: bytes, encoding: .utf8)
            else { return JSValue(undefinedIn: ctx) }
            return JSValue(object: str, in: ctx)
        }
        let storeSet: @convention(block) (String, JSValue) -> Void = { [weak self] key, val in
            let ctx = JSContext.current()!
            guard let scope = self?.currentScope else { return }
            let bytes = Self.bytesFromValue(val, in: ctx) ?? Data()
            do {
                try MITMScriptStore.shared.set(scope: scope, key: key, value: bytes)
            } catch MITMScriptStore.StoreError.capacityExceeded {
                let err = JSValue(
                    newErrorFromMessage: "Anywhere.store: capacity exceeded (per-scope cap is \(MITMScriptStore.maxBytesPerScope) bytes)",
                    in: ctx
                )
                ctx.exception = err
            } catch {
                let err = JSValue(newErrorFromMessage: "Anywhere.store: \(error)", in: ctx)
                ctx.exception = err
            }
        }
        let storeDelete: @convention(block) (String) -> Void = { [weak self] key in
            guard let scope = self?.currentScope else { return }
            MITMScriptStore.shared.delete(scope: scope, key: key)
        }
        let storeKeys: @convention(block) () -> [String] = { [weak self] in
            guard let scope = self?.currentScope else { return [] }
            return MITMScriptStore.shared.keys(scope: scope)
        }
        store.setObject(storeGet, forKeyedSubscript: "get" as NSString)
        store.setObject(storeGetString, forKeyedSubscript: "getString" as NSString)
        store.setObject(storeSet, forKeyedSubscript: "set" as NSString)
        store.setObject(storeDelete, forKeyedSubscript: "delete" as NSString)
        store.setObject(storeKeys, forKeyedSubscript: "keys" as NSString)
        anywhere.setObject(store, forKeyedSubscript: "store" as NSString)

        // Anywhere.done(uint8Array) / Anywhere.exit() — short-circuit
        // the body-rule chain. They set engine state and return
        // undefined; the script keeps executing, so user code is
        // expected to `return` immediately afterward to skip wasted
        // work. ``done`` requires a Uint8Array (or any typed-array /
        // ArrayBuffer) — strings, null, undefined, and the no-arg form
        // raise a JS `TypeError`.
        let doneBlock: @convention(block) (JSValue) -> Void = { [weak self] val in
            let ctx = JSContext.current()!
            guard let self else { return }
            guard let bytes = Self.typedArrayBytesFromValue(val, in: ctx) else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.done(value): value must be a Uint8Array",
                    in: ctx
                )
                return
            }
            self.currentDirective = .done(bytes)
        }
        let exitBlock: @convention(block) () -> Void = { [weak self] in
            self?.currentDirective = .exit
        }
        anywhere.setObject(doneBlock, forKeyedSubscript: "done" as NSString)
        anywhere.setObject(exitBlock, forKeyedSubscript: "exit" as NSString)

        context.setObject(anywhere, forKeyedSubscript: "Anywhere" as NSString)
    }

    // MARK: - Body bridging (static so closures don't capture self)

    private static func makeUint8Array(in context: JSContext, from data: Data) -> JSValue {
        let count = data.count
        // Always allocate at least one byte so the deallocator has a
        // valid pointer to free; JSC accepts a zero-length view fine.
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: max(count, 1), alignment: 1)
        if count > 0 {
            data.copyBytes(to: buffer.assumingMemoryBound(to: UInt8.self), count: count)
        }
        let deallocator: JSTypedArrayBytesDeallocator = { ptr, _ in
            ptr?.deallocate()
        }
        var exception: JSValueRef?
        let ref = JSObjectMakeTypedArrayWithBytesNoCopy(
            context.jsGlobalContextRef,
            kJSTypedArrayTypeUint8Array,
            buffer,
            count,
            deallocator,
            nil,
            &exception
        )
        guard exception == nil, let ref else {
            buffer.deallocate()
            return JSValue(undefinedIn: context)
        }
        return JSValue(jsValueRef: ref, in: context)
    }

    private static func bytesFromValue(_ value: JSValue, in context: JSContext) -> Data? {
        if value.isNull || value.isUndefined { return nil }
        if value.isString {
            return value.toString().map { Data($0.utf8) }
        }
        return typedArrayBytesFromValue(value, in: context)
    }

    /// Strict typed-array / ArrayBuffer extraction — no string
    /// fallback. Returns nil for null, undefined, strings, numbers,
    /// plain objects, and anything else that isn't byte-shaped.
    /// `Anywhere.done` uses this to enforce its Uint8Array-only
    /// contract; the bytes-or-string helpers (utf8/base64/hex,
    /// `process` return value) keep using ``bytesFromValue``.
    private static func typedArrayBytesFromValue(_ value: JSValue, in context: JSContext) -> Data? {
        if value.isNull || value.isUndefined { return nil }
        let ctxRef = context.jsGlobalContextRef
        guard let ref = value.jsValueRef else { return nil }
        var exception: JSValueRef?
        let kind = JSValueGetTypedArrayType(ctxRef, ref, &exception)
        if exception != nil { return nil }
        if kind == kJSTypedArrayTypeNone { return nil }
        guard let obj = JSValueToObject(ctxRef, ref, &exception), exception == nil else {
            return nil
        }
        if kind == kJSTypedArrayTypeArrayBuffer {
            let len = JSObjectGetArrayBufferByteLength(ctxRef, obj, &exception)
            guard exception == nil,
                  let ptr = JSObjectGetArrayBufferBytesPtr(ctxRef, obj, &exception),
                  exception == nil
            else { return nil }
            return Data(bytes: ptr, count: len)
        }
        let len = JSObjectGetTypedArrayByteLength(ctxRef, obj, &exception)
        guard exception == nil,
              let ptr = JSObjectGetTypedArrayBytesPtr(ctxRef, obj, &exception),
              exception == nil
        else { return nil }
        return Data(bytes: ptr, count: len)
    }

    private static func decodeHex(_ str: String) -> Data {
        var out = Data()
        var iter = str.unicodeScalars.makeIterator()
        while let hi = iter.next() {
            guard let lo = iter.next(),
                  let h = hexNibble(hi),
                  let l = hexNibble(lo)
            else { return Data() }
            out.append((h << 4) | l)
        }
        return out
    }

    private static func hexNibble(_ scalar: Unicode.Scalar) -> UInt8? {
        switch scalar {
        case "0"..."9": return UInt8(scalar.value - 48)
        case "a"..."f": return UInt8(scalar.value - 87)
        case "A"..."F": return UInt8(scalar.value - 55)
        default: return nil
        }
    }
}

extension MITMScriptEngine {

    /// Lazy holder for one ``MITMScriptEngine`` instance per
    /// ``MITMSession``. Threads the lazy-creation policy through the rule
    /// pipeline without requiring the engine to be allocated up front for
    /// every intercepted connection — sessions whose policy never invokes
    /// a script rule never instantiate a JSContext.
    ///
    /// Not thread-safe. Sessions serialize all rule application on
    /// ``MITMSession``'s lwIP queue, so no synchronization is needed
    /// here.
    final class Provider {
        private var instance: MITMScriptEngine?

        init() {}

        func get() -> MITMScriptEngine {
            if let instance { return instance }
            let new = MITMScriptEngine()
            instance = new
            return new
        }
    }
}
