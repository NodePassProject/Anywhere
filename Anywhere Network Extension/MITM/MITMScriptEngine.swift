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
/// ``CompiledMITMOperation/script`` rule. One ``JSContext`` is reused
/// across every script invocation on the connection; compiled functions
/// are cached by source content so duplicate scripts share work.
///
/// Watchdog: ``JSContextGroupSetExecutionTimeLimit`` is private API on
/// Apple platforms, so v1 ships without one. Scripts arrive through the
/// rule importer and are treated as trusted author code; the
/// ``MITMBodyCodec/maxBufferedBodyBytes`` cap bounds the working set
/// even in the worst case.
final class MITMScriptEngine {

    /// Mutable view of the in-flight HTTP message. The runtime hands
    /// this to `function process(ctx)` and reads each field back after
    /// the call; the JS side may mutate any field by assignment or in
    /// place (`ctx.body` is a Uint8Array backed by Swift-owned memory,
    /// so element-wise writes propagate without a return value).
    ///
    /// `method` and `url` are populated on both request and response
    /// phases (response carries the originating request's values, looked
    /// up via ``MITMRequestLog``). `status` is populated on response
    /// only. `phase` is read-only on the JS side; reassigning it is a
    /// no-op on Swift readback.
    struct Message {
        let phase: MITMPhase
        var method: String?
        var url: String?
        var status: Int?
        var headers: [(name: String, value: String)]
        var body: Data
        let ruleSetID: UUID?
    }

    /// Result of a single ``apply(_:source:)`` call. ``MITMScriptTransform``
    /// branches on this to chain rules normally, short-circuit with the
    /// current message, or roll back to the message as it entered the
    /// rule chain.
    enum Outcome {
        /// Normal return. Feed ``message`` to the next rule.
        case modified(Message)
        /// Script called `Anywhere.done()`. Use ``message``; skip the
        /// remaining rules in the chain.
        case done(Message)
        /// Script called `Anywhere.exit()`. Revert to the message as it
        /// entered the rule chain; skip the remaining rules.
        case exit
    }

    /// Per-frame snapshot for ``applyFrame``. Mirrors ``Message`` for
    /// the fields a streaming script can inspect, plus frame-level
    /// metadata (index + END_STREAM flag). All ctx fields except
    /// ``body`` are read-only on the JS side — HEADERS have already
    /// gone on the wire by the time DATA frames flow.
    struct FrameContext {
        let phase: MITMPhase
        let method: String?
        let url: String?
        let status: Int?
        let headers: [(name: String, value: String)]
        let frameIndex: Int
        /// True when this is the last frame in the stream (HTTP/2
        /// END_STREAM, HTTP/1 chunked terminator). Lets the script
        /// flush any state it has been accumulating.
        let isLast: Bool
        let ruleSetID: UUID?
    }

    /// Result of ``applyFrame``. ``state`` is the (possibly newly
    /// created) JSValue holding the script's persistent per-stream
    /// state; the caller threads it back in on the next frame and
    /// drops it at stream end.
    enum FrameOutcome {
        /// Normal return. Emit ``body`` as this frame's payload.
        case modified(body: Data, state: JSValue?)
        /// Script called `Anywhere.done()`. Emit ``body``, then pass
        /// every subsequent frame on this stream through unchanged.
        case done(body: Data)
        /// Script called `Anywhere.exit()`. Emit the original frame
        /// payload, then pass every subsequent frame through.
        case exit
    }

    /// Internal tag set by the `Anywhere.done` / `Anywhere.exit`
    /// blocks; ``apply`` reads it after the JS function returns and
    /// converts it to ``Outcome``.
    fileprivate enum Directive {
        case done
        case exit
    }

    private let context: JSContext
    private var compiled: [String: JSValue] = [:]

    /// Scope key the `Anywhere.store` globals consult on each call.
    /// Stashed by ``apply`` immediately before invoking the user
    /// function and cleared on return so a stray store call from a
    /// nested or re-entrant invocation cannot leak into the wrong scope.
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

    /// Runs ``source`` against ``message``. Returns the post-script
    /// message, or ``message`` unchanged when the script throws or
    /// otherwise fails to compile.
    func apply(_ message: Message, source: String) -> Outcome {
        guard let function = compileIfNeeded(source) else { return .modified(message) }
        currentScope = message.ruleSetID
        currentDirective = nil
        defer {
            currentScope = nil
            currentDirective = nil
        }
        let ctxArg = makeContextValue(message)
        _ = function.call(withArguments: [ctxArg])
        // The script may have replaced ctx.body with a new typed array,
        // mutated the original in place, or done nothing — read back
        // whatever is on the object now.
        let updated = readBack(message, from: ctxArg)
        if let directive = currentDirective {
            context.exception = nil
            switch directive {
            case .done: return .done(updated)
            case .exit: return .exit
            }
        }
        if context.exception != nil {
            // exceptionHandler already logged.
            context.exception = nil
            return .modified(message)
        }
        return .modified(updated)
    }

    /// Runs ``source`` against a single frame of a streaming body.
    /// Returns the (possibly modified) frame bytes plus the persistent
    /// state object the caller threads into the next frame. On script
    /// failure the original ``frame`` is emitted unchanged.
    func applyFrame(
        _ frame: Data,
        source: String,
        frameContext ctx: FrameContext,
        state: JSValue?
    ) -> FrameOutcome {
        guard let function = compileIfNeeded(source) else {
            return .modified(body: frame, state: state)
        }
        currentScope = ctx.ruleSetID
        currentDirective = nil
        defer {
            currentScope = nil
            currentDirective = nil
        }
        let ctxArg = makeFrameContextValue(ctx, frame: frame, state: state)
        _ = function.call(withArguments: [ctxArg])
        // Pull the body and state back off the ctx; ignore any
        // mutations to method/url/status/headers — HEADERS are on the
        // wire already, so they can't take effect.
        let body: Data
        if let bodyVal = ctxArg.objectForKeyedSubscript("body"),
           let bytes = Self.bytesFromValue(bodyVal, in: context) {
            body = bytes
        } else {
            body = frame
        }
        let updatedState = ctxArg.objectForKeyedSubscript("state")
        if let directive = currentDirective {
            context.exception = nil
            switch directive {
            case .done: return .done(body: body)
            case .exit: return .exit
            }
        }
        if context.exception != nil {
            context.exception = nil
            return .modified(body: frame, state: state)
        }
        return .modified(body: body, state: updatedState)
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
            logger.warning("[MITM][JS] script did not define process(ctx)")
            return nil
        }
        compiled[source] = value
        return value
    }

    // MARK: - Context bridging

    /// Builds the mutable JS ctx object exposed to `process(ctx)`. Each
    /// scalar field is set unconditionally; missing ones (e.g. `status`
    /// on the request phase) are JS `null` so the script can probe with
    /// `=== null` / `=== undefined`.
    private func makeContextValue(_ msg: Message) -> JSValue {
        let obj = JSValue(newObjectIn: context)!
        obj.setObject(
            msg.phase == .httpRequest ? "request" : "response",
            forKeyedSubscript: "phase" as NSString
        )
        obj.setObject(msg.method as Any, forKeyedSubscript: "method" as NSString)
        obj.setObject(msg.url as Any, forKeyedSubscript: "url" as NSString)
        obj.setObject(msg.status as Any, forKeyedSubscript: "status" as NSString)
        // Headers as an array of [name, value] pairs preserves both
        // duplicates and emit order; users can mutate it freely with
        // standard Array methods.
        let pairs: [[String]] = msg.headers.map { [$0.name, $0.value] }
        obj.setObject(pairs, forKeyedSubscript: "headers" as NSString)
        obj.setObject(Self.makeUint8Array(in: context, from: msg.body), forKeyedSubscript: "body" as NSString)
        return obj
    }

    /// Builds the per-frame JS ctx for ``applyFrame``. Like
    /// ``makeContextValue`` but adds a ``frame`` sub-object holding
    /// {index, end} and a ``state`` field that the script mutates
    /// across calls. On the first call ``state`` is nil and we install
    /// a fresh empty object so the script can write to it without
    /// guarding.
    private func makeFrameContextValue(
        _ ctx: FrameContext,
        frame: Data,
        state: JSValue?
    ) -> JSValue {
        let obj = JSValue(newObjectIn: context)!
        obj.setObject(
            ctx.phase == .httpRequest ? "request" : "response",
            forKeyedSubscript: "phase" as NSString
        )
        obj.setObject(ctx.method as Any, forKeyedSubscript: "method" as NSString)
        obj.setObject(ctx.url as Any, forKeyedSubscript: "url" as NSString)
        obj.setObject(ctx.status as Any, forKeyedSubscript: "status" as NSString)
        let pairs: [[String]] = ctx.headers.map { [$0.name, $0.value] }
        obj.setObject(pairs, forKeyedSubscript: "headers" as NSString)

        let frameInfo = JSValue(newObjectIn: context)!
        frameInfo.setObject(ctx.frameIndex, forKeyedSubscript: "index" as NSString)
        frameInfo.setObject(ctx.isLast, forKeyedSubscript: "end" as NSString)
        obj.setObject(frameInfo, forKeyedSubscript: "frame" as NSString)

        let stateValue = state ?? JSValue(newObjectIn: context)!
        obj.setObject(stateValue, forKeyedSubscript: "state" as NSString)

        obj.setObject(Self.makeUint8Array(in: context, from: frame), forKeyedSubscript: "body" as NSString)
        return obj
    }

    /// Reads each mutable field off the post-call ctx object and builds
    /// an updated ``Message``. Anything the script didn't touch comes
    /// back identical to the input; anything it cleared (assigned
    /// `null` / `undefined`) becomes nil on Swift side.
    private func readBack(_ original: Message, from ctx: JSValue) -> Message {
        var msg = original
        let method = ctx.objectForKeyedSubscript("method")
        msg.method = stringOrNil(method)
        let url = ctx.objectForKeyedSubscript("url")
        msg.url = stringOrNil(url)
        let status = ctx.objectForKeyedSubscript("status")
        msg.status = intOrNil(status)
        if let headers = ctx.objectForKeyedSubscript("headers"),
           !headers.isUndefined, !headers.isNull {
            msg.headers = Self.headersFromValue(headers)
        }
        if let body = ctx.objectForKeyedSubscript("body"),
           let bytes = Self.bytesFromValue(body, in: context) {
            msg.body = bytes
        }
        return msg
    }

    private func stringOrNil(_ value: JSValue?) -> String? {
        guard let value, !value.isUndefined, !value.isNull else { return nil }
        return value.toString()
    }

    private func intOrNil(_ value: JSValue?) -> Int? {
        guard let value, !value.isUndefined, !value.isNull else { return nil }
        if value.isNumber {
            return Int(value.toInt32())
        }
        // A string like "418" is convertible, but ambiguous; refuse and
        // let the script use a number literal explicitly.
        return nil
    }

    /// Decodes a JS `[[name, value], ...]` array into the Swift header
    /// list. Anything non-arrayish or whose entries aren't two-string
    /// pairs is dropped silently.
    private static func headersFromValue(_ value: JSValue) -> [(name: String, value: String)] {
        guard let array = value.toArray() else { return [] }
        var result: [(name: String, value: String)] = []
        result.reserveCapacity(array.count)
        for entry in array {
            guard let pair = entry as? [Any], pair.count == 2 else { continue }
            let name = (pair[0] as? String) ?? String(describing: pair[0])
            let val = (pair[1] as? String) ?? String(describing: pair[1])
            result.append((name: name, value: val))
        }
        return result
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

        // Anywhere.done() / Anywhere.exit() — short-circuit the script
        // chain. They set engine state and return undefined; the script
        // keeps executing, so user code is expected to `return`
        // immediately afterward to skip wasted work.
        //
        // ``done`` commits the current ctx state as the final message;
        // ``exit`` reverts to the message as it entered the rule chain.
        let doneBlock: @convention(block) () -> Void = { [weak self] in
            self?.currentDirective = .done
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
    /// Used for the utf8/base64/hex helpers' inputs, since the body
    /// readback already accepts strings (via ``bytesFromValue``) as a
    /// convenience.
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
