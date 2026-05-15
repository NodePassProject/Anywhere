//
//  MITMScriptEngine.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation
import JavaScriptCore

private let logger = AnywhereLogger(category: "MITM")

/// Per-``MITMSession`` JavaScript runtime for the
/// ``CompiledMITMOperation/script`` rule. One ``JSContext`` is reused
/// across every script invocation on the connection; compiled functions
/// are cached by source content so duplicate scripts share work.
///
/// No execution-time watchdog. Preempting a runaway JS call from
/// another thread requires ``JSContextGroupSetExecutionTimeLimit``,
/// which lives in WebKit's ``JSContextRefPrivate.h`` — SPI that App
/// Review's automated scan flags on sight (the symbol name appears
/// verbatim in the Mach-O import table no matter how the call site
/// is wrapped), with no public-API substitute that preempts a
/// synchronous call already running in JSC. We accept the
/// consequence by design: a user-authored ``process(ctx)`` that
/// loops forever, recurses without bound, or backtracks a
/// pathological regex will wedge the calling MITM connection and,
/// because the pipeline shares one lwIP queue, every other flow in
/// the tunnel along with it. Mitigation is on the authoring side —
/// keep scripts simple and bounded; the engine still reverts uncaught
/// throws so a script that fails partway leaves the wire untouched.
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

    /// Synthesized response produced when a request-phase script calls
    /// `Anywhere.respond(...)`. The runtime drops the request before it
    /// reaches the upstream leg and writes this response straight back to
    /// the client instead. Only emitted on ``MITMPhase/httpRequest``;
    /// response-phase invocations of ``Anywhere/respond`` are ignored
    /// since the script can already rewrite the response via ctx
    /// mutations.
    struct SynthesizedResponse {
        let status: Int
        let headers: [(name: String, value: String)]
        let body: Data
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
        /// Request-phase script called `Anywhere.respond(...)`. Drop the
        /// request without forwarding upstream and synthesize this
        /// response back to the client.
        case respond(SynthesizedResponse)
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

    /// Internal tag set by the `Anywhere.done` / `Anywhere.exit` /
    /// `Anywhere.respond` blocks; ``apply`` reads it after the JS
    /// function returns and converts it to ``Outcome``.
    fileprivate enum Directive {
        case done
        case exit
        case respond(SynthesizedResponse)
    }

    private let context: JSContext
    /// Compiled `process(ctx)` functions keyed by the
    /// ``CompiledMITMOperation``'s ``sourceKey``. Using a precomputed
    /// hash as the key keeps lookups O(1) regardless of source size —
    /// the previous ``[String: JSValue]`` cache rehashed and recompared
    /// the entire source on every JS call, which dominated CPU for
    /// large scripts on hot streams.
    private var compiled: [Int: JSValue] = [:]

    /// Scope key the `Anywhere.store` globals consult on each call.
    /// Stashed by ``apply`` immediately before invoking the user
    /// function and cleared on return so a stray store call from a
    /// nested or re-entrant invocation cannot leak into the wrong scope.
    fileprivate var currentScope: UUID?

    /// Directive set by `Anywhere.done` / `Anywhere.exit` /
    /// `Anywhere.respond`. ``apply`` inspects this after the JS function
    /// returns; when set, the directive wins over whatever the function
    /// returned — including over a tail-end exception. This is
    /// intentional: a script that already signalled its decision
    /// before stumbling into a throw (typically an
    /// ``Anywhere.store.set`` over the per-scope cap) has expressed
    /// the result it wanted, and rolling back to ``.modified(message)``
    /// would discard that decision.
    fileprivate var currentDirective: Directive?

    /// Process-wide JSC heap shared by every ``MITMScriptEngine``. Each
    /// session still owns its own ``JSContext`` so script-set globals
    /// stay per-session, but the underlying heap, GC, and allocator
    /// are shared — the previous one-VM-per-engine layout multiplied
    /// JSC's multi-MiB per-VM cost by every active MITM session, which
    /// the Network Extension's ~50 MiB budget can't sustain under even
    /// modest concurrency. JSC serializes access to the heap with an
    /// internal mutex, so multiple sessions on independent queues are
    /// safe without an external lock.
    private static let sharedVM: JSVirtualMachine = JSVirtualMachine()!

    init() {
        self.context = JSContext(virtualMachine: Self.sharedVM)
        // JSC's default exception handler writes the thrown value to
        // ``context.exception``; installing a custom handler REPLACES
        // that default, so we must reinstate the write ourselves or
        // every ``context.exception != nil`` check downstream sees
        // nil and the rollback path silently never fires.
        self.context.exceptionHandler = { context, exception in
            logger.warning("[MITM][JS] uncaught: \(exception?.toString() ?? "<unknown>")")
            context?.exception = exception
        }
        installAnywhereGlobals()
    }

    /// Runs ``source`` against ``message``. Returns the post-script
    /// message, or ``message`` unchanged when the script throws or
    /// otherwise fails to compile. ``sourceKey`` is the cache key
    /// computed at rule-compile time; equal keys imply equal sources.
    func apply(_ message: Message, source: String, sourceKey: Int) -> Outcome {
        guard let function = compileIfNeeded(source, key: sourceKey) else {
            return .modified(message)
        }
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
        let hadException = context.exception != nil
        if let directive = currentDirective {
            context.exception = nil
            switch directive {
            case .done: return .done(updated)
            case .exit: return .exit
            case .respond(let response):
                // Only request-phase scripts can synthesize a response;
                // response-phase scripts can already rewrite the
                // response via ctx mutations, so ``Anywhere.respond``
                // there is treated as a no-op.
                if message.phase == .httpRequest {
                    return .respond(response)
                }
                logger.warning("[MITM][JS] Anywhere.respond ignored on response phase")
                return .modified(updated)
            }
        }
        if hadException {
            // Uncaught throw without a directive: revert all ctx
            // mutations the script made before the throw. The
            // defensive default is to discard partial work rather than
            // commit a half-formed rewrite onto the wire; a script
            // that wants its mutations preserved can wrap the failing
            // call in try/catch, or signal ``Anywhere.done()``
            // explicitly before the throw point (the directive branch
            // above keeps ``updated`` in that case).
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
        sourceKey: Int,
        frameContext ctx: FrameContext,
        state: JSValue?
    ) -> FrameOutcome {
        guard let function = compileIfNeeded(source, key: sourceKey) else {
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
        let hadException = context.exception != nil
        if let directive = currentDirective {
            context.exception = nil
            switch directive {
            case .done: return .done(body: body)
            case .exit: return .exit
            case .respond:
                // streamScript can't synthesize a response — the head
                // has already gone on the wire by the time DATA frames
                // flow. Treat it as a no-op and continue streaming.
                logger.warning("[MITM][JS] Anywhere.respond ignored in streamScript")
                return .modified(body: body, state: updatedState)
            }
        }
        if hadException {
            context.exception = nil
            return .modified(body: frame, state: state)
        }
        return .modified(body: body, state: updatedState)
    }

    // MARK: - Compilation

    private func compileIfNeeded(_ source: String, key: Int) -> JSValue? {
        if let cached = compiled[key] { return cached }
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
        // Caching a non-callable value (e.g. ``let process = 42;`` or
        // ``var process = { run: ... };``) would have every subsequent
        // ``function.call`` throw "not a function" forever, since the
        // cache is sticky for the engine's lifetime. Reject up front so
        // the failure mode is one logged line, not one warning per
        // intercepted message.
        guard let ref = value.jsValueRef else { return nil }
        let ctxRef = context.jsGlobalContextRef
        var exception: JSValueRef?
        guard let object = JSValueToObject(ctxRef, ref, &exception),
              exception == nil,
              JSObjectIsFunction(ctxRef, object)
        else {
            logger.warning("[MITM][JS] script's `process` is not a function; declare it as `function process(ctx) { ... }`")
            return nil
        }
        compiled[key] = value
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
    ///
    /// Hostile / buggy scripts can write CR / LF / NUL into ``method``,
    /// ``url``, header names, or header values. The HTTP/1 serializer
    /// emits those bytes verbatim, which would split the wire framing
    /// (request smuggling / response splitting); HTTP/2 receivers
    /// reject any CR / LF / NUL in a HEADERS block per RFC 9113 §8.2.1
    /// and drop the stream. To make either outcome impossible from a
    /// rule set, this method validates each field before adopting it:
    /// fields that fail validation revert to the ``original`` input,
    /// invalid header entries are dropped, and a non-array
    /// ``ctx.headers`` is treated as "leave headers alone" rather than
    /// silently wiping every header (a common typo footgun).
    private func readBack(_ original: Message, from ctx: JSValue) -> Message {
        var msg = original
        let methodVal = ctx.objectForKeyedSubscript("method")
        msg.method = validatedMethod(methodVal, original: original.method)
        let urlVal = ctx.objectForKeyedSubscript("url")
        msg.url = validatedURL(urlVal, original: original.url)
        let statusVal = ctx.objectForKeyedSubscript("status")
        msg.status = validatedStatus(statusVal, original: original.status)
        if let headersVal = ctx.objectForKeyedSubscript("headers"),
           !headersVal.isUndefined, !headersVal.isNull {
            if let validated = Self.headersFromValue(headersVal) {
                msg.headers = validated
            }
            // else: ctx.headers isn't array-shaped — keep ``original.headers``
            //       rather than wiping them. A script doing
            //       ``ctx.headers = "Foo: bar"`` shouldn't strip every
            //       header from the message.
        }
        if let body = ctx.objectForKeyedSubscript("body"),
           let bytes = Self.bytesFromValue(body, in: context) {
            msg.body = bytes
        }
        return msg
    }

    /// Pulls ``ctx.method`` back. ``undefined`` / ``null`` clears the
    /// field; a value that's a non-empty RFC 9110 §9.1 token (same
    /// charset as a header field-name) is adopted; anything else
    /// reverts to ``original`` with a warning. The token check rules
    /// out SP / HTAB / CR / LF / NUL, all of which would smuggle bytes
    /// onto the request line.
    private func validatedMethod(_ value: JSValue?, original: String?) -> String? {
        guard let value, !value.isUndefined, !value.isNull else { return nil }
        guard let str = value.toString() else { return original }
        if Self.isValidHeaderName(str) { return str }
        logger.warning("[MITM][JS] ctx.method contains invalid characters; reverting")
        return original
    }

    /// Pulls ``ctx.url`` back. Same cleared-vs-adopted semantics as
    /// ``validatedMethod``; the validation rejects empty strings and
    /// anything containing SP / HTAB / CTLs. We don't try to fully
    /// validate URL syntax — ``rebuildStartLine`` already falls back to
    /// the original request-target when the URL fails to parse — but
    /// stripping HTTP/1 start-line delimiters keeps a malicious or
    /// buggy script from corrupting the request line.
    private func validatedURL(_ value: JSValue?, original: String?) -> String? {
        guard let value, !value.isUndefined, !value.isNull else { return nil }
        guard let str = value.toString() else { return original }
        if Self.isValidRequestTargetValue(str) { return str }
        logger.warning("[MITM][JS] ctx.url is empty or contains whitespace/control characters; reverting")
        return original
    }

    /// Pulls ``ctx.status`` back. ``undefined`` / ``null`` clears the
    /// status (response-phase scripts can use this to drop a value);
    /// a number in the 100…599 wire range is adopted; out-of-range
    /// numbers and non-numeric values revert to ``original`` with a
    /// warning. Strings convertible to numbers (`"200"`) are refused
    /// rather than silently coerced — the failure mode of accidentally
    /// stringifying the status is hard enough to debug already.
    private func validatedStatus(_ value: JSValue?, original: Int?) -> Int? {
        guard let value, !value.isUndefined, !value.isNull else { return nil }
        guard value.isNumber else {
            logger.warning("[MITM][JS] ctx.status is not a number; reverting (script may have assigned a string — use a numeric literal)")
            return original
        }
        let n = Int(value.toInt32())
        if (100...599).contains(n) { return n }
        logger.warning("[MITM][JS] ctx.status \(n) outside 100…599; reverting")
        return original
    }

    /// Decodes a JS `[[name, value], ...]` array into the Swift header
    /// list, returning nil when the input isn't array-shaped at all
    /// (so the caller can keep the original headers instead of wiping
    /// them) or when every entry in a non-empty input failed
    /// validation. An explicit empty input array still returns an
    /// empty list so a script can intentionally clear all headers via
    /// `ctx.headers = []`. Individual entries whose name isn't a valid
    /// HTTP token (RFC 9110 §5.6.2) or whose value contains CR / LF /
    /// NUL (§5.5) are dropped with a warning — emitting them verbatim
    /// would split the response head on the wire.
    ///
    /// The "all dropped" guard rules out a common footgun: a script
    /// that writes a flat array (``ctx.headers = ["X-Foo","bar"]``)
    /// instead of the required pair-of-pairs shape would otherwise
    /// silently wipe every header on the message, since every entry
    /// fails the ``pair.count == 2`` shape check. Reverting forces the
    /// drop warnings into the log path the caller can act on.
    private static func headersFromValue(_ value: JSValue) -> [(name: String, value: String)]? {
        guard let array = value.toArray() else { return nil }
        if array.isEmpty { return [] }
        var result: [(name: String, value: String)] = []
        result.reserveCapacity(array.count)
        for entry in array {
            guard let pair = entry as? [Any], pair.count == 2 else {
                logger.warning("[MITM][JS] dropping ctx.headers entry that isn't a [name, value] pair")
                continue
            }
            let name = (pair[0] as? String) ?? String(describing: pair[0])
            let val = (pair[1] as? String) ?? String(describing: pair[1])
            guard isValidHeaderName(name) else {
                logger.warning("[MITM][JS] dropping header with invalid name: \(name)")
                continue
            }
            guard isValidHeaderValue(val) else {
                logger.warning("[MITM][JS] dropping header \(name) with CR/LF/NUL in value")
                continue
            }
            result.append((name: name, value: val))
        }
        if result.isEmpty {
            logger.warning("[MITM][JS] ctx.headers had no valid [name, value] pairs; reverting to original headers (use ``ctx.headers = []`` to intentionally clear)")
            return nil
        }
        return result
    }

    /// RFC 9110 §5.6.2: header field-name and method token alphabet.
    /// Duplicated from ``MITMHTTP1Stream`` / ``MITMHTTP2Connection``
    /// rather than shared via a helper type so the engine stays
    /// dependency-free of the wire layers.
    private static func isValidHeaderName(_ name: String) -> Bool {
        guard !name.isEmpty else { return false }
        for byte in name.utf8 {
            switch byte {
            case 0x21, 0x23, 0x24, 0x25, 0x26, 0x27,
                 0x2A, 0x2B, 0x2D, 0x2E,
                 0x5E, 0x5F, 0x60, 0x7C, 0x7E:
                continue
            case 0x30...0x39, 0x41...0x5A, 0x61...0x7A:
                continue
            default:
                return false
            }
        }
        return true
    }

    /// RFC 9110 §5.5: header field-value must not contain CR / LF /
    /// NUL. Same rule applies to anything we splice onto an HTTP/1
    /// start line — those characters are exactly what splits a wire
    /// message into two.
    private static func isValidHeaderValue(_ value: String) -> Bool {
        for byte in value.utf8 {
            if byte == 0x0D || byte == 0x0A || byte == 0x00 {
                return false
            }
        }
        return true
    }

    /// HTTP/1 request-targets are delimited by SP in the start line, so a
    /// script-provided URL / relative target cannot safely contain SP,
    /// HTAB, or any control byte. Absolute URLs are still allowed; the
    /// serializers will project them down to path + query where needed.
    private static func isValidRequestTargetValue(_ value: String) -> Bool {
        guard !value.isEmpty else { return false }
        for byte in value.utf8 {
            if byte <= 0x20 || byte == 0x7F {
                return false
            }
        }
        return true
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

        // Anywhere.respond({status, headers, body}) — request-phase
        // short-circuit. The runtime drops the request before it
        // reaches upstream and writes the supplied response back to
        // the client. The spec object accepts:
        //   - status: number (default 200)
        //   - headers: [[name, value], ...] (default [])
        //   - body: Uint8Array | ArrayBuffer | string (default empty)
        // Any of those fields may be omitted. Response-phase and
        // streamScript invocations are ignored (logged as warnings).
        let respondBlock: @convention(block) (JSValue) -> Void = { [weak self] spec in
            guard let self else { return }
            guard !spec.isUndefined, !spec.isNull else {
                self.currentDirective = .respond(
                    SynthesizedResponse(status: 200, headers: [], body: Data())
                )
                return
            }
            // Clamp the status to the 100…599 range a real HTTP
            // response can occupy. A negative or out-of-range value
            // would either emit ``HTTP/1.1 -1`` on the wire (HTTP/1) or
            // an ``:status: -1`` HPACK literal the receiver rejects as
            // malformed (HTTP/2). 200 is the obvious fallback.
            let status: Int
            if let statusVal = spec.objectForKeyedSubscript("status"),
               statusVal.isNumber {
                let raw = Int(statusVal.toInt32())
                if (100...599).contains(raw) {
                    status = raw
                } else {
                    logger.warning("[MITM][JS] Anywhere.respond status \(raw) out of 100…599; using 200")
                    status = 200
                }
            } else {
                status = 200
            }
            var headers: [(name: String, value: String)] = []
            if let headersVal = spec.objectForKeyedSubscript("headers"),
               !headersVal.isUndefined, !headersVal.isNull,
               let parsed = Self.headersFromValue(headersVal) {
                headers = parsed
            }
            let body: Data
            if let bodyVal = spec.objectForKeyedSubscript("body"),
               !bodyVal.isUndefined, !bodyVal.isNull {
                body = Self.bytesFromValue(bodyVal, in: self.context) ?? Data()
            } else {
                body = Data()
            }
            self.currentDirective = .respond(
                SynthesizedResponse(status: status, headers: headers, body: body)
            )
        }
        anywhere.setObject(respondBlock, forKeyedSubscript: "respond" as NSString)

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
            guard let lo = iter.next() else {
                logger.warning("[MITM][JS] Anywhere.hex.decode: odd-length input; returning empty Data")
                return Data()
            }
            guard let h = hexNibble(hi), let l = hexNibble(lo) else {
                logger.warning("[MITM][JS] Anywhere.hex.decode: non-hex character in input; returning empty Data")
                return Data()
            }
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
