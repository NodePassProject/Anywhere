//
//  MITMScriptEngine.swift
//  Anywhere
//
//  Created by NodePassProject on 5/9/26.
//

import Foundation
import JavaScriptCore
import CryptoKit
import Security

private let logger = AnywhereLogger(category: "MITM")

/// Running total of bytes pinned by ``NoCopy`` Uint8Array allocations
/// across every ``MITMScriptEngine``. File-private (not a class
/// static) so the C-convention deallocator handed to
/// ``JSObjectMakeTypedArrayWithBytesNoCopy`` can reference the
/// symbol without capturing closure state, which the Swift compiler
/// forbids inside ``@convention(c)`` blocks.
private nonisolated(unsafe) var mitmScriptTypedArrayBytes: Int = 0
private let mitmScriptTypedArrayLock = UnfairLock()

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
/// synchronous call already running in JSC. We accept the consequence
/// by design, but its blast radius is bounded: invocations run off the
/// lwIP queue on ``MITMScriptTransform``'s serial script queue (the
/// calling connection parks while its JS runs), so a user-authored
/// ``process(ctx)`` that loops forever, recurses without bound, or
/// backtracks a pathological regex wedges only *its own* MITM
/// connection — every other flow in the tunnel keeps moving on the lwIP
/// queue. It does monopolize the shared JavaScript runtime, so other
/// connections' scripts queue behind it (their packet flow is
/// unaffected). Mitigation is on the authoring side — keep scripts
/// simple and bounded; the engine still reverts uncaught throws so a
/// script that fails partway leaves the wire untouched.
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
    /// ``CompiledMITMOperation``'s ``sourceKey``. The engine is shared by
    /// every connection to its rule set (see ``Provider``), so a script
    /// compiles once and is reused across connections; keying on a
    /// precomputed 64-bit hash keeps each lookup O(1) regardless of
    /// source size.
    ///
    /// The stored ``byteCount`` is a cheap collision guard.
    /// ``sourceCacheKey`` is a randomly-seeded ``Hasher`` output, so two
    /// distinct sources share a key only on a full 64-bit collision
    /// (~2^-64 per pair) — vanishing in practice. Confirming the stored
    /// length on a hit is O(1); comparing the whole source would be an
    /// O(n) walk on every JS call, the very cost this hash-keyed cache
    /// exists to avoid. A length mismatch recompiles under the same key;
    /// a same-length 64-bit collision is the only residual gap, not worth
    /// the per-call compare.
    private struct CompiledEntry {
        let byteCount: Int
        let function: JSValue
    }
    private var compiled: [Int: CompiledEntry] = [:]

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
    /// rule set owns one ``JSContext`` (see the engine registry on
    /// ``Provider``) so its script globals stay isolated from other rule
    /// sets, but the underlying heap, GC, and allocator are shared: a
    /// separate ``JSVirtualMachine`` per engine would multiply JSC's
    /// multi-MiB per-VM cost by every active rule set, which the Network
    /// Extension's ~50 MiB budget can't sustain under even modest
    /// concurrency. JSC serializes access to the heap with an internal
    /// mutex, so engines on independent queues are safe without an
    /// external lock.
    private static let sharedVM: JSVirtualMachine = JSVirtualMachine()!

    /// Defensive serialization around ``apply``/``applyFrame``. One engine
    /// is shared by every connection to its rule set, and all invocations
    /// are funneled through ``MITMScriptTransform``'s single serial script
    /// queue — off the lwIP queue, so a slow script parks its connection
    /// instead of stalling packet processing (see
    /// ``MITMScriptTransform/scriptQueue``). That serial queue already
    /// serializes calls, but the lock keeps the no-concurrent-re-entry
    /// contract enforceable at the engine boundary: it guards
    /// ``currentScope`` / ``currentDirective`` / ``compiled`` against a
    /// future refactor that runs invocations on a concurrent queue or a
    /// second VM. Cost is a single uncontended ``NSLock`` acquisition per
    /// call.
    private let invocationLock = NSLock()

    /// Threshold above which we ask JSC to GC after the next script
    /// invocation completes. 16 MiB leaves ample room for in-flight
    /// bodies in normal use while keeping the worst-case pin time
    /// short.
    private static let softTypedArrayBudget: Int = 16 * 1024 * 1024
    /// Hard cap on outstanding typed-array bytes. Past this we refuse
    /// new allocations and hand the script an empty Uint8Array.
    /// Bounds the worst-case NE memory cost across all engines
    /// regardless of GC pressure; the script will see truncated body
    /// bytes which is strictly better than the NE being OOM-killed.
    private static let hardTypedArrayBudget: Int = 32 * 1024 * 1024

    /// Re-entrancy guard for ``exceptionHandler``: formatting a thrown
    /// value for the log runs JS ``ToString``, which a script can
    /// override to throw and re-enter the handler. Only touched on the
    /// JS execution thread (serialized by ``invocationLock``), so a plain
    /// ``Bool`` suffices.
    private var isFormattingException = false

    init() {
        self.context = JSContext(virtualMachine: Self.sharedVM)
        // JSC's default exception handler writes the thrown value to
        // ``context.exception``; installing a custom handler REPLACES
        // that default, so we must reinstate the write ourselves or
        // every ``context.exception != nil`` check downstream sees
        // nil and the rollback path silently never fires.
        self.context.exceptionHandler = { [weak self] context, exception in
            // Restore the thrown value so downstream
            // ``context.exception != nil`` checks fire and the rollback
            // path runs — on every path, including the guard below.
            defer { context?.exception = exception }
            // Re-entrancy guard: formatting the value for the log runs JS
            // ``ToString`` (both ``-toString`` and ``JSValue.description``
            // route through it — there is no allocation-only formatter),
            // which a script can override to throw, re-entering this
            // handler. Without the guard that recurses and stack-grows the
            // NE process.
            if let self, self.isFormattingException {
                logger.warning("[MITM][JS] uncaught (nested throw while formatting exception)")
                return
            }
            self?.isFormattingException = true
            defer { self?.isFormattingException = false }
            if let exception {
                logger.warning("[MITM][JS] uncaught: \(String(describing: exception))")
            } else {
                logger.warning("[MITM][JS] uncaught: <unknown>")
            }
        }
        installAnywhereGlobals()
    }

    /// Runs ``source`` against ``message``. Returns the post-script
    /// message, or ``message`` unchanged when the script throws or
    /// otherwise fails to compile. ``sourceKey`` is the cache key
    /// computed at rule-compile time; equal keys imply equal sources.
    func apply(_ message: Message, source: String, sourceKey: Int) -> Outcome {
        invocationLock.lock()
        defer {
            invocationLock.unlock()
            collectIfBudgetExceeded()
        }
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

    /// Asks JSC to run GC when outstanding ``NoCopy`` Uint8Array bytes
    /// have crossed ``softTypedArrayBudget``. JSC's GC scheduler is
    /// otherwise driven by JS-heap accounting only and has no idea
    /// the native ``NoCopy`` buffers are pinning megabytes of host
    /// memory — without the explicit hint a chatty stream can fill
    /// the Network Extension's ~50 MiB budget long before JSC decides
    /// to collect on its own.
    private func collectIfBudgetExceeded() {
        let snapshot: Int = {
            mitmScriptTypedArrayLock.lock()
            defer { mitmScriptTypedArrayLock.unlock() }
            return mitmScriptTypedArrayBytes
        }()
        if snapshot >= Self.softTypedArrayBudget {
            JSGarbageCollect(context.jsGlobalContextRef)
        }
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
        invocationLock.lock()
        defer {
            invocationLock.unlock()
            collectIfBudgetExceeded()
        }
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

    /// Eagerly compiles ``source`` into the function cache so the first real
    /// ``apply``/``applyFrame`` that uses it skips the parse + compile step —
    /// and, for the first engine built process-wide, also absorbs the
    /// one-time ``JSVirtualMachine`` spin-up and ``Anywhere``-global install
    /// that ``init`` performs. Serialized with invocations via
    /// ``invocationLock`` and idempotent: a cache hit is a no-op, and a
    /// source that fails to compile is simply left uncached (it recompiles,
    /// still failing and logging once, on first real use). Execution is
    /// deliberately not triggered — running the user's ``process`` against a
    /// fabricated ctx could fire ``Anywhere.respond``, mutate the store, or
    /// loop without bound on the shared script queue.
    func precompile(source: String, sourceKey: Int) {
        invocationLock.lock()
        defer { invocationLock.unlock() }
        _ = compileIfNeeded(source, key: sourceKey)
    }

    private func compileIfNeeded(_ source: String, key: Int) -> JSValue? {
        let byteCount = source.utf8.count
        if let cached = compiled[key] {
            // Defensive collision guard. The cache is keyed on a 64-bit
            // ``Hasher`` output; two distinct sources can in theory
            // share a key (extremely unlikely, but not impossible).
            if cached.byteCount == byteCount { return cached.function }
            logger.warning("[MITM][JS] cache-key collision: recompiling under same key")
        }
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
        compiled[key] = CompiledEntry(byteCount: byteCount, function: value)
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

        // ``state`` is threaded across frames by the caller's
        // ``FrameCursor``. A ``JSValue`` is bound to the context it
        // was created in; using one inside a different context is
        // undefined behavior in JSC. Within a session the engine (and
        // thus the context) is stable, so this normally holds — but
        // guard defensively against a stale cursor that survived an
        // engine swap (rule reload / teardown race): if the
        // incoming ``state`` belongs to a different context, discard
        // it and start the script with a fresh state object rather
        // than risk a trap.
        let stateValue: JSValue
        if let state, state.context === context {
            stateValue = state
        } else {
            stateValue = JSValue(newObjectIn: context)!
        }
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
        // Use ``toDouble`` rather than ``toInt32``: the latter
        // silently truncates 64-bit-ish JS numbers (the result of
        // an overflowed integer expression, for example) modulo
        // 2^32, so ``ctx.status = 4_294_967_496`` would slip through
        // as 200 even though it's nonsense. Reject anything that
        // isn't a finite integer in the wire-status range.
        let d = value.toDouble()
        guard d.isFinite, d.rounded() == d else {
            logger.warning("[MITM][JS] ctx.status \(d) is not a finite integer; reverting")
            return original
        }
        let n = Int(d)
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
        // Iterate the ``JSValue`` array and call ``toString()`` on each
        // leaf so JSC's standard ``ToString`` runs (numbers → ``"42"``,
        // booleans → ``"true"``, objects → ``"[object …]"``) — stable,
        // predictable output that survives the validators below. Going
        // through ``value.toArray()`` instead would funnel each leaf
        // through the Obj-C bridge, which stringifies a JS number as
        // ``"Optional(42)"`` or a raw ``JSValue`` debug description —
        // values that then fail ``isValidHeaderName`` (dropping the
        // entry) or land on the wire verbatim from value position.
        guard value.isArray else { return nil }
        let length = Int(value.objectForKeyedSubscript("length")?.toInt32() ?? 0)
        if length == 0 { return [] }
        var result: [(name: String, value: String)] = []
        result.reserveCapacity(length)
        for i in 0..<length {
            guard let entry = value.objectAtIndexedSubscript(i),
                  entry.isArray,
                  let entryLen = entry.objectForKeyedSubscript("length")?.toInt32(),
                  entryLen == 2
            else {
                logger.warning("[MITM][JS] dropping ctx.headers entry that isn't a [name, value] pair")
                continue
            }
            guard let nameVal = entry.objectAtIndexedSubscript(0),
                  let valueVal = entry.objectAtIndexedSubscript(1),
                  !nameVal.isUndefined, !nameVal.isNull,
                  !valueVal.isUndefined, !valueVal.isNull,
                  let name = nameVal.toString(),
                  let val = valueVal.toString()
            else {
                logger.warning("[MITM][JS] dropping ctx.headers entry with null/undefined/non-stringifiable component")
                continue
            }
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
        installCodecGlobals(on: anywhere)
        installCryptoGlobals(on: anywhere)
        installJWTGlobals(on: anywhere)
        installJSONGlobals(on: anywhere)
        installStoreGlobals(on: anywhere)
        installLogGlobals(on: anywhere)
        installControlGlobals(on: anywhere)
        context.setObject(anywhere, forKeyedSubscript: "Anywhere" as NSString)
    }

    /// Installs ``Anywhere.codec`` — every paired encoder/decoder
    /// (byte-level + wire-format) lives here so scripts pull from a
    /// single place. Crypto, JWT, store, log, and the control
    /// directives stay top-level on ``Anywhere`` because they aren't
    /// encode/decode pairs.
    private func installCodecGlobals(on anywhere: JSValue) {
        let codec = JSValue(newObjectIn: context)!

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
        codec.setObject(utf8, forKeyedSubscript: "utf8" as NSString)

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
        codec.setObject(base64, forKeyedSubscript: "base64" as NSString)

        // Anywhere.base64url — RFC 4648 §5 unpadded base64url. Distinct
        // from base64 (``-``/``_`` instead of ``+``/``/``, no trailing
        // ``=`` padding); required for JWT, OAuth bearer tokens,
        // WebPush, and most modern web crypto. Encode emits the
        // canonical no-padding form; decode is lenient — it accepts
        // either alphabet and either padded or unpadded input because
        // tokens in the wild routinely arrive in mixed shapes (servers
        // forget to strip padding, clients re-encode through standard
        // base64, etc.).
        let base64url = JSValue(newObjectIn: context)!
        let base64URLEncodeBlock: @convention(block) (JSValue) -> String = { val in
            let ctx = JSContext.current()!
            return Self.encodeBase64URL(Self.bytesFromValue(val, in: ctx) ?? Data())
        }
        let base64URLDecodeBlock: @convention(block) (String) -> JSValue = { str in
            let ctx = JSContext.current()!
            return Self.makeUint8Array(in: ctx, from: Self.decodeBase64URL(str) ?? Data())
        }
        base64url.setObject(base64URLEncodeBlock, forKeyedSubscript: "encode" as NSString)
        base64url.setObject(base64URLDecodeBlock, forKeyedSubscript: "decode" as NSString)
        codec.setObject(base64url, forKeyedSubscript: "base64url" as NSString)

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
        codec.setObject(hex, forKeyedSubscript: "hex" as NSString)

        // Anywhere.protobuf — schema-free protobuf wire-format codec.
        // Targets the common rewrite case (flip one field, re-encode)
        // without forcing the rule to bundle a ~80 KiB protobuf.js
        // implementation in its script source — that bundle compiled
        // multi-ms per chain on the lwIP queue and was a recurring
        // source of JSC heap pressure in the extension's tight RAM
        // budget. ``decode`` returns a flat list of ``{field, wire,
        // value}`` entries preserving on-wire order (so repeated
        // fields come back as multiple entries the caller can iterate
        // or splice); ``encode`` takes the same shape back. Wire-0
        // (varint) values are BigInt so 64-bit IDs / timestamps round
        // trip losslessly; wire-1 / wire-5 (fixed64 / fixed32) values
        // are raw Uint8Array of length 8 / 4 because the script-level
        // interpretation (sfixed vs double vs uint) is a schema
        // concern this layer can't know — the script picks one with a
        // DataView. Nested messages and packed-repeated payloads land
        // as Uint8Array inside a wire-2 entry; recurse with
        // ``decode`` or split with ``decodeVarint`` to walk them.
        // Deprecated group wire types (3, 4) are rejected.
        let protobuf = JSValue(newObjectIn: context)!
        let pbDecodeBlock: @convention(block) (JSValue) -> JSValue = { val in
            let ctx = JSContext.current()!
            guard let bytes = Self.bytesFromValue(val, in: ctx) else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.decode: expected Uint8Array/ArrayBuffer/string",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            do {
                let entries = try Self.protobufDecodeWire(bytes)
                return Self.makeProtobufEntries(entries, in: ctx)
            } catch {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.decode: \(error)",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
        }
        let pbEncodeBlock: @convention(block) (JSValue) -> JSValue = { val in
            let ctx = JSContext.current()!
            do {
                let entries = try Self.parseProtobufEntries(val, in: ctx)
                return Self.makeUint8Array(in: ctx, from: Self.protobufEncodeWire(entries))
            } catch {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.encode: \(error)",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
        }
        // Single-varint primitives — useful when the script is walking
        // an embedded message by hand (e.g. picking the third packed
        // varint out of a wire-2 payload) and doesn't want to roundtrip
        // through ``decode``.
        let pbEncodeVarintBlock: @convention(block) (JSValue) -> JSValue = { val in
            let ctx = JSContext.current()!
            guard let u = Self.uint64FromJSValue(val) else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.encodeVarint: expected non-negative Number or BigInt",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            return Self.makeUint8Array(in: ctx, from: Self.writeVarint(u))
        }
        let pbDecodeVarintBlock: @convention(block) (JSValue, JSValue) -> JSValue = { bytesVal, offsetVal in
            let ctx = JSContext.current()!
            guard let bytes = Self.bytesFromValue(bytesVal, in: ctx) else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.decodeVarint: expected Uint8Array/ArrayBuffer/string",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            let offset: Int
            if offsetVal.isUndefined || offsetVal.isNull {
                offset = 0
            } else if offsetVal.isNumber {
                offset = Int(offsetVal.toInt32())
            } else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.decodeVarint: offset must be a Number",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            guard offset >= 0, offset <= bytes.count else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.decodeVarint: offset out of range",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            // Return null on truncated/malformed rather than throwing —
            // ``decodeVarint`` is the primitive scripts reach for when
            // probing unknown bytes, and null is easier to branch on
            // than a try/catch around a one-byte parse.
            guard let (value, end) = Self.readVarint(bytes, from: offset) else {
                return JSValue(nullIn: ctx)
            }
            let obj = JSValue(newObjectIn: ctx)!
            obj.setObject(Self.makeBigInt(value, in: ctx), forKeyedSubscript: "value" as NSString)
            obj.setObject(end - offset, forKeyedSubscript: "consumed" as NSString)
            return obj
        }
        protobuf.setObject(pbDecodeBlock, forKeyedSubscript: "decode" as NSString)
        protobuf.setObject(pbEncodeBlock, forKeyedSubscript: "encode" as NSString)
        protobuf.setObject(pbEncodeVarintBlock, forKeyedSubscript: "encodeVarint" as NSString)
        protobuf.setObject(pbDecodeVarintBlock, forKeyedSubscript: "decodeVarint" as NSString)
        codec.setObject(protobuf, forKeyedSubscript: "protobuf" as NSString)

        // Anywhere.codec.{gzip,deflate,brotli} — transport compression
        // codecs as encode/decode pairs (see ``installCompressionCodec``
        // for why a script needs these even though the pipeline already
        // auto-decodes the outer Content-Encoding).
        installCompressionCodec(on: codec, named: "gzip", codec: .gzip)
        installCompressionCodec(on: codec, named: "deflate", codec: .deflate)
        installCompressionCodec(on: codec, named: "brotli", codec: .brotli)

        anywhere.setObject(codec, forKeyedSubscript: "codec" as NSString)
    }

    /// Installs one `Anywhere.codec.<name>` transport-compression codec
    /// (gzip/deflate/brotli) as an encode/decode pair backed by
    /// ``MITMBodyCodec``. The transport pipeline already auto-decodes the
    /// outer `Content-Encoding` and re-emits identity, so scripts don't
    /// need these for the response body itself — they're for compression
    /// that pass never sees: a gzipped blob nested inside a JSON field, a
    /// brotli'd protobuf, re-compressing a body to hand to
    /// `Anywhere.respond`, or restoring a `Content-Encoding` the script
    /// wants to keep on the wire. Both directions accept
    /// Uint8Array/ArrayBuffer/string and return a Uint8Array. decode
    /// throws on malformed input or a payload that would exceed the
    /// ``MITMBodyCodec/maxBufferedBodyBytes`` decompression-bomb cap;
    /// encode throws only on internal codec failure (effectively never).
    private func installCompressionCodec(on codecNamespace: JSValue, named name: String, codec codecKind: MITMBodyCodec.Codec) {
        let obj = JSValue(newObjectIn: context)!
        let encodeBlock: @convention(block) (JSValue) -> JSValue = { val in
            let ctx = JSContext.current()!
            guard let bytes = Self.bytesFromValue(val, in: ctx) else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.codec.\(name).encode: expected Uint8Array/ArrayBuffer/string",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            guard let out = MITMBodyCodec.encode(bytes, codec: codecKind) else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.codec.\(name).encode failed", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
            return Self.makeUint8Array(in: ctx, from: out)
        }
        let decodeBlock: @convention(block) (JSValue) -> JSValue = { val in
            let ctx = JSContext.current()!
            guard let bytes = Self.bytesFromValue(val, in: ctx) else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.codec.\(name).decode: expected Uint8Array/ArrayBuffer/string",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            guard let out = MITMBodyCodec.decode(bytes, codec: codecKind) else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.codec.\(name).decode failed (malformed input or exceeds \(MITMBodyCodec.maxBufferedBodyBytes) B cap)",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            return Self.makeUint8Array(in: ctx, from: out)
        }
        obj.setObject(encodeBlock, forKeyedSubscript: "encode" as NSString)
        obj.setObject(decodeBlock, forKeyedSubscript: "decode" as NSString)
        codecNamespace.setObject(obj, forKeyedSubscript: name as NSString)
    }

    /// Installs ``Anywhere.crypto`` — hashes, HMAC, AES-GCM, random
    /// bytes, UUID. Top-level rather than under ``codec`` because
    /// cryptographic primitives aren't reversible encodings (hashes
    /// are one-way; HMAC has no decode side).
    private func installCryptoGlobals(on anywhere: JSValue) {
        // Anywhere.crypto — hashes, HMAC, secure random, UUID. Hash and
        // HMAC functions return raw digest bytes as a Uint8Array; the
        // script composes with ``Anywhere.codec.hex.encode`` /
        // ``Anywhere.codec.base64.encode`` to format. Key/data inputs accept
        // anything ``bytesFromValue`` understands (Uint8Array,
        // ArrayBuffer, or string — strings are UTF-8 encoded).
        let crypto = JSValue(newObjectIn: context)!
        let md5Block: @convention(block) (JSValue) -> JSValue = { val in
            let ctx = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: ctx) ?? Data()
            return Self.makeUint8Array(in: ctx, from: Data(Insecure.MD5.hash(data: bytes)))
        }
        let sha1Block: @convention(block) (JSValue) -> JSValue = { val in
            let ctx = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: ctx) ?? Data()
            return Self.makeUint8Array(in: ctx, from: Data(Insecure.SHA1.hash(data: bytes)))
        }
        let sha256Block: @convention(block) (JSValue) -> JSValue = { val in
            let ctx = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: ctx) ?? Data()
            return Self.makeUint8Array(in: ctx, from: Data(SHA256.hash(data: bytes)))
        }
        let sha384Block: @convention(block) (JSValue) -> JSValue = { val in
            let ctx = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: ctx) ?? Data()
            return Self.makeUint8Array(in: ctx, from: Data(SHA384.hash(data: bytes)))
        }
        let sha512Block: @convention(block) (JSValue) -> JSValue = { val in
            let ctx = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: ctx) ?? Data()
            return Self.makeUint8Array(in: ctx, from: Data(SHA512.hash(data: bytes)))
        }
        let hmacSHA1Block: @convention(block) (JSValue, JSValue) -> JSValue = { keyVal, dataVal in
            let ctx = JSContext.current()!
            let key = Self.bytesFromValue(keyVal, in: ctx) ?? Data()
            let data = Self.bytesFromValue(dataVal, in: ctx) ?? Data()
            let mac = HMAC<Insecure.SHA1>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Self.makeUint8Array(in: ctx, from: Data(mac))
        }
        let hmacSHA256Block: @convention(block) (JSValue, JSValue) -> JSValue = { keyVal, dataVal in
            let ctx = JSContext.current()!
            let key = Self.bytesFromValue(keyVal, in: ctx) ?? Data()
            let data = Self.bytesFromValue(dataVal, in: ctx) ?? Data()
            let mac = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Self.makeUint8Array(in: ctx, from: Data(mac))
        }
        let hmacSHA384Block: @convention(block) (JSValue, JSValue) -> JSValue = { keyVal, dataVal in
            let ctx = JSContext.current()!
            let key = Self.bytesFromValue(keyVal, in: ctx) ?? Data()
            let data = Self.bytesFromValue(dataVal, in: ctx) ?? Data()
            let mac = HMAC<SHA384>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Self.makeUint8Array(in: ctx, from: Data(mac))
        }
        let hmacSHA512Block: @convention(block) (JSValue, JSValue) -> JSValue = { keyVal, dataVal in
            let ctx = JSContext.current()!
            let key = Self.bytesFromValue(keyVal, in: ctx) ?? Data()
            let data = Self.bytesFromValue(dataVal, in: ctx) ?? Data()
            let mac = HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Self.makeUint8Array(in: ctx, from: Data(mac))
        }
        // randomBytes(n) — cap at 64 KiB so a script typo
        // (``randomBytes(1<<30)``) can't pin the extension's tiny RAM
        // budget. Non-integer / negative / oversized lengths throw a JS
        // error rather than coercing silently; the script sees a normal
        // catchable exception instead of a confused Uint8Array.
        let randomBytesBlock: @convention(block) (JSValue) -> JSValue = { lenVal in
            let ctx = JSContext.current()!
            let d = lenVal.toDouble()
            guard d.isFinite, d >= 0, d <= 65536, d == d.rounded() else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.crypto.randomBytes: length must be an integer in [0, 65536]",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            let n = Int(d)
            if n == 0 { return Self.makeUint8Array(in: ctx, from: Data()) }
            var bytes = [UInt8](repeating: 0, count: n)
            let status = bytes.withUnsafeMutableBufferPointer { buf in
                SecRandomCopyBytes(kSecRandomDefault, n, buf.baseAddress!)
            }
            guard status == errSecSuccess else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.crypto.randomBytes: SecRandomCopyBytes failed (status \(status))",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            return Self.makeUint8Array(in: ctx, from: Data(bytes))
        }
        // Lowercased to match the form most HTTP/JSON consumers emit;
        // scripts that need the uppercase variant can ``.toUpperCase()``.
        let uuidBlock: @convention(block) () -> String = {
            UUID().uuidString.lowercased()
        }
        crypto.setObject(md5Block, forKeyedSubscript: "md5" as NSString)
        crypto.setObject(sha1Block, forKeyedSubscript: "sha1" as NSString)
        crypto.setObject(sha256Block, forKeyedSubscript: "sha256" as NSString)
        crypto.setObject(sha384Block, forKeyedSubscript: "sha384" as NSString)
        crypto.setObject(sha512Block, forKeyedSubscript: "sha512" as NSString)
        crypto.setObject(hmacSHA1Block, forKeyedSubscript: "hmacSHA1" as NSString)
        crypto.setObject(hmacSHA256Block, forKeyedSubscript: "hmacSHA256" as NSString)
        crypto.setObject(hmacSHA384Block, forKeyedSubscript: "hmacSHA384" as NSString)
        crypto.setObject(hmacSHA512Block, forKeyedSubscript: "hmacSHA512" as NSString)
        crypto.setObject(randomBytesBlock, forKeyedSubscript: "randomBytes" as NSString)
        crypto.setObject(uuidBlock, forKeyedSubscript: "uuid" as NSString)

        // Anywhere.crypto.aesGCM — authenticated encryption (AEAD).
        // Unlocks the class of E2E-encrypted-body rewrites used by
        // many app APIs (WeChat / NetEase / Bilibili and most modern
        // mobile SDKs ship AES-GCM-wrapped JSON over HTTPS); without
        // this the script can see the encrypted blob but can't read or
        // mutate it. The spec object accepts:
        //   - key:       Uint8Array of 16, 24, or 32 bytes (AES-128/192/256)
        //   - nonce:     Uint8Array (12-byte standard); omit on encrypt
        //                and the runtime generates a fresh random nonce
        //                per call (and returns it on the result).
        //   - plaintext / ciphertext: Uint8Array (string accepted, UTF-8 encoded)
        //   - tag:       Uint8Array of 16 bytes (decrypt only)
        //   - aad:       Uint8Array (optional, additional authenticated data)
        // Decrypt throws a catchable JS error on auth failure (wrong
        // key, tampered ciphertext, mismatched AAD) so the rule chain
        // sees a normal try/catch rather than a wedged stream.
        let aesGCM = JSValue(newObjectIn: context)!
        let aesGCMEncryptBlock: @convention(block) (JSValue) -> JSValue = { spec in
            let ctx = JSContext.current()!
            guard !spec.isUndefined, !spec.isNull else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: expected a spec object", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
            guard let key = Self.bytesFromValue(spec.objectForKeyedSubscript("key"), in: ctx),
                  key.count == 16 || key.count == 24 || key.count == 32 else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: key must be a Uint8Array of length 16, 24, or 32", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
            guard let plaintext = Self.bytesFromValue(spec.objectForKeyedSubscript("plaintext"), in: ctx) else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: plaintext must be Uint8Array/ArrayBuffer/string", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
            let nonceData: Data?
            let nonceVal = spec.objectForKeyedSubscript("nonce")
            if let nonceVal, !nonceVal.isUndefined, !nonceVal.isNull {
                guard let n = Self.bytesFromValue(nonceVal, in: ctx) else {
                    ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: nonce must be Uint8Array/ArrayBuffer/string", in: ctx)
                    return JSValue(undefinedIn: ctx)
                }
                nonceData = n
            } else {
                nonceData = nil
            }
            let aadData: Data?
            let aadVal = spec.objectForKeyedSubscript("aad")
            if let aadVal, !aadVal.isUndefined, !aadVal.isNull {
                guard let a = Self.bytesFromValue(aadVal, in: ctx) else {
                    ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: aad must be Uint8Array/ArrayBuffer/string", in: ctx)
                    return JSValue(undefinedIn: ctx)
                }
                aadData = a
            } else {
                aadData = nil
            }
            do {
                let symKey = SymmetricKey(data: key)
                let nonce: AES.GCM.Nonce
                if let nonceData {
                    nonce = try AES.GCM.Nonce(data: nonceData)
                } else {
                    nonce = AES.GCM.Nonce()
                }
                let box: AES.GCM.SealedBox
                if let aadData {
                    box = try AES.GCM.seal(plaintext, using: symKey, nonce: nonce, authenticating: aadData)
                } else {
                    box = try AES.GCM.seal(plaintext, using: symKey, nonce: nonce)
                }
                let out = JSValue(newObjectIn: ctx)!
                out.setObject(Self.makeUint8Array(in: ctx, from: Data(box.nonce)), forKeyedSubscript: "nonce" as NSString)
                out.setObject(Self.makeUint8Array(in: ctx, from: box.ciphertext), forKeyedSubscript: "ciphertext" as NSString)
                out.setObject(Self.makeUint8Array(in: ctx, from: box.tag), forKeyedSubscript: "tag" as NSString)
                return out
            } catch {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: \(error)", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
        }
        let aesGCMDecryptBlock: @convention(block) (JSValue) -> JSValue = { spec in
            let ctx = JSContext.current()!
            guard !spec.isUndefined, !spec.isNull else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: expected a spec object", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
            guard let key = Self.bytesFromValue(spec.objectForKeyedSubscript("key"), in: ctx),
                  key.count == 16 || key.count == 24 || key.count == 32 else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: key must be a Uint8Array of length 16, 24, or 32", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
            guard let nonce = Self.bytesFromValue(spec.objectForKeyedSubscript("nonce"), in: ctx) else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: nonce must be Uint8Array/ArrayBuffer/string", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
            guard let ciphertext = Self.bytesFromValue(spec.objectForKeyedSubscript("ciphertext"), in: ctx) else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: ciphertext must be Uint8Array/ArrayBuffer/string", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
            guard let tag = Self.bytesFromValue(spec.objectForKeyedSubscript("tag"), in: ctx),
                  tag.count == 16 else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: tag must be a Uint8Array of length 16", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
            let aadData: Data?
            let aadVal = spec.objectForKeyedSubscript("aad")
            if let aadVal, !aadVal.isUndefined, !aadVal.isNull {
                guard let a = Self.bytesFromValue(aadVal, in: ctx) else {
                    ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: aad must be Uint8Array/ArrayBuffer/string", in: ctx)
                    return JSValue(undefinedIn: ctx)
                }
                aadData = a
            } else {
                aadData = nil
            }
            do {
                let symKey = SymmetricKey(data: key)
                let gcmNonce = try AES.GCM.Nonce(data: nonce)
                let box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
                let plaintext: Data
                if let aadData {
                    plaintext = try AES.GCM.open(box, using: symKey, authenticating: aadData)
                } else {
                    plaintext = try AES.GCM.open(box, using: symKey)
                }
                return Self.makeUint8Array(in: ctx, from: plaintext)
            } catch {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: \(error)", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
        }
        aesGCM.setObject(aesGCMEncryptBlock, forKeyedSubscript: "encrypt" as NSString)
        aesGCM.setObject(aesGCMDecryptBlock, forKeyedSubscript: "decrypt" as NSString)
        crypto.setObject(aesGCM, forKeyedSubscript: "aesGCM" as NSString)
        anywhere.setObject(crypto, forKeyedSubscript: "crypto" as NSString)
    }

    /// Installs ``Anywhere.jwt`` — JWT compact serialization codec.
    /// Stays top-level (not under ``codec``) because it's a composite
    /// that already depends on base64url + JSON and is more
    /// recognizable to script authors at the top level.
    private func installJWTGlobals(on anywhere: JSValue) {
        // Anywhere.jwt — JWT compact serialization (RFC 7519 / 7515).
        // Pure-codec: no signature verification or ``alg`` enforcement
        // is performed here — the script does that itself with the
        // HMAC/hash helpers and the key it already has. ``decode``
        // splits the token on ``.``, base64url-decodes each segment,
        // JSON-parses the header (required) and the payload
        // (best-effort — opaque JWS payloads round-trip as
        // Uint8Array), and returns ``signingInput`` (the literal
        // ``header.payload`` octet string per RFC 7515 §5.1) so the
        // script can recompute and compare the signature without
        // re-base64url-ing anything. ``encode`` glues the three
        // segments back together: header/payload that look like bytes
        // (Uint8Array / ArrayBuffer / string) are emitted verbatim;
        // anything else is JSON.stringify'd first. Signature is the
        // raw signature bytes — the script computes it (HMAC for HS*,
        // private-key sign for RS*/ES*/EdDSA) and passes the bytes
        // through.
        let jwt = JSValue(newObjectIn: context)!
        let jwtDecodeBlock: @convention(block) (String) -> JSValue = { token in
            let ctx = JSContext.current()!
            let parts = token.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count == 2 || parts.count == 3 else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.jwt.decode: expected 2 or 3 dot-separated segments, got \(parts.count)",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            guard let headerBytes = Self.decodeBase64URL(String(parts[0])) else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.jwt.decode: header is not valid base64url", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
            guard let payloadBytes = Self.decodeBase64URL(String(parts[1])) else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.jwt.decode: payload is not valid base64url", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
            let signatureBytes: Data
            if parts.count == 3 {
                guard let sig = Self.decodeBase64URL(String(parts[2])) else {
                    ctx.exception = JSValue(newErrorFromMessage: "Anywhere.jwt.decode: signature is not valid base64url", in: ctx)
                    return JSValue(undefinedIn: ctx)
                }
                signatureBytes = sig
            } else {
                signatureBytes = Data()
            }
            // Header MUST be JSON per RFC 7519 §5 — a JWT without a
            // JSON header isn't a JWT.
            guard let headerStr = String(data: headerBytes, encoding: .utf8),
                  let headerObj = Self.parseJSON(headerStr, in: ctx) else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.jwt.decode: header is not valid JSON", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
            // Payload: try JSON; fall back to raw bytes. Unsigned JWS
            // tokens occasionally carry a binary payload (RFC 7797),
            // so silently coercing to a Uint8Array is friendlier than
            // throwing.
            let payloadVal: JSValue
            if let payloadStr = String(data: payloadBytes, encoding: .utf8),
               let parsed = Self.parseJSON(payloadStr, in: ctx) {
                payloadVal = parsed
            } else {
                payloadVal = Self.makeUint8Array(in: ctx, from: payloadBytes)
            }
            let signingInput = "\(parts[0]).\(parts[1])"
            let result = JSValue(newObjectIn: ctx)!
            result.setObject(headerObj, forKeyedSubscript: "header" as NSString)
            result.setObject(payloadVal, forKeyedSubscript: "payload" as NSString)
            result.setObject(Self.makeUint8Array(in: ctx, from: signatureBytes), forKeyedSubscript: "signature" as NSString)
            result.setObject(Self.makeUint8Array(in: ctx, from: Data(signingInput.utf8)), forKeyedSubscript: "signingInput" as NSString)
            return result
        }
        let jwtEncodeBlock: @convention(block) (JSValue) -> JSValue = { spec in
            let ctx = JSContext.current()!
            guard !spec.isUndefined, !spec.isNull else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.jwt.encode: expected a spec object with {header, payload, signature?}",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            guard let headerSeg = Self.encodeJWTSegment(spec.objectForKeyedSubscript("header"), in: ctx) else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.jwt.encode: header must be an object, string, or Uint8Array",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            guard let payloadSeg = Self.encodeJWTSegment(spec.objectForKeyedSubscript("payload"), in: ctx) else {
                ctx.exception = JSValue(
                    newErrorFromMessage: "Anywhere.jwt.encode: payload must be an object, string, or Uint8Array",
                    in: ctx
                )
                return JSValue(undefinedIn: ctx)
            }
            let signatureSeg: String
            let sigVal = spec.objectForKeyedSubscript("signature")
            if let sigVal, !sigVal.isUndefined, !sigVal.isNull {
                guard let sigBytes = Self.bytesFromValue(sigVal, in: ctx) else {
                    ctx.exception = JSValue(
                        newErrorFromMessage: "Anywhere.jwt.encode: signature must be a Uint8Array (the raw signature bytes)",
                        in: ctx
                    )
                    return JSValue(undefinedIn: ctx)
                }
                signatureSeg = Self.encodeBase64URL(sigBytes)
            } else {
                // RFC 7515 compact serialization keeps the trailing dot
                // for the empty signature so verifiers can still split
                // on count == 3.
                signatureSeg = ""
            }
            return JSValue(object: "\(headerSeg).\(payloadSeg).\(signatureSeg)", in: ctx)
        }
        jwt.setObject(jwtDecodeBlock, forKeyedSubscript: "decode" as NSString)
        jwt.setObject(jwtEncodeBlock, forKeyedSubscript: "encode" as NSString)
        anywhere.setObject(jwt, forKeyedSubscript: "jwt" as NSString)
    }

    /// One step of a parsed JSONPath. Only the two shapes the path
    /// helpers actually need: an object member (``.key``) and an array
    /// element (``.index``). No wildcards or ``..`` descent — recursive
    /// matching is a separate concern handled by ``replaceRecursive`` /
    /// ``deleteRecursive``, which take a bare key name instead of a path.
    private enum JSONPathSegment {
        case key(String)
        case index(Int)
    }

    /// What ``applyAtPath`` does to the addressed leaf.
    private enum JSONLeafMode { case add, replace, delete }

    /// Installs ``Anywhere.json`` — byte-oriented JSON body editing.
    ///
    /// Every method is bytes-in / bytes-out: the first argument is the
    /// body (``Uint8Array``, ``ArrayBuffer``, or string), the return is
    /// a fresh ``Uint8Array`` of the re-serialized JSON. The document is
    /// parsed once per call and emitted compact (no pretty-printing —
    /// it's going on the wire); callers that chain several edits just
    /// feed one result into the next.
    ///
    /// The contract is deliberately total: a body that isn't JSON, a
    /// path that doesn't resolve, a type mismatch (e.g. an object key
    /// addressed into an array), or a value that can't be re-serialized
    /// all yield the body **unchanged** rather than throwing. A rewrite
    /// rule routinely fires on responses whose shape it doesn't fully
    /// control, and a thrown error there would abort the whole script
    /// for the connection; a silent pass-through degrades to a no-op
    /// instead.
    ///
    /// Path methods (``add`` / ``replace`` / ``delete``) take a JSONPath
    /// like ``"$.data.items[0].id"`` (leading ``$`` optional; dotted
    /// keys and ``[index]`` / ``["key"]`` brackets). The recursive
    /// methods take a **bare key name** matched at every depth, not a
    /// path. The ``removeWhere…`` methods take a path to an array and
    /// drop the elements that match.
    private func installJSONGlobals(on anywhere: JSValue) {
        let json = JSValue(newObjectIn: context)!

        // add(body, path, value) — upsert. Creates the addressed member
        // (or overwrites it if already present); for an array index it
        // sets in range or appends when the index equals the length.
        let addBlock: @convention(block) (JSValue, String, JSValue) -> JSValue = { body, path, value in
            let ctx = JSContext.current()!
            guard let v = Self.jsonValue(from: value, in: ctx) else {
                logger.warning("[MITM][JS] Anywhere.json.add: value is undefined; use delete() to remove a field. Body unchanged.")
                return Self.jsonPassthrough(body, in: ctx)
            }
            guard let segments = Self.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.add: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            return Self.runJSONOp(body, in: ctx) { root in
                root = Self.applyAtPath(root, segments: segments, mode: .add, value: v)
            }
        }

        // replace(body, path, value) — modify-in-place. Unlike add, does
        // nothing when the addressed member/index doesn't already exist,
        // so it can't accidentally introduce fields.
        let replaceBlock: @convention(block) (JSValue, String, JSValue) -> JSValue = { body, path, value in
            let ctx = JSContext.current()!
            guard let v = Self.jsonValue(from: value, in: ctx) else {
                logger.warning("[MITM][JS] Anywhere.json.replace: value is undefined; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            guard let segments = Self.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.replace: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            return Self.runJSONOp(body, in: ctx) { root in
                root = Self.applyAtPath(root, segments: segments, mode: .replace, value: v)
            }
        }

        // replaceRecursive(body, key, value) — replace the value of every
        // property named `key`, at any depth. The second argument is a
        // literal key name, NOT a path: existing occurrences are
        // overwritten in place; the key is never created where absent.
        let replaceRecursiveBlock: @convention(block) (JSValue, String, JSValue) -> JSValue = { body, key, value in
            let ctx = JSContext.current()!
            guard let v = Self.jsonValue(from: value, in: ctx) else {
                logger.warning("[MITM][JS] Anywhere.json.replaceRecursive: value is undefined; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            return Self.runJSONOp(body, in: ctx) { root in
                Self.replaceKeyRecursive(root, key: key, value: v)
            }
        }

        // delete(body, path) — remove the addressed member/element.
        let deleteBlock: @convention(block) (JSValue, String) -> JSValue = { body, path in
            let ctx = JSContext.current()!
            guard let segments = Self.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.delete: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            return Self.runJSONOp(body, in: ctx) { root in
                root = Self.applyAtPath(root, segments: segments, mode: .delete, value: nil)
            }
        }

        // deleteRecursive(body, key) — remove every property named `key`,
        // at any depth. Bare key name, not a path (mirror of
        // replaceRecursive).
        let deleteRecursiveBlock: @convention(block) (JSValue, String) -> JSValue = { body, key in
            let ctx = JSContext.current()!
            return Self.runJSONOp(body, in: ctx) { root in
                Self.deleteKeyRecursive(root, key: key)
            }
        }

        // removeWhereKeyExists(body, path, key) — at the array addressed
        // by `path`, drop every element that is an object containing
        // `key`. Non-object elements (and objects lacking the key) are
        // kept. No-op if the path doesn't resolve to an array.
        let removeWhereKeyExistsBlock: @convention(block) (JSValue, String, String) -> JSValue = { body, path, key in
            let ctx = JSContext.current()!
            guard let segments = Self.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.removeWhereKeyExists: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            return Self.runJSONOp(body, in: ctx) { root in
                guard let array = Self.resolveNode(root, segments: segments) as? NSMutableArray else { return }
                let kept = array.filter { ($0 as? NSDictionary)?.object(forKey: key) == nil }
                array.setArray(kept)
            }
        }

        // removeWhereFieldIn(body, path, field, values) — at the array
        // addressed by `path`, drop every element that is an object whose
        // `field` equals one of `values` (JSON-value equality; `values`
        // may be an array or a lone scalar). Elements without `field` are
        // kept. No-op if the path doesn't resolve to an array.
        let removeWhereFieldInBlock: @convention(block) (JSValue, String, String, JSValue) -> JSValue = { body, path, field, valuesVal in
            let ctx = JSContext.current()!
            guard let segments = Self.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.removeWhereFieldIn: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            let needles = Self.jsonArrayValues(from: valuesVal, in: ctx)
            return Self.runJSONOp(body, in: ctx) { root in
                guard let array = Self.resolveNode(root, segments: segments) as? NSMutableArray else { return }
                let kept = array.filter { element in
                    guard let object = element as? NSDictionary,
                          let fieldValue = object.object(forKey: field) else { return true }
                    return !needles.contains { Self.jsonValueEquals($0, fieldValue) }
                }
                array.setArray(kept)
            }
        }

        json.setObject(addBlock, forKeyedSubscript: "add" as NSString)
        json.setObject(replaceBlock, forKeyedSubscript: "replace" as NSString)
        json.setObject(replaceRecursiveBlock, forKeyedSubscript: "replaceRecursive" as NSString)
        json.setObject(deleteBlock, forKeyedSubscript: "delete" as NSString)
        json.setObject(deleteRecursiveBlock, forKeyedSubscript: "deleteRecursive" as NSString)
        json.setObject(removeWhereKeyExistsBlock, forKeyedSubscript: "removeWhereKeyExists" as NSString)
        json.setObject(removeWhereFieldInBlock, forKeyedSubscript: "removeWhereFieldIn" as NSString)
        anywhere.setObject(json, forKeyedSubscript: "json" as NSString)
    }

    // MARK: - Anywhere.json internals (static so the JSC closures above
    // don't capture self)

    /// Bytes → parsed JSON → ``mutate`` → bytes. The single choke point
    /// every ``Anywhere.json`` method routes through, so the
    /// parse-once / emit-compact / pass-through-on-failure contract lives
    /// in exactly one place. ``mutate`` receives the root as ``inout`` so
    /// an op can both edit a container in place (the common case) and
    /// swap the root wholesale (a ``$``-targeted replace).
    private static func runJSONOp(_ body: JSValue, in ctx: JSContext, _ mutate: (inout Any) -> Void) -> JSValue {
        let original = bytesFromValue(body, in: ctx) ?? Data()
        guard var root = jsonParse(original) else {
            return makeUint8Array(in: ctx, from: original)
        }
        mutate(&root)
        guard let out = jsonSerialize(root) else {
            logger.warning("[MITM][JS] Anywhere.json: edited value is not serializable; body unchanged")
            return makeUint8Array(in: ctx, from: original)
        }
        return makeUint8Array(in: ctx, from: out)
    }

    /// Returns the body bytes verbatim as a fresh ``Uint8Array`` — used
    /// for the early-out paths (undefined value, malformed path) so a
    /// rejected edit leaves even the byte layout untouched, rather than
    /// silently re-emitting a body we never actually changed.
    private static func jsonPassthrough(_ body: JSValue, in ctx: JSContext) -> JSValue {
        makeUint8Array(in: ctx, from: bytesFromValue(body, in: ctx) ?? Data())
    }

    /// ``JSON.parse`` via Foundation, with mutable containers so the ops
    /// can edit nodes in place and ``.fragmentsAllowed`` so a top-level
    /// scalar body (``42``, ``"x"``, ``true``) still parses. Returns nil
    /// for empty or malformed input.
    private static func jsonParse(_ data: Data) -> Any? {
        guard !data.isEmpty else { return nil }
        return try? JSONSerialization.jsonObject(with: data, options: [.mutableContainers, .fragmentsAllowed])
    }

    /// ``JSON.stringify`` via Foundation. Compact, slashes left
    /// unescaped to match how servers actually emit URLs in JSON, and
    /// ``.fragmentsAllowed`` to round-trip a scalar root. Returns nil
    /// when the graph can't be represented as JSON (a NaN/∞
    /// ``NSNumber``, a stray ``NSDate`` from a value conversion, a
    /// non-string dictionary key), which the caller turns into a
    /// body-unchanged pass-through.
    private static func jsonSerialize(_ object: Any) -> Data? {
        return try? JSONSerialization.data(withJSONObject: object, options: [.fragmentsAllowed, .withoutEscapingSlashes])
    }

    /// Converts a script-supplied value into its Foundation JSON form.
    /// ``undefined`` maps to nil (the caller treats that as "no value
    /// given"); ``null`` maps to ``NSNull``. Everything else rides
    /// ``JSValue/toObject`` — JSON-shaped inputs become
    /// ``NSNumber`` / ``NSString`` / ``NSArray`` / ``NSDictionary``;
    /// anything exotic survives only until ``jsonSerialize`` rejects it.
    private static func jsonValue(from value: JSValue, in ctx: JSContext) -> Any? {
        if value.isUndefined { return nil }
        if value.isNull { return NSNull() }
        return value.toObject()
    }

    /// Normalizes the ``values`` argument of ``removeWhereFieldIn`` into
    /// a Swift array: a JS array becomes its elements, a lone scalar
    /// becomes a one-element array (so ``removeWhereFieldIn(b, p, f, "x")``
    /// works as well as the array form), undefined/null becomes empty.
    private static func jsonArrayValues(from value: JSValue, in ctx: JSContext) -> [Any] {
        if value.isUndefined || value.isNull { return [] }
        if value.isArray, let array = value.toArray() { return array }
        if let single = jsonValue(from: value, in: ctx) { return [single] }
        return []
    }

    /// JSON-value equality for the ``removeWhere…`` predicates. Both
    /// sides are Foundation JSON leaves (``NSNumber`` / ``NSString`` /
    /// ``NSNull``), so ``isEqual`` is exactly right — and it treats ``1``
    /// and ``1.0`` as equal, which is what a script comparing against a
    /// numeric literal expects.
    private static func jsonValueEquals(_ lhs: Any, _ rhs: Any) -> Bool {
        return (lhs as AnyObject).isEqual(rhs)
    }

    /// Splits a JSONPath into segments. Tolerant by design: a leading
    /// ``$`` is optional, brackets accept a bare or quoted key or a
    /// numeric index, and a path written without the ``$.`` prefix
    /// (``"data.items"``) still parses. Returns nil only for genuinely
    /// malformed input — an empty dotted segment (``"a..b"``, a trailing
    /// ``"."``) or an empty ``"[]"`` — so the caller can warn instead of
    /// silently addressing the wrong node. An empty result (``"$"`` or
    /// ``""``) means "the document root".
    private static func parseJSONPath(_ raw: String) -> [JSONPathSegment]? {
        var segments: [JSONPathSegment] = []
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
    /// segments index an array (bounds-checked). Any other pairing — a
    /// key into an array, an index into an object, a step off the end, a
    /// step into a scalar — returns nil, which unwinds the whole walk to
    /// a no-op.
    private static func childNode(_ node: Any?, _ segment: JSONPathSegment) -> Any? {
        guard let node else { return nil }
        switch segment {
        case .key(let key):
            return (node as? NSDictionary)?.object(forKey: key)
        case .index(let index):
            guard let array = node as? NSArray, index >= 0, index < array.count else { return nil }
            return array[index]
        }
    }

    /// Resolves a full path to its node (or nil). Empty segments means
    /// the root. Used by the ``removeWhere…`` ops to find the target
    /// array.
    private static func resolveNode(_ root: Any, segments: [JSONPathSegment]) -> Any? {
        var node: Any? = root
        for segment in segments {
            node = childNode(node, segment)
        }
        return node
    }

    /// Applies add/replace/delete at the leaf of ``segments``. Walks to
    /// the leaf's parent container, then acts per ``mode``. Returns the
    /// root — usually the same object mutated in place, except an
    /// empty-path add/replace which swaps the root for ``value``. Every
    /// miss (absent parent, wrong container type, out-of-range index) is
    /// a no-op.
    private static func applyAtPath(_ root: Any, segments: [JSONPathSegment], mode: JSONLeafMode, value: Any?) -> Any {
        if segments.isEmpty {
            switch mode {
            case .add, .replace: return value ?? root
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
                if let value { dictionary.setObject(value, forKey: key as NSString) }
            case .replace:
                if dictionary.object(forKey: key) != nil, let value {
                    dictionary.setObject(value, forKey: key as NSString)
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
                    if index >= 0, index < count { array.replaceObject(at: index, with: value) }
                    else if index == count { array.add(value) }
                }
            case .replace:
                if let value, index >= 0, index < count { array.replaceObject(at: index, with: value) }
            case .delete:
                if index >= 0, index < count { array.removeObject(at: index) }
            }
        }
        return root
    }

    /// Overwrites every ``key`` member at any depth with ``value``.
    /// Children are visited before the key is set so the replacement is
    /// never itself descended into; the key is only overwritten where it
    /// already exists (recursive replace, not recursive insert).
    private static func replaceKeyRecursive(_ node: Any?, key: String, value: Any) {
        if let dictionary = node as? NSMutableDictionary {
            for k in dictionary.allKeys {
                guard let ks = k as? String, ks != key else { continue }
                replaceKeyRecursive(dictionary.object(forKey: ks), key: key, value: value)
            }
            if dictionary.object(forKey: key) != nil {
                dictionary.setObject(value, forKey: key as NSString)
            }
        } else if let array = node as? NSMutableArray {
            for element in array { replaceKeyRecursive(element, key: key, value: value) }
        }
    }

    /// Removes every ``key`` member at any depth, then recurses into what
    /// remains.
    private static func deleteKeyRecursive(_ node: Any?, key: String) {
        if let dictionary = node as? NSMutableDictionary {
            dictionary.removeObject(forKey: key)
            for k in dictionary.allKeys {
                if let ks = k as? String { deleteKeyRecursive(dictionary.object(forKey: ks), key: key) }
            }
        } else if let array = node as? NSMutableArray {
            for element in array { deleteKeyRecursive(element, key: key) }
        }
    }

    /// Installs ``Anywhere.store`` — per-rule-set persistent key/value
    /// state. ``[weak self]`` on each block so the JSC-held closures
    /// don't retain the engine.
    private func installStoreGlobals(on anywhere: JSValue) {
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
    }

    /// Installs ``Anywhere.log`` — info/warning/error/debug bridged to
    /// the shared ``AnywhereLogger`` instance for this file.
    private func installLogGlobals(on anywhere: JSValue) {
        // Anywhere.log.{info,warning,error,debug}(message) — writes
        // through ``AnywhereLogger``. ``info``/``warning``/``error`` also
        // forward to the user-facing log viewer via the static
        // ``logSink`` the Network Extension installs; ``debug`` is
        // os.log-only and compiles to a no-op in release. Each line is
        // prefixed with ``[MITM][JS]`` to match the engine's own
        // diagnostic lines, so scripts and engine output share one
        // grep target.
        let log = JSValue(newObjectIn: context)!
        let logInfo: @convention(block) (String) -> Void = { msg in
            logger.info("[MITM][JS] \(msg)")
        }
        let logWarning: @convention(block) (String) -> Void = { msg in
            logger.warning("[MITM][JS] \(msg)")
        }
        let logError: @convention(block) (String) -> Void = { msg in
            logger.error("[MITM][JS] \(msg)")
        }
        let logDebug: @convention(block) (String) -> Void = { msg in
            logger.debug("[MITM][JS] \(msg)")
        }
        log.setObject(logInfo, forKeyedSubscript: "info" as NSString)
        log.setObject(logWarning, forKeyedSubscript: "warning" as NSString)
        log.setObject(logError, forKeyedSubscript: "error" as NSString)
        log.setObject(logDebug, forKeyedSubscript: "debug" as NSString)
        anywhere.setObject(log, forKeyedSubscript: "log" as NSString)
    }

    /// Installs the control directives ``Anywhere.done`` / ``exit`` /
    /// ``respond``. ``[weak self]`` on each block (same reason as
    /// ``installStoreGlobals``).
    private func installControlGlobals(on anywhere: JSValue) {
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
                // ``toDouble`` (not ``toInt32``) so a 64-bit-ish JS
                // number can't truncate modulo 2^32 into a valid-
                // looking status (e.g. 4_294_967_496 → 200).
                let d = statusVal.toDouble()
                let raw = (d.isFinite && d.rounded() == d) ? Int(d) : -1
                if (100...599).contains(raw) {
                    status = raw
                } else {
                    logger.warning("[MITM][JS] Anywhere.respond status \(d) out of 100…599; using 200")
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
                // Use the currently-executing context for byte
                // extraction, matching every sibling helper block
                // (which all read ``JSContext.current()``). The two are
                // the same context today, but reading ``self.context``
                // here would be an inconsistency that breaks if a
                // child/worker context is ever introduced.
                let ctx = JSContext.current() ?? self.context
                body = Self.bytesFromValue(bodyVal, in: ctx) ?? Data()
            } else {
                body = Data()
            }
            self.currentDirective = .respond(
                SynthesizedResponse(status: status, headers: headers, body: body)
            )
        }
        anywhere.setObject(respondBlock, forKeyedSubscript: "respond" as NSString)
    }

    // MARK: - Body bridging (static so closures don't capture self)

    private static func makeUint8Array(in context: JSContext, from data: Data) -> JSValue {
        let count = data.count
        // Hard cap: if we've already pinned ``hardTypedArrayBudget``
        // bytes across all engines, refuse the allocation and return
        // an empty view. JSC's GC may free the existing pins shortly,
        // but until it does, growing further risks an NE OOM-kill
        // (which would take down every active tunnel session). The
        // script sees a smaller-than-expected body, which the user
        // can debug; the alternative is a hard crash.
        let projected: Int = {
            mitmScriptTypedArrayLock.lock()
            defer { mitmScriptTypedArrayLock.unlock() }
            return mitmScriptTypedArrayBytes + count
        }()
        if projected > hardTypedArrayBudget && count > 0 {
            logger.warning("[MITM][JS] typed-array budget exhausted (\(projected) B > \(hardTypedArrayBudget) B); returning empty Uint8Array")
            // Recurse with empty data so we still hand the script a
            // valid Uint8Array reference (zero-length); the
            // recursion bypasses the cap because count=0.
            return makeUint8Array(in: context, from: Data())
        }
        // Always allocate at least one byte so the deallocator has a
        // valid pointer to free; JSC accepts a zero-length view fine.
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: max(count, 1), alignment: 1)
        if count > 0 {
            data.copyBytes(to: buffer.assumingMemoryBound(to: UInt8.self), count: count)
        }
        // Capture the allocation in the budget; the deallocator
        // (called by JSC when it reclaims the typed array) subtracts.
        if count > 0 {
            mitmScriptTypedArrayLock.lock()
            mitmScriptTypedArrayBytes += count
            mitmScriptTypedArrayLock.unlock()
        }
        // ``JSTypedArrayBytesDeallocator`` is a C function pointer —
        // `(bytes, deallocatorContext) -> Void` — that can't capture
        // closure state. Pass the byte count via the
        // ``deallocatorContext`` pointer (heap-allocated ``Int`` box)
        // so the deallocator can subtract the right amount from the
        // file-private counter (which IS reachable from the C-convention
        // closure because it's a global symbol, not a capture).
        let lengthBox = UnsafeMutablePointer<Int>.allocate(capacity: 1)
        lengthBox.initialize(to: count)
        let deallocator: JSTypedArrayBytesDeallocator = { ptr, ctx in
            ptr?.deallocate()
            if let ctx {
                let box = ctx.assumingMemoryBound(to: Int.self)
                let len = box.pointee
                if len > 0 {
                    mitmScriptTypedArrayLock.lock()
                    mitmScriptTypedArrayBytes -= len
                    mitmScriptTypedArrayLock.unlock()
                }
                box.deinitialize(count: 1)
                box.deallocate()
            }
        }
        var exception: JSValueRef?
        let ref = JSObjectMakeTypedArrayWithBytesNoCopy(
            context.jsGlobalContextRef,
            kJSTypedArrayTypeUint8Array,
            buffer,
            count,
            deallocator,
            UnsafeMutableRawPointer(lengthBox),
            &exception
        )
        guard exception == nil, let ref else {
            buffer.deallocate()
            lengthBox.deinitialize(count: 1)
            lengthBox.deallocate()
            if count > 0 {
                mitmScriptTypedArrayLock.lock()
                mitmScriptTypedArrayBytes -= count
                mitmScriptTypedArrayLock.unlock()
            }
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

    // MARK: - Protobuf wire format

    /// In-flight decoded field. ``.varint`` carries the raw unsigned
    /// 64-bit value (the script applies zigzag for sint32/sint64
    /// itself, since this layer can't know the field type);
    /// ``.bytes`` carries the wire-1 / wire-2 / wire-5 payload
    /// verbatim.
    fileprivate enum ProtobufFieldValue {
        case varint(UInt64)
        case bytes(Data)
    }

    fileprivate struct ProtobufEntry {
        let field: UInt32
        let wire: UInt8
        let value: ProtobufFieldValue
    }

    private struct ProtobufError: Error, CustomStringConvertible {
        let description: String
    }

    /// Reads a single varint at ``offset``, returning the decoded
    /// value and the index immediately past its last byte. Returns
    /// nil on truncation or when the encoding spans more than 10
    /// bytes (the maximum for a 64-bit varint per the protobuf spec).
    ///
    /// ``offset`` is an absolute index into ``data`` (i.e. it must lie
    /// in ``data.startIndex...data.endIndex``). Callers that pass a
    /// 0-based offset must therefore hand in a zero-based ``Data`` —
    /// the guard below rejects (returns nil for) a mismatched
    /// slice-relative offset rather than trapping on an
    /// out-of-bounds subscript.
    fileprivate static func readVarint(_ data: Data, from offset: Int) -> (UInt64, Int)? {
        guard offset >= data.startIndex, offset <= data.endIndex else { return nil }
        var result: UInt64 = 0
        var shift: UInt64 = 0
        var idx = offset
        var bytesRead = 0
        let end = data.endIndex
        while idx < end {
            if bytesRead >= 10 { return nil }
            let byte = data[idx]
            result |= UInt64(byte & 0x7F) << shift
            idx += 1
            bytesRead += 1
            if byte & 0x80 == 0 {
                return (result, idx)
            }
            shift += 7
        }
        return nil
    }

    fileprivate static func writeVarint(_ value: UInt64) -> Data {
        var v = value
        var out = Data()
        out.reserveCapacity(10)
        while true {
            if v < 0x80 {
                out.append(UInt8(v))
                return out
            }
            out.append(UInt8((v & 0x7F) | 0x80))
            v >>= 7
        }
    }

    fileprivate static func protobufDecodeWire(_ data: Data) throws -> [ProtobufEntry] {
        var entries: [ProtobufEntry] = []
        var idx = data.startIndex
        let end = data.endIndex
        while idx < end {
            guard let (tag, next) = readVarint(data, from: idx) else {
                throw ProtobufError(description: "truncated or oversized tag varint at offset \(idx - data.startIndex)")
            }
            idx = next
            let wire = UInt8(tag & 0x7)
            let fieldRaw = tag >> 3
            // Protobuf reserves field number 0 and caps at 2^29 - 1.
            // Anything outside that range is malformed wire.
            guard fieldRaw > 0, fieldRaw <= 536870911 else {
                throw ProtobufError(description: "invalid field number \(fieldRaw)")
            }
            let field = UInt32(fieldRaw)
            switch wire {
            case 0:
                guard let (v, n) = readVarint(data, from: idx) else {
                    throw ProtobufError(description: "truncated varint for field \(field)")
                }
                idx = n
                entries.append(ProtobufEntry(field: field, wire: 0, value: .varint(v)))
            case 1:
                guard idx + 8 <= end else {
                    throw ProtobufError(description: "truncated fixed64 for field \(field)")
                }
                entries.append(ProtobufEntry(field: field, wire: 1, value: .bytes(data.subdata(in: idx..<idx + 8))))
                idx += 8
            case 2:
                guard let (len, n) = readVarint(data, from: idx) else {
                    throw ProtobufError(description: "truncated length for field \(field)")
                }
                idx = n
                let needed = Int(len)
                // The Int conversion above truncates on UInt64 ≥ 2^63;
                // a length that large is itself malformed (it can't fit
                // in the remaining bytes). Guard both: non-negative
                // after the cast, and within the message.
                guard needed >= 0, idx + needed <= end else {
                    throw ProtobufError(description: "length-delimited field \(field) (len=\(len)) exceeds message")
                }
                entries.append(ProtobufEntry(field: field, wire: 2, value: .bytes(data.subdata(in: idx..<idx + needed))))
                idx += needed
            case 5:
                guard idx + 4 <= end else {
                    throw ProtobufError(description: "truncated fixed32 for field \(field)")
                }
                entries.append(ProtobufEntry(field: field, wire: 5, value: .bytes(data.subdata(in: idx..<idx + 4))))
                idx += 4
            case 3, 4:
                throw ProtobufError(description: "deprecated group wire type \(wire) is not supported")
            default:
                throw ProtobufError(description: "unknown wire type \(wire)")
            }
        }
        return entries
    }

    fileprivate static func protobufEncodeWire(_ entries: [ProtobufEntry]) -> Data {
        var out = Data()
        for entry in entries {
            let tag = UInt64(entry.field) << 3 | UInt64(entry.wire)
            out.append(writeVarint(tag))
            switch entry.value {
            case .varint(let v):
                out.append(writeVarint(v))
            case .bytes(let bytes):
                if entry.wire == 2 {
                    out.append(writeVarint(UInt64(bytes.count)))
                }
                out.append(bytes)
            }
        }
        return out
    }

    /// Pulls a JS array of ``{field, wire, value}`` entries back into
    /// Swift. Validates shape strictly so a malformed entry surfaces
    /// as a catchable JS error rather than silently encoding garbage:
    /// wrong-length fixed payloads, non-numeric varints, and
    /// out-of-range field numbers all throw.
    fileprivate static func parseProtobufEntries(_ val: JSValue, in context: JSContext) throws -> [ProtobufEntry] {
        guard val.isArray else {
            throw ProtobufError(description: "expected an array of {field, wire, value} entries")
        }
        let lengthVal = val.objectForKeyedSubscript("length")
        guard let lengthVal, lengthVal.isNumber else {
            throw ProtobufError(description: "input array has no length")
        }
        let count = Int(lengthVal.toInt32())
        var entries: [ProtobufEntry] = []
        entries.reserveCapacity(count)
        for idx in 0..<count {
            guard let entryVal = val.objectAtIndexedSubscript(idx),
                  !entryVal.isUndefined, !entryVal.isNull else {
                throw ProtobufError(description: "entry \(idx) is null/undefined")
            }
            let fieldVal = entryVal.objectForKeyedSubscript("field")
            guard let fieldVal, fieldVal.isNumber else {
                throw ProtobufError(description: "entry \(idx).field must be a Number")
            }
            let fieldNum = fieldVal.toInt32()
            guard fieldNum > 0, fieldNum <= 536_870_911 else {
                throw ProtobufError(description: "entry \(idx).field \(fieldNum) out of range (1…2^29-1)")
            }
            let wireVal = entryVal.objectForKeyedSubscript("wire")
            guard let wireVal, wireVal.isNumber else {
                throw ProtobufError(description: "entry \(idx).wire must be a Number")
            }
            let wireNum = UInt8(truncatingIfNeeded: wireVal.toInt32())
            let valueVal = entryVal.objectForKeyedSubscript("value")
            switch wireNum {
            case 0:
                guard let v = valueVal.flatMap({ uint64FromJSValue($0) }) else {
                    throw ProtobufError(description: "entry \(idx).value (wire 0) must be a non-negative integer Number or BigInt")
                }
                entries.append(ProtobufEntry(field: UInt32(fieldNum), wire: 0, value: .varint(v)))
            case 1:
                guard let bytes = valueVal.flatMap({ bytesFromValue($0, in: context) }), bytes.count == 8 else {
                    throw ProtobufError(description: "entry \(idx).value (wire 1) must be a Uint8Array of length 8")
                }
                entries.append(ProtobufEntry(field: UInt32(fieldNum), wire: 1, value: .bytes(bytes)))
            case 2:
                guard let bytes = valueVal.flatMap({ bytesFromValue($0, in: context) }) else {
                    throw ProtobufError(description: "entry \(idx).value (wire 2) must be Uint8Array/ArrayBuffer/string")
                }
                entries.append(ProtobufEntry(field: UInt32(fieldNum), wire: 2, value: .bytes(bytes)))
            case 5:
                guard let bytes = valueVal.flatMap({ bytesFromValue($0, in: context) }), bytes.count == 4 else {
                    throw ProtobufError(description: "entry \(idx).value (wire 5) must be a Uint8Array of length 4")
                }
                entries.append(ProtobufEntry(field: UInt32(fieldNum), wire: 5, value: .bytes(bytes)))
            case 3, 4:
                throw ProtobufError(description: "entry \(idx).wire = \(wireNum): deprecated group wire types not supported")
            default:
                throw ProtobufError(description: "entry \(idx).wire = \(wireNum): unknown wire type")
            }
        }
        return entries
    }

    /// Lifts a Swift entry list into a JS array of
    /// ``{field, wire, value}`` objects. The ``BigInt`` constructor
    /// lookup is hoisted out of the loop because looking it up per
    /// entry dominates decode time for varint-heavy messages.
    fileprivate static func makeProtobufEntries(_ entries: [ProtobufEntry], in context: JSContext) -> JSValue {
        let array = JSValue(newArrayIn: context)!
        let bigIntFn = context.objectForKeyedSubscript("BigInt")
        for (idx, entry) in entries.enumerated() {
            let obj = JSValue(newObjectIn: context)!
            obj.setObject(NSNumber(value: entry.field), forKeyedSubscript: "field" as NSString)
            obj.setObject(NSNumber(value: entry.wire), forKeyedSubscript: "wire" as NSString)
            let v: JSValue
            switch entry.value {
            case .varint(let u):
                v = bigIntFn?.call(withArguments: [String(u)]) ?? JSValue(undefinedIn: context)
            case .bytes(let d):
                v = makeUint8Array(in: context, from: d)
            }
            obj.setObject(v, forKeyedSubscript: "value" as NSString)
            array.setObject(obj, atIndexedSubscript: idx)
        }
        return array
    }

    /// Builds a JS BigInt from a UInt64 by stringifying and calling
    /// the global ``BigInt`` constructor — the only public path on
    /// the Obj-C bridge that accepts the full 64-bit range. The
    /// alternative (passing a Double to ``BigInt``) loses precision
    /// above 2^53.
    fileprivate static func makeBigInt(_ value: UInt64, in context: JSContext) -> JSValue {
        let bigIntFn = context.objectForKeyedSubscript("BigInt")
        return bigIntFn?.call(withArguments: [String(value)]) ?? JSValue(undefinedIn: context)
    }

    /// Converts a JS value to a UInt64 for encode-side input. Accepts
    /// ``Number`` only when it's a non-negative integer in safe-int
    /// range (so a script using ``3`` for a small field tag works
    /// without sprinkling ``n`` suffixes); larger values must arrive
    /// as ``BigInt`` (or a decimal string) to avoid silent precision
    /// loss. Negative numbers and non-numeric values return nil and
    /// surface as a JS error at the call site.
    fileprivate static func uint64FromJSValue(_ val: JSValue) -> UInt64? {
        if val.isUndefined || val.isNull { return nil }
        if val.isNumber {
            let d = val.toDouble()
            guard d.isFinite, d >= 0, d <= 9_007_199_254_740_991.0, d == d.rounded() else {
                return nil
            }
            return UInt64(d)
        }
        // BigInt and string both come through toString as a decimal
        // representation; UInt64(_:) rejects anything that isn't a
        // valid non-negative decimal integer.
        guard let str = val.toString() else { return nil }
        return UInt64(str)
    }

    // MARK: - Base64URL / JWT helpers

    /// RFC 4648 §5: standard base64 with ``+``→``-``, ``/``→``_``, and
    /// trailing ``=`` padding stripped. Always emits the canonical
    /// no-padding form; decode is permissive about either alphabet
    /// and either padded or unpadded input because tokens in the wild
    /// frequently re-encode through a generic base64 step.
    fileprivate static func encodeBase64URL(_ data: Data) -> String {
        var s = data.base64EncodedString()
        s = s.replacingOccurrences(of: "+", with: "-")
        s = s.replacingOccurrences(of: "/", with: "_")
        s = s.replacingOccurrences(of: "=", with: "")
        return s
    }

    fileprivate static func decodeBase64URL(_ str: String) -> Data? {
        var s = str.replacingOccurrences(of: "-", with: "+")
        s = s.replacingOccurrences(of: "_", with: "/")
        let mod = s.count % 4
        if mod > 0 {
            s += String(repeating: "=", count: 4 - mod)
        }
        return Data(base64Encoded: s)
    }

    /// Calls the JS ``JSON.parse`` global. Used instead of a Swift
    /// JSON decoder so the resulting value is a real JS object the
    /// script can mutate by assignment (a Swift-side
    /// ``JSONSerialization`` round-trip would land back in JS as a
    /// dictionary the script can read but not mutate naturally).
    /// Returns nil for malformed input and swallows the thrown
    /// exception so the engine's outer ``context.exception != nil``
    /// gate doesn't roll back the whole script just because we
    /// probed a payload that turned out not to be JSON.
    fileprivate static func parseJSON(_ str: String, in context: JSContext) -> JSValue? {
        let json = context.objectForKeyedSubscript("JSON")
        let result = json?.invokeMethod("parse", withArguments: [str])
        if context.exception != nil {
            context.exception = nil
            return nil
        }
        return result
    }

    /// Encodes one JWT header/payload segment. Bytes-shaped inputs
    /// (string / Uint8Array / ArrayBuffer) are base64url'd verbatim —
    /// that's how a script feeds a pre-stringified JSON or a binary
    /// JWS payload (RFC 7797). Anything else (plain object, array,
    /// number) goes through ``JSON.stringify`` first. Returns nil on
    /// undefined/null input or when ``JSON.stringify`` returns
    /// undefined (e.g. a JS value with a non-serializable cycle).
    fileprivate static func encodeJWTSegment(_ value: JSValue?, in context: JSContext) -> String? {
        guard let value, !value.isUndefined, !value.isNull else { return nil }
        if let bytes = bytesFromValue(value, in: context) {
            return encodeBase64URL(bytes)
        }
        let json = context.objectForKeyedSubscript("JSON")
        guard let result = json?.invokeMethod("stringify", withArguments: [value]),
              !result.isUndefined,
              let str = result.toString() else {
            return nil
        }
        return encodeBase64URL(Data(str.utf8))
    }
}

extension MITMScriptEngine {

    /// Process-wide registry of engines keyed by rule-set id — the same
    /// scope ``Anywhere.store`` uses. One engine serves every connection
    /// whose matched rule set has that id, so a script's compiled
    /// ``process`` function, its installed ``Anywhere`` globals, and any
    /// state it stashes on ``globalThis`` are built once per rule set and
    /// reused across connections instead of rebuilt per connection.
    ///
    /// Sharing across connections is safe because every rule application
    /// runs on the single serial lwIP queue (see ``MITMSession``), so no
    /// two scripts ever execute concurrently. Creation happens under
    /// ``registryLock`` so two callers racing to first-use a rule set
    /// can't build two engines for it — that would split the ``compiled``
    /// cache and ``globalThis`` state and produce silent, hard-to-diagnose
    /// crosstalk within the rule set.
    private static var engines: [UUID: MITMScriptEngine] = [:]
    /// Engine for the degenerate nil-scope case (a script fired for a host
    /// whose matched set has no id). Scripts always belong to a rule set,
    /// so this is unreachable in practice; it just gives the lookup a home.
    private static var scopelessEngine: MITMScriptEngine?
    private static let registryLock = UnfairLock()

    /// The shared engine for ``scope``, created on first use. Stays lazy:
    /// a rule set whose rules never invoke a script never builds a
    /// ``JSContext``.
    static func sharedEngine(forScope scope: UUID?) -> MITMScriptEngine {
        registryLock.withLock { () -> MITMScriptEngine in
            guard let scope else {
                if let engine = scopelessEngine { return engine }
                let engine = MITMScriptEngine()
                scopelessEngine = engine
                return engine
            }
            if let engine = engines[scope] { return engine }
            let engine = MITMScriptEngine()
            engines[scope] = engine
            return engine
        }
    }

    /// Drops engines whose rule set is no longer present, freeing each
    /// one's ``JSContext`` and compiled-function cache. Called from
    /// ``MITMRewritePolicy/load`` after a config change, alongside the
    /// ``MITMScriptStore`` purge — so in-memory script state, like the
    /// store, survives a rule-set edit (the id is stable) and is cleared
    /// only when the set is removed.
    static func purgeEngines(activeIDs: Set<UUID>) {
        registryLock.withLock {
            engines = engines.filter { activeIDs.contains($0.key) }
        }
    }

    /// Per-session handle to the shared engine for the session's matched
    /// rule set. Holds the rule-set ``scope`` and resolves the engine
    /// lazily on the first script execution, so a connection whose rules
    /// never fire a script never touches a ``JSContext``.
    final class Provider {
        private let scope: UUID?
        init(scope: UUID?) { self.scope = scope }
        func get() -> MITMScriptEngine { MITMScriptEngine.sharedEngine(forScope: scope) }
    }
}
