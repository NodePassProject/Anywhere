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

private let logger = AnywhereLogger(category: "MITMScriptEngine")

/// Bytes pinned by NoCopy Uint8Array allocations; file-private so the C deallocator can reference it without captures.
private nonisolated(unsafe) var mitmScriptTypedArrayBytes: Int = 0
private let mitmScriptTypedArrayLock = UnfairLock()

/// In-flight Anywhere.http fetches across all engines, bounded by httpMaxConcurrentGlobal.
private nonisolated(unsafe) var mitmScriptGlobalFetchCount: Int = 0
private let mitmScriptGlobalFetchLock = UnfairLock()

/// JavaScript runtime for `script` rules: one JSContext per rule set, compiled functions cached by source hash.
/// Runaway JS cannot be preempted (JSContextGroupSetExecutionTimeLimit is App Review-flagged WebKit SPI);
/// a hung sync span trips MITMScriptWatchdog, and an unsettled promise is reverted by the idle watchdog.
final class MITMScriptEngine {

    typealias Message = HTTPMessage

    /// Produced by `Anywhere.respond(...)`: the request is dropped and this response goes to the client.
    struct SynthesizedResponse {
        let status: Int
        let headers: [(name: String, value: String)]
        let body: Data
    }

    enum Outcome {
        case modified(Message)
        case done(Message)
        case exit
        /// Request-phase only: drop the request and synthesize this response to the client.
        case respond(SynthesizedResponse)
    }

    /// Per-frame context for applyFrame. All ctx fields except body are read-only — HEADERS are already on the wire.
    struct FrameContext {
        let phase: MITMPhase
        let method: String?
        let url: String?
        let status: Int?
        let headers: [(name: String, value: String)]
        let frameIndex: Int
        /// Last frame in the stream (HTTP/2 END_STREAM, HTTP/1 chunked terminator).
        let isLast: Bool
        let ruleSetID: UUID?
    }

    /// Result of applyFrame; the caller threads `state` back in on the next frame.
    enum FrameOutcome {
        case modified(body: Data, state: JSValue?)
        /// Emit ``body``; pass every subsequent frame through unchanged.
        case done(body: Data)
        /// Emit the original frame payload; pass every subsequent frame through.
        case exit
    }

    /// Set by `Anywhere.done/exit/respond` during a span; read at settlement.
    fileprivate enum Directive {
        case done
        case exit
        case respond(SynthesizedResponse)
    }

    /// State for one `process(ctx)` run; `currentInvocation` names the executing
    /// span so store/control/http blocks act on the right one.
    fileprivate final class Invocation {
        let scope: UUID?
        /// False on ``applyFrame`` (head is already on the wire) and the sync path.
        let allowsHTTP: Bool
        var directive: Directive?

        // Async buffered-script fields — nil/unused on sync + frame paths.
        let original: Message?
        var ctxValue: JSValue?
        let resumeQueue: DispatchQueue?
        let completion: ((Outcome) -> Void)?
        /// Held so JSC keeps the promise's reactions reachable while suspended.
        var resultPromise: JSValue?
        var inFlightFetches = 0
        var totalFetches = 0
        var delivered = false

        /// Idle watchdog; fires and reverts the invocation if the promise never settles.
        var watchdog: DispatchWorkItem?

        init(scope: UUID?, original: Message, resumeQueue: DispatchQueue, completion: @escaping (Outcome) -> Void) {
            self.scope = scope
            self.allowsHTTP = true
            self.original = original
            self.resumeQueue = resumeQueue
            self.completion = completion
        }

        /// Lightweight sync-span invocation: carries only scope, HTTP gate, and directive slot.
        init(scope: UUID?, allowsHTTP: Bool) {
            self.scope = scope
            self.allowsHTTP = allowsHTTP
            self.original = nil
            self.resumeQueue = nil
            self.completion = nil
        }
    }

    private let context: JSContext
    /// Compiled `process(ctx)` functions keyed by source hash; `byteCount` is a hash-collision guard.
    private struct CompiledEntry {
        let byteCount: Int
        let function: JSValue
    }
    private var compiled: [Int: CompiledEntry] = [:]

    /// Invocation whose synchronous JS span is running right now; nil between spans.
    private var currentInvocation: Invocation?

    /// Suspended async invocations, retained until delivery so weak captures in fetch/settle closures stay valid.
    private var liveInvocations: [ObjectIdentifier: Invocation] = [:]

    /// Shared across all engines: per-rule-set VMs would multiply JSC's multi-MiB per-VM
    /// overhead beyond the NE's ~50 MiB budget. JSC serializes heap access internally.
    private static let sharedVM: JSVirtualMachine = JSVirtualMachine()!

    /// Serializes synchronous JS spans and guards `currentInvocation`/`compiled`; never held across an `await`.
    private let invocationLock = NSLock()

    /// GC-nudge threshold for pinned NoCopy bytes (JSC's GC can't see them).
    private static let softTypedArrayBudget: Int = 16 * 1024 * 1024
    /// Hard cap: new NoCopy allocations past this return an empty Uint8Array.
    private static let hardTypedArrayBudget: Int = 32 * 1024 * 1024

    // MARK: Anywhere.http caps

    private static let httpDefaultTimeout: TimeInterval = 10
    private static let httpMaxTimeout: TimeInterval = 30
    private static let httpMaxConcurrentPerInvocation = 4
    private static let httpMaxTotalPerInvocation = 16
    private static let httpMaxResponseBytes = 4 * 1024 * 1024
    private static let httpMaxConcurrentGlobal = 32

    /// Idle timeout for a suspended invocation; exceeds httpMaxTimeout so a slow-but-progressing
    /// fetch isn't cut off while still bounding a promise that never settles.
    private static let invocationIdleTimeout: TimeInterval = httpMaxTimeout + 30

    /// Re-entrancy guard: formatting a thrown value runs JS ToString, which a script can
    /// override to throw and recurse the exception handler until the NE stack-overflows.
    private var isFormattingException = false

    init() {
        self.context = JSContext(virtualMachine: Self.sharedVM)
        // Reinstate JSC's default write to context.exception or downstream checks never fire.
        self.context.exceptionHandler = { [weak self] context, exception in
            defer { context?.exception = exception }
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

    /// Wraps one synchronous JSC span with the ``MITMScriptWatchdog`` hard cap.
    @inline(__always)
    private func runUserScript<T>(_ label: String, _ body: () -> T) -> T {
        MITMScriptWatchdog.begin(label)
        defer { MITMScriptWatchdog.end() }
        return PerformanceMonitor.measure(.mitmScript, body)
    }

    /// A script-set directive wins over a trailing uncaught throw; a bare throw reverts to the original.
    private func finalize(original: Message, updated: Message, directive: Directive?) -> Outcome {
        let hadException = context.exception != nil
        context.exception = nil
        if let directive {
            return outcome(forDirective: directive, original: original, updated: updated)
        }
        if hadException {
            return .modified(original)
        }
        return .modified(updated)
    }

    /// ``Anywhere.respond`` degrades to ``.modified`` on the response phase.
    private func outcome(forDirective directive: Directive, original: Message, updated: Message) -> Outcome {
        switch directive {
        case .done: return .done(updated)
        case .exit: return .exit
        case .respond(let response):
            if original.phase == .httpRequest {
                return .respond(response)
            }
            logger.warning("[MITM][JS] Anywhere.respond ignored on response phase")
            return .modified(updated)
        }
    }

    /// True when ``value`` is an object with a callable `then` (a Promise or async return).
    private func isThenable(_ value: JSValue) -> Bool {
        guard value.isObject,
              let thenVal = value.objectForKeyedSubscript("then"),
              thenVal.isObject,
              let ref = thenVal.jsValueRef
        else { return false }
        let ctxRef = context.jsGlobalContextRef
        var exception: JSValueRef?
        guard let obj = JSValueToObject(ctxRef, ref, &exception), exception == nil else {
            return false
        }
        return JSObjectIsFunction(ctxRef, obj)
    }

    /// Runs `process(ctx)`; a thenable return suspends without holding the script
    /// queue. ``completion`` fires exactly once on ``resumeQueue`` at settlement.
    func applyAsync(
        _ message: Message,
        source: String,
        sourceKey: Int,
        resumeOn resumeQueue: DispatchQueue,
        completion: @escaping (Outcome) -> Void
    ) {
        let inv = Invocation(
            scope: message.ruleSetID,
            original: message,
            resumeQueue: resumeQueue,
            completion: completion
        )
        invocationLock.lock()
        defer {
            invocationLock.unlock()
            collectIfBudgetExceeded()
        }
        guard let function = compileIfNeeded(source, key: sourceKey) else {
            deliver(.modified(message), for: inv)
            return
        }
        let ctxArg = makeContextValue(message)
        inv.ctxValue = ctxArg
        currentInvocation = inv
        let returned = runUserScript(source) { function.call(withArguments: [ctxArg]) }
        guard let returned, isThenable(returned) else {
            currentInvocation = nil
            let updated = readBack(message, from: ctxArg)
            deliver(finalize(original: message, updated: updated, directive: inv.directive), for: inv)
            return
        }
        // Suspended at an await — retain the promise so JSC keeps its reactions reachable.
        inv.resultPromise = returned
        liveInvocations[ObjectIdentifier(inv)] = inv
        currentInvocation = nil
        // Arm first: an already-settled promise delivers synchronously and deliver() cancels the timer.
        armWatchdog(for: inv)
        attachSettleHandlers(to: returned, for: inv)
    }

    /// Weak `inv` capture avoids an inv→promise→reaction→inv retain cycle.
    private func attachSettleHandlers(to promise: JSValue, for inv: Invocation) {
        let onFulfilled: @convention(block) (JSValue) -> Void = { [weak self, weak inv] _ in
            guard let self, let inv else { return }
            self.finishSuccess(inv)
        }
        let onRejected: @convention(block) (JSValue) -> Void = { [weak self, weak inv] reason in
            guard let self, let inv else { return }
            self.finishRejected(inv, reason: reason)
        }
        promise.invokeMethod("then", withArguments: [onFulfilled, onRejected])
        // A throw from inside `then` lands on the context; clear so it can't leak into the next span.
        if context.exception != nil { context.exception = nil }
    }

    private func finishSuccess(_ inv: Invocation) {
        guard !inv.delivered, let original = inv.original, let ctxArg = inv.ctxValue else { return }
        let updated = readBack(original, from: ctxArg)
        deliver(finalize(original: original, updated: updated, directive: inv.directive), for: inv)
    }

    /// A directive set before the rejection still wins; otherwise revert to the original.
    private func finishRejected(_ inv: Invocation, reason: JSValue?) {
        guard !inv.delivered, let original = inv.original else { return }
        let ctxArg = inv.ctxValue ?? makeContextValue(original)
        let updated = readBack(original, from: ctxArg)
        context.exception = nil
        if let directive = inv.directive {
            deliver(outcome(forDirective: directive, original: original, updated: updated), for: inv)
        } else {
            if let reason {
                logger.warning("[MITM][JS] process(ctx) promise rejected: \(String(describing: reason))")
            }
            deliver(.modified(original), for: inv)
        }
    }

    /// Delivers the final ``Outcome`` exactly once and releases JS object references.
    private func deliver(_ outcome: Outcome, for inv: Invocation) {
        guard !inv.delivered else { return }
        inv.delivered = true
        inv.watchdog?.cancel()
        inv.watchdog = nil
        liveInvocations.removeValue(forKey: ObjectIdentifier(inv))
        inv.resultPromise = nil
        inv.ctxValue = nil
        guard let resumeQueue = inv.resumeQueue, let completion = inv.completion else { return }
        resumeQueue.async { completion(outcome) }
    }

    /// (Re)arms the idle watchdog; settlement cancels it first, so settlement always wins.
    private func armWatchdog(for inv: Invocation) {
        inv.watchdog?.cancel()
        let item = DispatchWorkItem { [weak self, weak inv] in
            guard let self, let inv else { return }
            self.invocationLock.lock()
            defer { self.invocationLock.unlock() }
            guard !inv.delivered, let original = inv.original else { return }
            logger.warning("[MITM][JS] process(ctx) did not settle within \(Self.invocationIdleTimeout)s; reverting")
            self.deliver(.modified(original), for: inv)
        }
        inv.watchdog = item
        MITMScriptTransform.scriptQueue.asyncAfter(deadline: .now() + Self.invocationIdleTimeout, execute: item)
    }

    /// Nudges JSC's GC (unaware of pinned NoCopy buffers) past the soft budget.
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

    /// Runs ``source`` against one streaming frame; on failure emits the frame unchanged.
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
        let inv = Invocation(scope: ctx.ruleSetID, allowsHTTP: false)
        currentInvocation = inv
        defer { currentInvocation = nil }
        let ctxArg = makeFrameContextValue(ctx, frame: frame, state: state)
        _ = runUserScript(source) { function.call(withArguments: [ctxArg]) }
        // Ignore mutations to method/url/status/headers — HEADERS are on the wire.
        let body: Data
        if let bodyVal = ctxArg.objectForKeyedSubscript("body"),
           let bytes = Self.bytesFromValue(bodyVal, in: context) {
            body = bytes
        } else {
            body = frame
        }
        let updatedState = ctxArg.objectForKeyedSubscript("state")
        let hadException = context.exception != nil
        if let directive = inv.directive {
            context.exception = nil
            switch directive {
            case .done: return .done(body: body)
            case .exit: return .exit
            case .respond:
                // HEADERS already on the wire — respond is a no-op in streamScript.
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

    /// Compiles into the cache ahead of traffic without running `process` —
    /// a fabricated ctx could fire respond, mutate the store, or spin.
    func precompile(source: String, sourceKey: Int) {
        invocationLock.lock()
        defer { invocationLock.unlock() }
        _ = compileIfNeeded(source, key: sourceKey)
    }

    /// Drops cache entries not in ``keep``. Must be called on the script queue
    /// so dropped JSValues release on the VM-owning queue.
    func pruneCompiled(keeping keep: Set<Int>) {
        invocationLock.lock()
        defer { invocationLock.unlock() }
        let stale = compiled.keys.filter { !keep.contains($0) }
        for key in stale { compiled.removeValue(forKey: key) }
    }

    private func compileIfNeeded(_ source: String, key: Int) -> JSValue? {
        let byteCount = source.utf8.count
        if let cached = compiled[key] {
            // 64-bit hash collision guard — a byte-count mismatch recompiles.
            if cached.byteCount == byteCount { return cached.function }
            logger.warning("[MITM][JS] cache-key collision: recompiling under same key")
        }
        // IIFE: keeps `process` out of globalThis; top-level user code runs here,
        // so a `while(true)` outside `process` hangs at compile time — watchdog covers it.
        let wrapped = "(function(){\n\(source)\nreturn process;\n})()"
        let value = runUserScript(source) { context.evaluateScript(wrapped) }
        if context.exception != nil {
            context.exception = nil
            return nil
        }
        guard let value, !value.isUndefined, !value.isNull else {
            logger.warning("[MITM][JS] script did not define process(ctx)")
            return nil
        }
        // Verify callable before caching: a cached non-function would fail every later intercept.
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

    private func makeContextValue(_ msg: Message) -> JSValue {
        let obj = JSValue(newObjectIn: context)!
        obj.setObject(
            msg.phase == .httpRequest ? "request" : "response",
            forKeyedSubscript: "phase" as NSString
        )
        obj.setObject(msg.method as Any, forKeyedSubscript: "method" as NSString)
        obj.setObject(msg.url as Any, forKeyedSubscript: "url" as NSString)
        obj.setObject(msg.status as Any, forKeyedSubscript: "status" as NSString)
        // [[name, value], ...] preserves duplicates and emit order.
        let pairs: [[String]] = msg.headers.map { [$0.name, $0.value] }
        obj.setObject(pairs, forKeyedSubscript: "headers" as NSString)
        obj.setObject(Self.makeUint8Array(in: context, from: msg.body), forKeyedSubscript: "body" as NSString)
        return obj
    }

    /// makeContextValue plus a `frame` `{index, end}` sub-object and persistent
    /// `state` (fresh empty object on first call so scripts write without guarding).
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

        // Using a JSValue in a context other than its own is UB in JSC; reset a
        // stale cursor that survived a rule reload / engine swap rather than trap.
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

    /// Only `body` is read back; method/url/status/headers assignments are discarded (injection guard).
    private func readBack(_ original: Message, from ctx: JSValue) -> Message {
        var msg = original
        if let body = ctx.objectForKeyedSubscript("body"),
           let bytes = Self.bytesFromValue(body, in: context) {
            msg.body = bytes
        }
        return msg
    }

    /// toInt32() wraps 2^31+ lengths negative (trapping a `0..<negative` range);
    /// reading via toDouble() and bounding avoids the trap and a huge-length spin.
    private static func validatedArrayLength(_ value: JSValue, max: Int) -> Int? {
        guard let lengthVal = value.objectForKeyedSubscript("length"), lengthVal.isNumber else {
            return nil
        }
        let raw = lengthVal.toDouble()
        guard raw.isFinite, raw >= 0, raw <= Double(max) else { return nil }
        return Int(raw)
    }

    /// Decodes a JS `[[name, value], ...]` array; nil (caller keeps the original headers) for non-array
    /// input or when every entry fails validation. Names must be RFC 9110 tokens; values must not
    /// contain CR/LF/NUL (response splitting).
    private static func headersFromValue(_ value: JSValue) -> [(name: String, value: String)]? {
        guard value.isArray else { return nil }
        guard let length = Self.validatedArrayLength(value, max: 100_000) else {
            logger.warning("[MITM][JS] dropping ctx.headers: length missing, negative, or implausibly large")
            return nil
        }
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
            guard isValidHTTPHeaderName(name) else {
                logger.warning("[MITM][JS] dropping header with invalid name: \(name)")
                continue
            }
            guard isValidHTTPHeaderValue(val) else {
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
        installHTTPGlobals(on: anywhere)
        context.setObject(anywhere, forKeyedSubscript: "Anywhere" as NSString)
        // Must follow Anywhere install: the shim captures Anywhere.codec.utf8.
        installTextCodecGlobals()
    }

    /// Installs native TextEncoder/TextDecoder (JSC has none) to pre-empt scripts' slow polyfills.
    /// decode must be lossy (invalid UTF-8 → U+FFFD) and respect byteOffset on typed-array sub-views.
    private func installTextCodecGlobals() {
        let installed = context.evaluateScript(#"""
        (function (g) {
          if (!g.Anywhere || !g.Anywhere.codec || !g.Anywhere.codec.utf8) return false;
          var enc = g.Anywhere.codec.utf8.encode;
          var dec = g.Anywhere.codec.utf8.decode;
          function TextEncoder() { this.encoding = "utf-8"; }
          TextEncoder.prototype.encode = function (input) {
            return enc(input == null ? "" : String(input));
          };
          function TextDecoder(label, options) {
            this.encoding = (label == null ? "utf-8" : String(label)).toLowerCase();
            this.fatal = !!(options && options.fatal);
            this.ignoreBOM = !!(options && options.ignoreBOM);
          }
          TextDecoder.prototype.decode = function (input) {
            return input == null ? "" : dec(input);
          };
          Object.defineProperty(g, "TextEncoder", { value: TextEncoder, writable: true, configurable: true });
          Object.defineProperty(g, "TextDecoder", { value: TextDecoder, writable: true, configurable: true });
          return true;
        })(typeof globalThis !== "undefined" ? globalThis : this);
        """#)
        if context.exception != nil {
            context.exception = nil
            logger.warning("[MITM][JS] failed to install TextEncoder/TextDecoder globals")
        } else if installed?.isBoolean == true, installed?.toBool() == false {
            logger.warning("[MITM][JS] TextEncoder/TextDecoder install skipped: Anywhere.codec.utf8 missing")
        }
    }

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
            // Lossy: invalid UTF-8 → U+FFFD so partial-text buffers still decode.
            return String(decoding: bytes, as: UTF8.self)
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
            // Lenient: skip embedded whitespace so wrapped base64 still decodes.
            return Self.makeUint8Array(in: ctx, from: Data(base64Encoded: str, options: .ignoreUnknownCharacters) ?? Data())
        }
        base64.setObject(base64Encode, forKeyedSubscript: "encode" as NSString)
        base64.setObject(base64Decode, forKeyedSubscript: "decode" as NSString)
        codec.setObject(base64, forKeyedSubscript: "base64" as NSString)

        // RFC 4648 §5 base64url: `-`/`_`, no padding. Decode is lenient (either
        // alphabet, padded or not) — tokens in the wild arrive in mixed shapes.
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

        // Schema-free protobuf wire codec. decode → [{field, wire, value}] in on-wire order; wire-0
        // varints are BigInt (lossless 64-bit), wire-1/2/5 payloads are Uint8Array, groups 3/4 rejected.
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
        // Single-varint helpers for hand-walking embedded messages without a full decode roundtrip.
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
            // null on truncated/malformed: easier to branch on than try/catch for a probe primitive.
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

        installCompressionCodec(on: codec, named: "gzip", codec: .gzip)
        installCompressionCodec(on: codec, named: "deflate", codec: .deflate)
        installCompressionCodec(on: codec, named: "brotli", codec: .brotli)

        anywhere.setObject(codec, forKeyedSubscript: "codec" as NSString)
    }

    /// Handles nested compression the auto-decoding pipeline never sees (e.g. a gzipped
    /// JSON field); decode throws on malformed input or past the decompression-bomb cap.
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

    private func installCryptoGlobals(on anywhere: JSValue) {
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
        // Capped at 64 KiB: a script typo can't pin the NE's RAM budget.
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

        // AES-GCM spec: key 16/24/32 B, nonce 12 B (random if omitted on encrypt), tag 16 B
        // (decrypt only), aad optional. Decrypt throws a catchable JS error on auth failure.
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
                guard n.count == 12 else {
                    ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: nonce must be 12 bytes", in: ctx)
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
            guard let nonce = Self.bytesFromValue(spec.objectForKeyedSubscript("nonce"), in: ctx),
                  nonce.count == 12 else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: nonce must be a Uint8Array of length 12", in: ctx)
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

    /// Anywhere.jwt — JWT compact serialization (RFC 7519/7515); pure codec, no signature verification.
    /// decode returns signingInput (RFC 7515 §5.1) so the script can verify without re-encoding.
    private func installJWTGlobals(on anywhere: JSValue) {
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
            // RFC 7519 §5: header MUST be JSON.
            guard let headerStr = String(data: headerBytes, encoding: .utf8),
                  let headerObj = Self.parseJSON(headerStr, in: ctx) else {
                ctx.exception = JSValue(newErrorFromMessage: "Anywhere.jwt.decode: header is not valid JSON", in: ctx)
                return JSValue(undefinedIn: ctx)
            }
            // Payload: try JSON; fall back to raw bytes (binary JWS payload per RFC 7797).
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
                signatureSeg = ""  // RFC 7515: trailing dot preserved so verifiers can split on count==3
            }
            return JSValue(object: "\(headerSeg).\(payloadSeg).\(signatureSeg)", in: ctx)
        }
        jwt.setObject(jwtDecodeBlock, forKeyedSubscript: "decode" as NSString)
        jwt.setObject(jwtEncodeBlock, forKeyedSubscript: "encode" as NSString)
        anywhere.setObject(jwt, forKeyedSubscript: "jwt" as NSString)
    }

    /// Anywhere.json — bytes-in/bytes-out JSON editing. All methods are total (failure returns the
    /// body unchanged); paths are JSONPath (`$.a.b[0]`), recursive methods take a bare key name.
    private func installJSONGlobals(on anywhere: JSValue) {
        let json = JSValue(newObjectIn: context)!

        // add: upsert — creates or overwrites; appends to arrays at index==length.
        let addBlock: @convention(block) (JSValue, String, JSValue) -> JSValue = { body, path, value in
            let ctx = JSContext.current()!
            guard let v = Self.jsonValue(from: value, in: ctx) else {
                logger.warning("[MITM][JS] Anywhere.json.add: value is undefined; use delete() to remove a field. Body unchanged.")
                return Self.jsonPassthrough(body, in: ctx)
            }
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.add: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            return Self.runJSONOp(body, in: ctx) { root in
                root = MITMJSONPatch.applyAtPath(root, segments: segments, mode: .add, value: v)
            }
        }

        // replace: modify-in-place only; no-op if the path doesn't exist.
        let replaceBlock: @convention(block) (JSValue, String, JSValue) -> JSValue = { body, path, value in
            let ctx = JSContext.current()!
            guard let v = Self.jsonValue(from: value, in: ctx) else {
                logger.warning("[MITM][JS] Anywhere.json.replace: value is undefined; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.replace: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            return Self.runJSONOp(body, in: ctx) { root in
                root = MITMJSONPatch.applyAtPath(root, segments: segments, mode: .replace, value: v)
            }
        }

        // replaceRecursive: bare key name (not a path), overwrites at any depth.
        let replaceRecursiveBlock: @convention(block) (JSValue, String, JSValue) -> JSValue = { body, key, value in
            let ctx = JSContext.current()!
            guard let v = Self.jsonValue(from: value, in: ctx) else {
                logger.warning("[MITM][JS] Anywhere.json.replaceRecursive: value is undefined; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            return Self.runJSONOp(body, in: ctx) { root in
                MITMJSONPatch.replaceKeyRecursive(root, key: key, value: v)
            }
        }

        let deleteBlock: @convention(block) (JSValue, String) -> JSValue = { body, path in
            let ctx = JSContext.current()!
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.delete: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            return Self.runJSONOp(body, in: ctx) { root in
                root = MITMJSONPatch.applyAtPath(root, segments: segments, mode: .delete, value: nil)
            }
        }

        let deleteRecursiveBlock: @convention(block) (JSValue, String) -> JSValue = { body, key in
            let ctx = JSContext.current()!
            return Self.runJSONOp(body, in: ctx) { root in
                MITMJSONPatch.deleteKeyRecursive(root, key: key)
            }
        }

        let removeWhereKeyExistsBlock: @convention(block) (JSValue, String, String) -> JSValue = { body, path, key in
            let ctx = JSContext.current()!
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.removeWhereKeyExists: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            return Self.runJSONOp(body, in: ctx) { root in
                guard let array = MITMJSONPatch.resolveNode(root, segments: segments) as? NSMutableArray else { return }
                let kept = array.filter { ($0 as? NSDictionary)?.object(forKey: key) == nil }
                array.setArray(kept)
            }
        }

        let removeWhereFieldInBlock: @convention(block) (JSValue, String, String, JSValue) -> JSValue = { body, path, field, valuesVal in
            let ctx = JSContext.current()!
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.removeWhereFieldIn: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            let needles = Self.jsonArrayValues(from: valuesVal, in: ctx)
            return Self.runJSONOp(body, in: ctx) { root in
                guard let array = MITMJSONPatch.resolveNode(root, segments: segments) as? NSMutableArray else { return }
                let kept = array.filter { element in
                    guard let object = element as? NSDictionary,
                          let fieldValue = object.object(forKey: field) else { return true }
                    return !needles.contains { MITMJSONPatch.valueEquals($0, fieldValue) }
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

    /// Bytes → parse → mutate → bytes, single choke-point for all json ops.
    private static func runJSONOp(_ body: JSValue, in ctx: JSContext, _ mutate: (inout Any) -> Void) -> JSValue {
        let original = bytesFromValue(body, in: ctx) ?? Data()
        guard var root = MITMJSONPatch.parse(original) else {
            return makeUint8Array(in: ctx, from: original)
        }
        // Return original bytes on a no-op edit: JSONSerialization round-trips can
        // reshape 64-bit IDs / high-precision decimals anywhere in the body.
        let before = MITMJSONPatch.snapshot(root)
        mutate(&root)
        guard !MITMJSONPatch.documentsEqual(before, root) else {
            return makeUint8Array(in: ctx, from: original)
        }
        guard let out = MITMJSONPatch.serialize(root) else {
            logger.warning("[MITM][JS] Anywhere.json: edited value is not serializable; body unchanged")
            return makeUint8Array(in: ctx, from: original)
        }
        return makeUint8Array(in: ctx, from: out)
    }

    private static func jsonPassthrough(_ body: JSValue, in ctx: JSContext) -> JSValue {
        makeUint8Array(in: ctx, from: bytesFromValue(body, in: ctx) ?? Data())
    }

    /// `undefined` → nil; `null` → NSNull; everything else → toObject().
    private static func jsonValue(from value: JSValue, in ctx: JSContext) -> Any? {
        if value.isUndefined { return nil }
        if value.isNull { return NSNull() }
        return value.toObject()
    }

    private static func jsonArrayValues(from value: JSValue, in ctx: JSContext) -> [Any] {
        if value.isUndefined || value.isNull { return [] }
        if value.isArray, let array = value.toArray() { return array }
        if let single = jsonValue(from: value, in: ctx) { return [single] }
        return []
    }

    private func installStoreGlobals(on anywhere: JSValue) {
        let store = JSValue(newObjectIn: context)!
        let storeGet: @convention(block) (String, Bool) -> JSValue = { [weak self] key, onDisk in
            let ctx = JSContext.current()!
            guard let scope = self?.currentInvocation?.scope,
                  let bytes = MITMScriptStore.shared.get(scope: scope, key: key, onDisk: onDisk)
            else { return JSValue(undefinedIn: ctx) }
            return Self.makeUint8Array(in: ctx, from: bytes)
        }
        let storeGetString: @convention(block) (String, Bool) -> JSValue = { [weak self] key, onDisk in
            let ctx = JSContext.current()!
            guard let scope = self?.currentInvocation?.scope,
                  let bytes = MITMScriptStore.shared.get(scope: scope, key: key, onDisk: onDisk),
                  let str = String(data: bytes, encoding: .utf8)
            else { return JSValue(undefinedIn: ctx) }
            return JSValue(object: str, in: ctx)
        }
        let storeSet: @convention(block) (String, JSValue, Bool) -> Void = { [weak self] key, val, onDisk in
            let ctx = JSContext.current()!
            guard let scope = self?.currentInvocation?.scope else { return }
            let bytes = Self.bytesFromValue(val, in: ctx) ?? Data()
            do {
                try MITMScriptStore.shared.set(scope: scope, key: key, value: bytes, onDisk: onDisk)
            } catch MITMScriptStore.StoreError.capacityExceeded {
                let cap = onDisk ? MITMScriptDiskStore.maxBytesPerScope : MITMScriptStore.maxBytesPerScope
                let err = JSValue(
                    newErrorFromMessage: "Anywhere.store: capacity exceeded (per-scope cap is \(cap) bytes)",
                    in: ctx
                )
                ctx.exception = err
            } catch MITMScriptStore.StoreError.writeFailed {
                let err = JSValue(newErrorFromMessage: "Anywhere.store: on-disk write failed", in: ctx)
                ctx.exception = err
            } catch {
                let err = JSValue(newErrorFromMessage: "Anywhere.store: \(error)", in: ctx)
                ctx.exception = err
            }
        }
        let storeDelete: @convention(block) (String, Bool) -> Void = { [weak self] key, onDisk in
            guard let scope = self?.currentInvocation?.scope else { return }
            MITMScriptStore.shared.delete(scope: scope, key: key, onDisk: onDisk)
        }
        let storeKeys: @convention(block) (Bool) -> [String] = { [weak self] onDisk in
            guard let scope = self?.currentInvocation?.scope else { return [] }
            return MITMScriptStore.shared.keys(scope: scope, onDisk: onDisk)
        }
        store.setObject(storeGet, forKeyedSubscript: "get" as NSString)
        store.setObject(storeGetString, forKeyedSubscript: "getString" as NSString)
        store.setObject(storeSet, forKeyedSubscript: "set" as NSString)
        store.setObject(storeDelete, forKeyedSubscript: "delete" as NSString)
        store.setObject(storeKeys, forKeyedSubscript: "keys" as NSString)
        anywhere.setObject(store, forKeyedSubscript: "store" as NSString)
    }

    private func installLogGlobals(on anywhere: JSValue) {
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

    private func installControlGlobals(on anywhere: JSValue) {
        let doneBlock: @convention(block) () -> Void = { [weak self] in
            self?.currentInvocation?.directive = .done
        }
        let exitBlock: @convention(block) () -> Void = { [weak self] in
            self?.currentInvocation?.directive = .exit
        }
        anywhere.setObject(doneBlock, forKeyedSubscript: "done" as NSString)
        anywhere.setObject(exitBlock, forKeyedSubscript: "exit" as NSString)

        let respondBlock: @convention(block) (JSValue) -> Void = { [weak self] spec in
            guard let self else { return }
            guard !spec.isUndefined, !spec.isNull else {
                self.currentInvocation?.directive = .respond(
                    SynthesizedResponse(status: 200, headers: [], body: Data())
                )
                return
            }
            // Clamp to 100…599: out-of-range status emits malformed HTTP/1 or HPACK.
            // Use toDouble (not toInt32) to prevent 2^32 wrap-around (4_294_967_496 → 200).
            let status: Int
            if let statusVal = spec.objectForKeyedSubscript("status"),
               statusVal.isNumber {
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
                let ctx = JSContext.current() ?? self.context
                body = Self.bytesFromValue(bodyVal, in: ctx) ?? Data()
            } else {
                body = Data()
            }
            self.currentInvocation?.directive = .respond(
                SynthesizedResponse(status: status, headers: headers, body: body)
            )
        }
        anywhere.setObject(respondBlock, forKeyedSubscript: "respond" as NSString)
    }

    // MARK: - Anywhere.http

    /// Anywhere.http — `get/post/request` returning a Promise of `{ status, headers, body, url }`.
    /// Available only in async buffered scripts; rejects in stream-script and on the sync path.
    private func installHTTPGlobals(on anywhere: JSValue) {
        let http = JSValue(newObjectIn: context)!
        let getBlock: @convention(block) (JSValue, JSValue) -> JSValue = { [weak self] urlVal, optsVal in
            let ctx = JSContext.current()!
            guard let self else { return Self.rejected("Anywhere.http: engine released", in: ctx) }
            return self.startHTTP(defaultMethod: "GET", urlVal: urlVal, optsVal: optsVal, in: ctx)
        }
        let postBlock: @convention(block) (JSValue, JSValue) -> JSValue = { [weak self] urlVal, optsVal in
            let ctx = JSContext.current()!
            guard let self else { return Self.rejected("Anywhere.http: engine released", in: ctx) }
            return self.startHTTP(defaultMethod: "POST", urlVal: urlVal, optsVal: optsVal, in: ctx)
        }
        let requestBlock: @convention(block) (JSValue) -> JSValue = { [weak self] specVal in
            let ctx = JSContext.current()!
            guard let self else { return Self.rejected("Anywhere.http: engine released", in: ctx) }
            let urlVal: JSValue = specVal.objectForKeyedSubscript("url") ?? JSValue(undefinedIn: ctx)
            return self.startHTTP(defaultMethod: "GET", urlVal: urlVal, optsVal: specVal, in: ctx)
        }
        http.setObject(getBlock, forKeyedSubscript: "get" as NSString)
        http.setObject(postBlock, forKeyedSubscript: "post" as NSString)
        http.setObject(requestBlock, forKeyedSubscript: "request" as NSString)
        anywhere.setObject(http, forKeyedSubscript: "http" as NSString)
    }

    private func startHTTP(defaultMethod: String, urlVal: JSValue, optsVal: JSValue, in ctx: JSContext) -> JSValue {
        guard let inv = currentInvocation, inv.allowsHTTP, inv.resumeQueue != nil else {
            return Self.rejected(
                "Anywhere.http is only available inside a buffered `script` rule — an `async function process(ctx)` that awaits it. It is unavailable in stream-script and on the synchronous path.",
                in: ctx
            )
        }
        guard !urlVal.isUndefined, !urlVal.isNull,
              let urlStr = urlVal.toString(),
              let url = URL(string: urlStr),
              let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = url.host, !host.isEmpty
        else {
            return Self.rejected("Anywhere.http: expected an absolute http(s) URL", in: ctx)
        }
        if inv.totalFetches >= Self.httpMaxTotalPerInvocation {
            return Self.rejected("Anywhere.http: per-invocation request cap (\(Self.httpMaxTotalPerInvocation)) reached", in: ctx)
        }
        if inv.inFlightFetches >= Self.httpMaxConcurrentPerInvocation {
            return Self.rejected("Anywhere.http: too many concurrent requests in this invocation (max \(Self.httpMaxConcurrentPerInvocation))", in: ctx)
        }
        if Self.globalFetchCount() >= Self.httpMaxConcurrentGlobal {
            return Self.rejected("Anywhere.http: global concurrent request cap (\(Self.httpMaxConcurrentGlobal)) reached", in: ctx)
        }

        let opts: JSValue? = optsVal.isObject ? optsVal : nil
        var request = URLRequest(url: url)
        let method = (opts?.objectForKeyedSubscript("method"))
            .flatMap { $0.isString ? $0.toString() : nil }?
            .uppercased() ?? defaultMethod
        // RFC 9110 token alphabet — reject CR/LF smuggling with a clear error.
        guard isValidHTTPHeaderName(method) else {
            return Self.rejected("Anywhere.http: invalid method token", in: ctx)
        }
        request.httpMethod = method
        if let headersVal = opts?.objectForKeyedSubscript("headers"), !headersVal.isUndefined, !headersVal.isNull {
            for header in Self.requestHeadersFromValue(headersVal, in: ctx) {
                request.addValue(header.value, forHTTPHeaderField: header.name)
            }
        }
        if let bodyVal = opts?.objectForKeyedSubscript("body"), !bodyVal.isUndefined, !bodyVal.isNull {
            request.httpBody = Self.bytesFromValue(bodyVal, in: ctx) ?? Data()
        }
        var timeout = Self.httpDefaultTimeout
        if let tVal = opts?.objectForKeyedSubscript("timeout"), tVal.isNumber {
            let ms = tVal.toDouble()
            if ms.isFinite, ms > 0 { timeout = min(ms / 1000.0, Self.httpMaxTimeout) }
        }
        request.timeoutInterval = timeout
        let followRedirects = (opts?.objectForKeyedSubscript("redirect"))
            .flatMap { $0.isString ? $0.toString() : nil } != "manual"
        let insecure: Bool
        if let iVal = opts?.objectForKeyedSubscript("insecure"), iVal.isBoolean {
            insecure = iVal.toBool()
        } else {
            insecure = AWCore.getAllowInsecure()
        }

        let maxBytes = Self.httpMaxResponseBytes

        let promise = JSValue(newPromiseIn: ctx, fromExecutor: { [weak self, weak inv] resolve, reject in
            guard let self else {
                reject?.call(withArguments: [Self.error("Anywhere.http: engine released", in: ctx)])
                return
            }
            // Executor runs synchronously, so inv is alive here; the completion's weak
            // capture drops a delivered/torn-down invocation and undoes the counters.
            guard let liveInv = inv else {
                reject?.call(withArguments: [Self.error("Anywhere.http: invocation released", in: ctx)])
                return
            }
            liveInv.inFlightFetches += 1
            liveInv.totalFetches += 1
            Self.reserveGlobalFetchSlot()
            MITMScriptHTTPClient.shared.send(
                request,
                followRedirects: followRedirects,
                insecure: insecure,
                maxBytes: maxBytes,
                // timeoutInterval bounds inactivity; resourceTimeout is the wall-clock cap.
                resourceTimeout: Self.invocationIdleTimeout
            ) { result in
                MITMScriptTransform.scriptQueue.async {
                    Self.releaseGlobalFetchSlot()
                    guard let inv else { return }   // delivered/torn down — drop
                    self.resumeFetch(inv: inv, resolve: resolve, reject: reject, result: result)
                }
            }
        })
        return promise ?? Self.rejected("Anywhere.http: could not create Promise", in: ctx)
    }

    /// Settling the Promise runs the `await` continuation synchronously.
    private func resumeFetch(
        inv: Invocation,
        resolve: JSValue?,
        reject: JSValue?,
        result: Result<MITMScriptHTTPClient.Response, Error>
    ) {
        invocationLock.lock()
        defer {
            invocationLock.unlock()
            collectIfBudgetExceeded()
        }
        if inv.inFlightFetches > 0 { inv.inFlightFetches -= 1 }
        // Progress: re-arm the watchdog for the continuation window.
        if !inv.delivered { armWatchdog(for: inv) }
        // Settle even if already delivered: a no-op in JS, but a `Promise.all`
        // still needs all legs settled to release JSC references.
        currentInvocation = inv
        defer { currentInvocation = nil }
        // The continuation runs synchronously — guard it: a `while(true)` after an await wedges here.
        runUserScript("async script (Anywhere.http resume continuation)") {
            switch result {
            case .success(let response):
                resolve?.call(withArguments: [Self.makeHTTPResponse(response, in: context)])
            case .failure(let error):
                reject?.call(withArguments: [Self.error("Anywhere.http: \(error.localizedDescription)", in: context)])
            }
        }
        if context.exception != nil { context.exception = nil }
    }

    // MARK: Anywhere.http helpers

    private static func error(_ message: String, in ctx: JSContext) -> JSValue {
        JSValue(newErrorFromMessage: message, in: ctx) ?? JSValue(newObjectIn: ctx)!
    }

    private static func rejected(_ message: String, in ctx: JSContext) -> JSValue {
        JSValue(newPromiseRejectedWithReason: error(message, in: ctx) as Any, in: ctx) ?? JSValue(undefinedIn: ctx)
    }

    private static func makeHTTPResponse(_ response: MITMScriptHTTPClient.Response, in ctx: JSContext) -> JSValue {
        let obj = JSValue(newObjectIn: ctx)!
        obj.setObject(response.status, forKeyedSubscript: "status" as NSString)
        let pairs: [[String]] = response.headers.map { [$0.name, $0.value] }
        obj.setObject(pairs, forKeyedSubscript: "headers" as NSString)
        obj.setObject(makeUint8Array(in: ctx, from: response.body), forKeyedSubscript: "body" as NSString)
        obj.setObject(response.finalURL as Any, forKeyedSubscript: "url" as NSString)
        return obj
    }

    /// Parses request headers from `[[name, value], …]` or `{ name: value }`, applying forbiddenRequestHeaders to both forms.
    private static func requestHeadersFromValue(_ value: JSValue, in ctx: JSContext) -> [(name: String, value: String)] {
        if value.isArray {
            // headersFromValue doesn't apply forbiddenRequestHeaders; apply here so both forms agree.
            return (headersFromValue(value) ?? []).filter { entry in
                guard !Self.forbiddenRequestHeaders.contains(entry.name.lowercased()) else {
                    logger.warning("[MITM][JS] Anywhere.http: dropping forbidden request header: \(entry.name)")
                    return false
                }
                return true
            }
        }
        guard value.isObject,
              let keys = ctx.objectForKeyedSubscript("Object")?.invokeMethod("keys", withArguments: [value]),
              keys.isArray
        else { return [] }
        guard let length = Self.validatedArrayLength(keys, max: 100_000) else { return [] }
        var out: [(name: String, value: String)] = []
        out.reserveCapacity(length)
        for i in 0..<length {
            guard let keyVal = keys.objectAtIndexedSubscript(i), let name = keyVal.toString(),
                  let valVal = value.objectForKeyedSubscript(name), !valVal.isUndefined, !valVal.isNull,
                  let val = valVal.toString()
            else { continue }
            guard isValidHTTPHeaderName(name) else {
                logger.warning("[MITM][JS] Anywhere.http: dropping request header with invalid name: \(name)")
                continue
            }
            guard isValidHTTPHeaderValue(val) else {
                logger.warning("[MITM][JS] Anywhere.http: dropping request header \(name) with CR/LF/NUL in value")
                continue
            }
            guard !Self.forbiddenRequestHeaders.contains(name.lowercased()) else {
                logger.warning("[MITM][JS] Anywhere.http: dropping forbidden request header: \(name)")
                continue
            }
            out.append((name: name, value: val))
        }
        return out
    }

    /// `Host` enables domain-fronting; the rest are framing/hop-by-hop smuggling vectors URLSession manages.
    private static let forbiddenRequestHeaders: Set<String> = [
        "host", "content-length", "connection", "transfer-encoding",
        "upgrade", "keep-alive", "te", "trailer", "expect", "proxy-connection",
    ]

    // MARK: Global Anywhere.http in-flight counter

    private static func reserveGlobalFetchSlot() {
        mitmScriptGlobalFetchLock.lock()
        mitmScriptGlobalFetchCount += 1
        mitmScriptGlobalFetchLock.unlock()
    }
    private static func releaseGlobalFetchSlot() {
        mitmScriptGlobalFetchLock.lock()
        if mitmScriptGlobalFetchCount > 0 { mitmScriptGlobalFetchCount -= 1 }
        mitmScriptGlobalFetchLock.unlock()
    }
    private static func globalFetchCount() -> Int {
        mitmScriptGlobalFetchLock.lock()
        defer { mitmScriptGlobalFetchLock.unlock() }
        return mitmScriptGlobalFetchCount
    }

    // MARK: - Body bridging (static so closures don't capture self)

    private static func makeUint8Array(in context: JSContext, from data: Data) -> JSValue {
        let count = data.count
        let projected: Int = {
            mitmScriptTypedArrayLock.lock()
            defer { mitmScriptTypedArrayLock.unlock() }
            return mitmScriptTypedArrayBytes + count
        }()
        if projected > hardTypedArrayBudget && count > 0 {
            logger.warning("[MITM][JS] typed-array budget exhausted (\(projected) B > \(hardTypedArrayBudget) B); returning empty Uint8Array")
            return makeUint8Array(in: context, from: Data())  // count=0 bypasses the cap
        }
        // Always allocate at least 1 byte: the deallocator needs a valid pointer.
        let buffer = UnsafeMutableRawPointer.allocate(byteCount: max(count, 1), alignment: 1)
        if count > 0 {
            data.copyBytes(to: buffer.assumingMemoryBound(to: UInt8.self), count: count)
        }
        if count > 0 {
            mitmScriptTypedArrayLock.lock()
            mitmScriptTypedArrayBytes += count
            mitmScriptTypedArrayLock.unlock()
        }
        // JSTypedArrayBytesDeallocator is a C function pointer and can't capture state; pass the
        // byte count via deallocatorContext so the deallocator can subtract from the global.
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

    /// Strict typed-array/ArrayBuffer extraction — no string fallback.
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
        guard exception == nil else { return nil }
        // JSObjectGetTypedArrayBytesPtr points at the backing buffer, not the view;
        // add byteOffset so a subarray reads its own slice, not the buffer's head.
        let offset = JSObjectGetTypedArrayByteOffset(ctxRef, obj, &exception)
        guard exception == nil,
              let ptr = JSObjectGetTypedArrayBytesPtr(ctxRef, obj, &exception),
              exception == nil
        else { return nil }
        return Data(bytes: ptr + offset, count: len)
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

    /// `.varint` carries raw unsigned 64-bit (zigzag is the script's concern); `.bytes` carries fixed/LEN payloads verbatim.
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

    /// Reads a varint at `offset` (absolute index), returning the value and the index past its last
    /// byte; nil on truncation, >10-byte encoding, or out-of-range offset (rather than trapping).
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
            // Field 0 is reserved; max is 2^29-1 per the protobuf spec.
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
                // Bound len in UInt64 space BEFORE narrowing: Int(len) traps for len ≥ 2^63 and
                // `idx + needed` can overflow — either crashes the extension on crafted wire.
                guard len <= UInt64(end - idx) else {
                    throw ProtobufError(description: "length-delimited field \(field) (len=\(len)) exceeds message")
                }
                let needed = Int(len)
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

    fileprivate static func parseProtobufEntries(_ val: JSValue, in context: JSContext) throws -> [ProtobufEntry] {
        guard val.isArray else {
            throw ProtobufError(description: "expected an array of {field, wire, value} entries")
        }
        guard let count = Self.validatedArrayLength(val, max: 10_000_000) else {
            throw ProtobufError(description: "input array length is missing, negative, or too large")
        }
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

    /// Lifts entries into a JS array; BigInt constructor hoisted out of the loop (per-entry lookup dominates decode time).
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

    /// Calls the global BigInt constructor via a decimal string — the only bridge path keeping full 64-bit precision.
    fileprivate static func makeBigInt(_ value: UInt64, in context: JSContext) -> JSValue {
        let bigIntFn = context.objectForKeyedSubscript("BigInt")
        return bigIntFn?.call(withArguments: [String(value)]) ?? JSValue(undefinedIn: context)
    }

    /// Number accepted only in safe-int range (≤2^53); larger values must be BigInt to avoid silent precision loss.
    fileprivate static func uint64FromJSValue(_ val: JSValue) -> UInt64? {
        if val.isUndefined || val.isNull { return nil }
        if val.isNumber {
            let d = val.toDouble()
            guard d.isFinite, d >= 0, d <= 9_007_199_254_740_991.0, d == d.rounded() else {
                return nil
            }
            return UInt64(d)
        }
        guard let str = val.toString() else { return nil }
        return UInt64(str)
    }

    // MARK: - Base64URL / JWT helpers

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
        // Strip whitespace before padding math: Data(base64Encoded:) rejects it.
        s = s.filter { !$0.isWhitespace }
        let mod = s.count % 4
        if mod > 0 {
            s += String(repeating: "=", count: 4 - mod)
        }
        return Data(base64Encoded: s)
    }

    /// JS JSON.parse returning a real JS object the script can mutate. Swallows the exception
    /// on malformed input so the outer exception gate doesn't roll back the whole script.
    fileprivate static func parseJSON(_ str: String, in context: JSContext) -> JSValue? {
        let json = context.objectForKeyedSubscript("JSON")
        let result = json?.invokeMethod("parse", withArguments: [str])
        if context.exception != nil {
            context.exception = nil
            return nil
        }
        return result
    }

    /// Bytes-shaped inputs are base64url'd verbatim; anything else is JSON.stringify'd first. Nil on undefined/null.
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

    /// Process-wide registry of engines keyed by rule-set id. Serialization comes from the script
    /// queue, NOT the lwIP queue — calling apply/applyFrame there would race the shared JSContext.
    private static var engines: [UUID: MITMScriptEngine] = [:]
    private static var scopelessEngine: MITMScriptEngine?
    private static let registryLock = UnfairLock()

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

    /// Drops engines for removed rule sets; state survives an edit (the id is stable) and clears only on removal.
    static func purgeEngines(activeIDs: Set<UUID>) {
        registryLock.withLock {
            engines = engines.filter { activeIDs.contains($0.key) }
        }
    }

    /// Per-session lazy handle to the shared engine for a rule set.
    final class Provider {
        private let scope: UUID?
        init(scope: UUID?) { self.scope = scope }
        func get() -> MITMScriptEngine { MITMScriptEngine.sharedEngine(forScope: scope) }
    }
}
