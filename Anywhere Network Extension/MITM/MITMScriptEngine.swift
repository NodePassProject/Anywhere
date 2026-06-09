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

/// Running count of ``Anywhere.http`` fetches in flight across every
/// ``MITMScriptEngine``, bounded by
/// ``MITMScriptEngine/httpMaxConcurrentGlobal``. File-private so the engine's
/// static reserve/release helpers can touch it without per-engine state, the
/// same shape as ``mitmScriptTypedArrayBytes`` above.
private nonisolated(unsafe) var mitmScriptGlobalFetchCount: Int = 0
private let mitmScriptGlobalFetchLock = UnfairLock()

/// Per-``MITMSession`` JavaScript runtime for the
/// ``CompiledMITMOperation/script`` rule. One ``JSContext`` is reused
/// across every script invocation on the connection; compiled functions
/// are cached by source content so duplicate scripts share work.
///
/// A runaway JS call can't be *preempted* from another thread:
/// ``JSContextGroupSetExecutionTimeLimit`` (WebKit SPI in
/// ``JSContextRefPrivate.h``) is the only API that would, and its symbol trips
/// App Review's scanner on sight — it appears verbatim in the Mach-O import
/// table however the call site is wrapped — with no public substitute that
/// stops a synchronous call already running in JSC. So a user ``process(ctx)``
/// that loops forever, recurses without bound, or backtracks a pathological
/// regex can't be interrupted; instead it is *contained* and *recovered from*.
/// Invocations run off the lwIP queue on ``MITMScriptTransform``'s serial
/// script queue, so a runaway parks its own connection and stalls the scripts
/// queued behind it but never the tunnel's packet flow. And because it can't be
/// interrupted it is watched: a synchronous span that outruns its hard cap
/// trips ``MITMScriptWatchdog``, which crashes the extension for a clean OS
/// relaunch, while an async script whose promise never settles is reverted by
/// the ``invocationIdleTimeout`` watchdog — so an otherwise-unbounded wedge
/// becomes a bounded, self-recovering one. The engine also reverts uncaught
/// throws, so a script that fails partway leaves the wire untouched.
final class MITMScriptEngine {

    /// Engine-local spelling of ``HTTPMessage`` — the protocol-agnostic message
    /// the rewriters build, scripts mutate, and the rewriters re-emit. Aliased
    /// rather than renamed throughout the engine so the internals keep reading
    /// as `Message`, while the shared type lives at top level for the HTTP/1 and
    /// HTTP/2 rewriters (and a future shared rewrite pipeline) to build against.
    typealias Message = HTTPMessage

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

    /// Per-invocation state for one `process(ctx)` run. Because the async
    /// (``applyAsync``) path lets a script suspend at an `await Anywhere.http`
    /// call, several invocations can be *suspended at once* on the one shared
    /// ``JSContext`` while only one executes a synchronous span at any instant.
    /// Each carries its own scope and directive here, and the `store` /
    /// control / `http` blocks consult ``currentInvocation`` — the single span
    /// running right now — so a block always reads the scope and writes the
    /// directive of the invocation it is actually inside, never a neighbor's.
    ///
    /// The sync ``apply`` and ``applyFrame`` paths build a lightweight
    /// instance (``allowsHTTP`` false, no completion) that lives only for the
    /// duration of their one synchronous span; the async path's `init`
    /// carries the readback base, the ctx handle, the result promise, and the
    /// resume plumbing the network continuation needs.
    fileprivate final class Invocation {
        /// `Anywhere.store` scope for this run.
        let scope: UUID?
        /// Whether `Anywhere.http` may be called here. False on the
        /// per-frame ``applyFrame`` path (the head is already on the wire and
        /// there is no place to suspend a stream) and on the synchronous
        /// ``apply`` path (it can't await).
        let allowsHTTP: Bool
        /// Set by `Anywhere.done` / `exit` / `respond` during a span; read at
        /// settlement.
        var directive: Directive?

        // Async buffered-script fields — nil/unused on the sync + frame paths.
        /// The message as it entered the engine: the revert target and the
        /// readback base.
        let original: Message?
        /// The ctx object handed to `process(ctx)`; read back for `body` when
        /// the script settles.
        var ctxValue: JSValue?
        /// Queue the final ``Outcome`` is delivered on (the connection's lwIP
        /// queue).
        let resumeQueue: DispatchQueue?
        /// Fires exactly once with the final ``Outcome``.
        let completion: ((Outcome) -> Void)?
        /// The promise `process` returned, held so JSC keeps its `then`
        /// reactions alive while the script is suspended.
        var resultPromise: JSValue?
        /// Outstanding and lifetime `Anywhere.http` fetch counts, for the
        /// per-invocation caps.
        var inFlightFetches = 0
        var totalFetches = 0
        /// Set once the final ``Outcome`` has been delivered so a late or
        /// duplicate settlement is ignored.
        var delivered = false

        /// Idle watchdog for the async path: armed when the script suspends
        /// and re-armed whenever a fetch makes progress. If it fires before the
        /// promise settles, the invocation is reverted and released so a
        /// never-settling promise can't park the connection forever.
        var watchdog: DispatchWorkItem?

        /// Async buffered-script invocation (``applyAsync``).
        init(scope: UUID?, original: Message, resumeQueue: DispatchQueue, completion: @escaping (Outcome) -> Void) {
            self.scope = scope
            self.allowsHTTP = true
            self.original = original
            self.resumeQueue = resumeQueue
            self.completion = completion
        }

        /// Lightweight synchronous-span invocation (sync ``apply`` /
        /// ``applyFrame``): carries only scope, the HTTP gate, and the
        /// directive slot.
        init(scope: UUID?, allowsHTTP: Bool) {
            self.scope = scope
            self.allowsHTTP = allowsHTTP
            self.original = nil
            self.resumeQueue = nil
            self.completion = nil
        }
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

    /// The invocation whose synchronous JS span is executing right now, or
    /// nil between spans — including while one or more async invocations sit
    /// suspended at an `await`. Set immediately before invoking the user
    /// function (and re-set before each network-driven resume) and cleared on
    /// return, so the `store` / control / `http` blocks always resolve to the
    /// invocation they are actually running inside: a stray or re-entrant
    /// call can't leak into the wrong scope, and the directive a script sets
    /// lands on its own invocation. Touched only on the script-execution
    /// thread (serialized by ``invocationLock`` + the serial script queue),
    /// so a plain field suffices.
    private var currentInvocation: Invocation?

    /// Async invocations currently suspended at an `await`, retained here from
    /// suspension (``applyAsync``) until ``deliver`` so they outlive the local
    /// that created them and the *weak* captures in the fetch-completion and
    /// promise-settle closures. Keyed by identity. Mutated only under
    /// ``invocationLock`` on a script span.
    private var liveInvocations: [ObjectIdentifier: Invocation] = [:]

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

    /// Serializes the engine's **synchronous JS spans**. One engine is shared
    /// by every connection to its rule set, and all spans are funneled through
    /// ``MITMScriptTransform``'s single serial script queue — off the lwIP
    /// queue, so a slow span parks its connection instead of stalling packet
    /// processing (see ``MITMScriptTransform/scriptQueue``).
    ///
    /// A "span" is one uninterrupted run of JS: a sync ``apply`` /
    /// ``applyFrame``, or — on the async ``applyAsync`` path — the initial
    /// `process(ctx)` call and each later resume that resolves an awaited
    /// ``Anywhere.http`` fetch. The lock is taken at the start of a span and
    /// released when it ends; it is **never held across an `await`**, so while
    /// a script is suspended waiting on the network the queue and the lock are
    /// both free for other connections' spans. That is what makes the async
    /// path non-blocking. The serial queue already orders spans; the lock keeps
    /// the one-span-at-a-time contract enforceable at the engine boundary —
    /// guarding ``currentInvocation`` / ``compiled`` against a future refactor
    /// that runs spans on a concurrent queue or a second VM. Cost is a single
    /// uncontended ``NSLock`` acquisition per span.
    private let invocationLock = NSLock()

    /// Threshold above which we ask JSC to GC after the next script
    /// invocation completes. 16 MiB leaves ample room for in-flight
    /// bodies in normal use while keeping the worst-case pin time
    /// short.
    private static let softTypedArrayBudget: Int = 16 * 1024 * 1024
    /// Hard cap on outstanding typed-array bytes. Past this we refuse
    /// new allocations and hand the script an empty Uint8Array.
    /// Bounds the worst-case NE memory cost across all engines
    /// regardless of GC pressure; the script sees truncated body bytes,
    /// better than running out of memory.
    private static let hardTypedArrayBudget: Int = 32 * 1024 * 1024

    // MARK: Anywhere.http caps
    //
    // Bounds on the outbound requests a buffered script can make via
    // ``Anywhere.http``. Each parked fetch holds the connection (the rewriter
    // parked it; the shared script queue stays free) and the invocation's ctx
    // body, so the per-invocation count + the per-request and total wall-clock
    // timeouts bound how long one connection can stay parked, and the global
    // in-flight cap bounds the extension's total outbound concurrency.

    /// Default per-request timeout when the script doesn't set `timeout`.
    private static let httpDefaultTimeout: TimeInterval = 10
    /// Hard ceiling on the per-request `timeout` option (clamped down to this).
    private static let httpMaxTimeout: TimeInterval = 30
    /// Most fetches one invocation may have in flight at once.
    private static let httpMaxConcurrentPerInvocation = 4
    /// Most fetches one invocation may make over its whole lifetime.
    private static let httpMaxTotalPerInvocation = 16
    /// Largest response body handed back to a script (also bounded by the
    /// shared typed-array budget). Mirrors the buffered-body cap.
    private static let httpMaxResponseBytes = 4 * 1024 * 1024
    /// Most fetches in flight at once across every engine in the extension.
    private static let httpMaxConcurrentGlobal = 32

    /// Idle ceiling for a suspended async ``process(ctx)`` — the longest the
    /// engine waits with no fetch making progress before it reverts the
    /// invocation. Comfortably exceeds a single fetch's ``httpMaxTimeout`` so a
    /// slow-but-progressing request isn't cut off, while bounding a script
    /// whose returned promise never settles (e.g. `new Promise(() => {})`, or
    /// an `await` that never resolves) — which the per-fetch timeout can't catch.
    private static let invocationIdleTimeout: TimeInterval = httpMaxTimeout + 30

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

    /// Runs one synchronous JSC execution span under ``MITMScriptWatchdog`` so a
    /// user script that loops or recurses without bound — which JSC cannot
    /// preempt — is detected from the monitor queue and crashes the extension
    /// past the hard cap instead of silently wedging the shared script queue
    /// forever. ``label`` is a cheap identifier (the script source, by
    /// reference) for the crash report. The watchdog brackets the *entire*
    /// synchronous span, so any built-in JS the Swift bridge invokes during it
    /// (``JSON.parse``, ``BigInt`` …) is already covered and needs no separate
    /// guard.
    @inline(__always)
    private func runUserScript<T>(_ label: String, _ body: () -> T) -> T {
        MITMScriptWatchdog.begin(label)
        defer { MITMScriptWatchdog.end() }
        return PerformanceMonitor.measure(.mitmScript, body)
    }

    // NB: there is intentionally no synchronous `apply(_:source:sourceKey:)`.
    // Every rewriter call site goes through ``MITMScriptTransform/apply`` →
    // ``applyAsync`` so a slow or `await`-ing script parks its connection off
    // the lwIP queue. A sync variant existed and was unused (dead code that
    // could silently drift from the async path it mirrored); it was removed.

    /// Maps a settled buffered-script invocation to an ``Outcome``: the
    /// shared readback decision used by ``apply`` and the async
    /// ``finishSuccess``. A directive set by the script wins over a tail-end
    /// uncaught throw (the script already expressed its decision before
    /// stumbling — typically into an ``Anywhere.store.set`` over the
    /// per-scope cap — and rolling back would discard it); a bare uncaught
    /// throw reverts to ``original`` so a half-formed rewrite never reaches
    /// the wire. Clears ``context.exception`` either way.
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

    /// Turns a control directive into an ``Outcome``. ``Anywhere.respond`` is
    /// honored only on the request phase; on the response phase the script
    /// can already rewrite via ctx mutations, so it degrades to ``.modified``.
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

    /// True when ``value`` is a thenable — an object with a callable `then`
    /// (an `async function`'s return, or any Promise). The async script path
    /// branches on this to decide whether to suspend; the sync path uses it
    /// to detect (and reject) a script it can't await.
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

    /// Async, non-blocking counterpart to ``apply``. Runs `process(ctx)` and,
    /// when it returns a thenable (an `async function`, typically because it
    /// `await`ed an ``Anywhere.http`` call), suspends **without holding**
    /// ``MITMScriptTransform/scriptQueue``: the span returns, the queue is
    /// freed for other connections' scripts, and the JS frame stays parked in
    /// JSC until the awaited fetch resolves. ``completion`` fires exactly once
    /// on ``resumeQueue`` when the script — and every fetch it awaited —
    /// settles. A synchronous `process` settles inline, exactly like
    /// ``apply``.
    ///
    /// Must be called on ``MITMScriptTransform/scriptQueue`` (the per-span
    /// ``invocationLock`` is acquired here and released when the span ends,
    /// never held across an `await`).
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
            // Synchronous completion: a plain `process`, or an `async`
            // one that finished without ever suspending. Read back and
            // finalize inline — identical to ``apply``.
            currentInvocation = nil
            let updated = readBack(message, from: ctxArg)
            deliver(finalize(original: message, updated: updated, directive: inv.directive), for: inv)
            return
        }
        // The script suspended at an `await`. Hold the returned promise so
        // JSC keeps its reactions reachable, attach settle handlers, and end
        // the span — the queue is free now. The handlers run later, on the
        // scriptQueue span that resolves the awaited fetch (see
        // ``resumeFetch``); for an already-settled promise they may run
        // during ``attachSettleHandlers`` below, which is fine.
        inv.resultPromise = returned
        liveInvocations[ObjectIdentifier(inv)] = inv
        currentInvocation = nil
        // Arm the idle watchdog before attaching handlers: if the promise is
        // already settled, ``attachSettleHandlers`` delivers synchronously and
        // ``deliver`` cancels the timer; otherwise it bounds the suspension.
        armWatchdog(for: inv)
        attachSettleHandlers(to: returned, for: inv)
    }

    /// Attaches `then(onFulfilled, onRejected)` to the promise `process`
    /// returned. The handlers capture ``inv`` weakly: while the script is
    /// suspended the invocation is kept alive by the in-flight fetch's
    /// completion closure, and at settlement that closure is still on the
    /// stack — so a weak capture is always live when a handler fires while
    /// avoiding an inv→promise→reaction→inv retain cycle.
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
        // A throw from inside `then` itself (not from the script) would land
        // on the context; clear it so it can't contaminate the next span.
        if context.exception != nil { context.exception = nil }
    }

    /// The script's returned promise fulfilled. Read back ``ctx.body`` and
    /// finalize with the same directive/exception precedence as ``apply``.
    /// Runs on a scriptQueue span (the initial attach, or a fetch
    /// resolution), so ``context`` access is serialized.
    private func finishSuccess(_ inv: Invocation) {
        guard !inv.delivered, let original = inv.original, let ctxArg = inv.ctxValue else { return }
        let updated = readBack(original, from: ctxArg)
        deliver(finalize(original: original, updated: updated, directive: inv.directive), for: inv)
    }

    /// The script's returned promise rejected (an uncaught throw on an async
    /// path — `await`ing a rejected fetch the script didn't `try/catch`, or a
    /// throw after the first suspension). Mirrors the sync uncaught-throw
    /// rule: a directive set before the throw still wins; otherwise revert to
    /// the original message so nothing half-formed reaches the wire.
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

    /// Delivers the final ``Outcome`` for an async invocation exactly once,
    /// on its resume queue, and breaks the invocation's hold on JS objects so
    /// the ctx body and the result promise can be collected promptly.
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

    /// (Re)arms ``Invocation/watchdog`` on ``MITMScriptTransform/scriptQueue``.
    /// Any prior timer is cancelled first. On expiry — only if the invocation
    /// hasn't already settled — the script is reverted to its original message
    /// and released. The work item runs on ``scriptQueue`` (serialized with the
    /// settle handlers) and takes ``invocationLock`` like every other delivery
    /// path; ``deliver`` cancels the timer, so a normal settlement always wins.
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

    /// Asks JSC to run GC when outstanding ``NoCopy`` Uint8Array bytes
    /// have crossed ``softTypedArrayBudget``. JSC's GC scheduler is
    /// otherwise driven by JS-heap accounting only and has no idea
    /// the native ``NoCopy`` buffers are pinning megabytes of host
    /// memory, so we ask it explicitly before a chatty stream's pins
    /// pile up.
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
        // Per-frame execution is synchronous and ``Anywhere.http`` is
        // unavailable (the head is already on the wire; there is nowhere to
        // suspend a live stream). The lightweight invocation just carries the
        // store scope and the directive slot for this frame.
        let inv = Invocation(scope: ctx.ruleSetID, allowsHTTP: false)
        currentInvocation = inv
        defer { currentInvocation = nil }
        let ctxArg = makeFrameContextValue(ctx, frame: frame, state: state)
        _ = runUserScript(source) { function.call(withArguments: [ctxArg]) }
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
        if let directive = inv.directive {
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

    /// Drops compiled-function cache entries whose ``sourceKey`` is not in
    /// ``keep`` — the set of script sources still active for this engine's rule
    /// set after a reload. Editing a script's source in place changes its
    /// content-hash key, so a new entry is compiled while the old one would
    /// otherwise linger for the engine's lifetime (the engine is retained
    /// across edits since its rule-set id is stable — see
    /// ``MITMRewritePolicy/load`` / ``purgeEngines``), accumulating a pinned
    /// JSC function per edit. Called from ``MITMScriptTransform/prewarm`` on the
    /// script queue right after the set's current sources are (re)compiled, so
    /// the dropped ``JSValue`` functions release on the VM-owning queue.
    func pruneCompiled(keeping keep: Set<Int>) {
        invocationLock.lock()
        defer { invocationLock.unlock() }
        let stale = compiled.keys.filter { !keep.contains($0) }
        for key in stale { compiled.removeValue(forKey: key) }
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
        // The IIFE runs the user's top-level code immediately, so a `while(true)`
        // outside `process` would hang here — guard the compile span too.
        let value = runUserScript(source) { context.evaluateScript(wrapped) }
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

    /// Reads the one script-mutable field, ``body``, off the post-call ctx
    /// and returns the updated ``Message``. Every other field is read-only
    /// (see ``Message``), so a script's assignment to ``method`` / ``url`` /
    /// ``status`` / ``headers`` is ignored and the originals carry through —
    /// which is what makes request-line / header / URL injection from a rule
    /// set impossible.
    private func readBack(_ original: Message, from ctx: JSValue) -> Message {
        var msg = original
        if let body = ctx.objectForKeyedSubscript("body"),
           let bytes = Self.bytesFromValue(body, in: context) {
            msg.body = bytes
        }
        return msg
    }

    /// Reads a JS array's `length` as a safe, non-negative element count, or
    /// nil when it is missing / non-finite / negative / implausibly large.
    ///
    /// `JSValue.toInt32()` applies ECMAScript ToInt32, which **wraps** a length
    /// of 2^31 or more to a *negative* `Int` — and `0..<negative` traps,
    /// crashing the whole extension (every tunnelled flow) from a one-line
    /// untrusted script such as `new Array(2**31)`. Reading the true length as
    /// a double and bounding it closes both the crash and the multi-billion-
    /// iteration spin a merely-non-negative huge length would cause. `max` is
    /// generous — far above any real header list / message — since the point is
    /// only to reject the pathological.
    private static func validatedArrayLength(_ value: JSValue, max: Int) -> Int? {
        guard let lengthVal = value.objectForKeyedSubscript("length"), lengthVal.isNumber else {
            return nil
        }
        let raw = lengthVal.toDouble()
        guard raw.isFinite, raw >= 0, raw <= Double(max) else { return nil }
        return Int(raw)
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
        // values that then fail ``isValidHTTPHeaderName`` (dropping the
        // entry) or land on the wire verbatim from value position.
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
        // Must follow the ``Anywhere`` install: the shim captures
        // ``Anywhere.codec.utf8`` to back the native text codecs.
        installTextCodecGlobals()
    }

    /// Installs WHATWG ``TextEncoder`` / ``TextDecoder`` on the JS global,
    /// backed by the native UTF-8 path of ``Anywhere.codec.utf8``.
    ///
    /// JavaScriptCore has no `TextEncoder` / `TextDecoder` (they're Web APIs,
    /// not ECMAScript), so a script that needs them ships a JS polyfill that
    /// walks the body char-by-char — the dominant cost when a rewrite touches
    /// a large response. Such polyfills self-install only when the global is
    /// absent (`globalThis.TextEncoder || install`), so a native one here
    /// takes over and routes the round-trip through the Swift codec; a script
    /// that never decodes pays nothing.
    ///
    /// `encode` / `decode` are captured from ``Anywhere.codec.utf8`` so the
    /// bridge survives a script reassigning ``Anywhere``. To stand in for a
    /// real ``TextDecoder``, `decode` must be lossy (invalid UTF-8 → U+FFFD,
    /// never "") and must honour the view's byte offset (see
    /// ``typedArrayBytesFromValue``); a script that decodes the body one
    /// field at a time relies on both, and either one wrong breaks it
    /// silently. Only the exercised subset exists: constructor `encoding` /
    /// `fatal` / `ignoreBOM` and one-shot `encode` / `decode`.
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
            // Lossy: invalid UTF-8 becomes U+FFFD rather than discarding the
            // whole string, so decoding a buffer that is only partly text
            // (one field of a binary body) still yields the text it holds.
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
            // Lenient, matching ``base64url.decode``: ``.ignoreUnknownCharacters``
            // skips embedded whitespace / newlines so wrapped or pretty-printed
            // base64 decodes instead of silently yielding an empty array (plain
            // ``Data(base64Encoded:)`` rejects any whitespace).
            return Self.makeUint8Array(in: ctx, from: Data(base64Encoded: str, options: .ignoreUnknownCharacters) ?? Data())
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
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.add: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            return Self.runJSONOp(body, in: ctx) { root in
                root = MITMJSONPatch.applyAtPath(root, segments: segments, mode: .add, value: v)
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
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.replace: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: ctx)
            }
            return Self.runJSONOp(body, in: ctx) { root in
                root = MITMJSONPatch.applyAtPath(root, segments: segments, mode: .replace, value: v)
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
                MITMJSONPatch.replaceKeyRecursive(root, key: key, value: v)
            }
        }

        // delete(body, path) — remove the addressed member/element.
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

        // deleteRecursive(body, key) — remove every property named `key`,
        // at any depth. Bare key name, not a path (mirror of
        // replaceRecursive).
        let deleteRecursiveBlock: @convention(block) (JSValue, String) -> JSValue = { body, key in
            let ctx = JSContext.current()!
            return Self.runJSONOp(body, in: ctx) { root in
                MITMJSONPatch.deleteKeyRecursive(root, key: key)
            }
        }

        // removeWhereKeyExists(body, path, key) — at the array addressed
        // by `path`, drop every element that is an object containing
        // `key`. Non-object elements (and objects lacking the key) are
        // kept. No-op if the path doesn't resolve to an array.
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

        // removeWhereFieldIn(body, path, field, values) — at the array
        // addressed by `path`, drop every element that is an object whose
        // `field` equals one of `values` (JSON-value equality; `values`
        // may be an array or a lone scalar). Elements without `field` are
        // kept. No-op if the path doesn't resolve to an array.
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

    /// Bytes → parsed JSON → ``mutate`` → bytes. The single choke point
    /// every ``Anywhere.json`` method routes through, so the
    /// parse-once / emit-compact / pass-through-on-failure contract lives
    /// in exactly one place. ``mutate`` receives the root as ``inout`` so
    /// an op can both edit a container in place (the common case) and
    /// swap the root wholesale (a ``$``-targeted replace).
    private static func runJSONOp(_ body: JSValue, in ctx: JSContext, _ mutate: (inout Any) -> Void) -> JSValue {
        let original = bytesFromValue(body, in: ctx) ?? Data()
        guard var root = MITMJSONPatch.parse(original) else {
            return makeUint8Array(in: ctx, from: original)
        }
        // No-op guard, mirroring ``MITMJSONPatch.applyAll``: snapshot the parsed
        // document, run the edit, and if nothing actually changed return the
        // ORIGINAL bytes rather than re-serializing. JSONSerialization
        // round-trips reshape 64-bit IDs / high-precision decimals *anywhere* in
        // the body, so an op that resolved nothing (e.g. a `$.missing` path or a
        // predicate that matched no element) must not be allowed to silently
        // corrupt untouched numbers — the same guard the native ``applyAll``
        // path applies.
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

    /// Returns the body bytes verbatim as a fresh ``Uint8Array`` — used
    /// for the early-out paths (undefined value, malformed path) so a
    /// rejected edit leaves even the byte layout untouched, rather than
    /// silently re-emitting a body we never actually changed.
    private static func jsonPassthrough(_ body: JSValue, in ctx: JSContext) -> JSValue {
        makeUint8Array(in: ctx, from: bytesFromValue(body, in: ctx) ?? Data())
    }

    /// Converts a script-supplied value into its Foundation JSON form.
    /// ``undefined`` maps to nil (the caller treats that as "no value
    /// given"); ``null`` maps to ``NSNull``. Everything else rides
    /// ``JSValue/toObject`` — JSON-shaped inputs become
    /// ``NSNumber`` / ``NSString`` / ``NSArray`` / ``NSDictionary``;
    /// anything exotic survives only until ``MITMJSONPatch/serialize`` rejects it.
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

    /// Installs ``Anywhere.store`` — per-rule-set persistent key/value
    /// state. ``[weak self]`` on each block so the JSC-held closures
    /// don't retain the engine.
    private func installStoreGlobals(on anywhere: JSValue) {
        let store = JSValue(newObjectIn: context)!
        let storeGet: @convention(block) (String) -> JSValue = { [weak self] key in
            let ctx = JSContext.current()!
            guard let scope = self?.currentInvocation?.scope,
                  let bytes = MITMScriptStore.shared.get(scope: scope, key: key)
            else { return JSValue(undefinedIn: ctx) }
            return Self.makeUint8Array(in: ctx, from: bytes)
        }
        let storeGetString: @convention(block) (String) -> JSValue = { [weak self] key in
            let ctx = JSContext.current()!
            guard let scope = self?.currentInvocation?.scope,
                  let bytes = MITMScriptStore.shared.get(scope: scope, key: key),
                  let str = String(data: bytes, encoding: .utf8)
            else { return JSValue(undefinedIn: ctx) }
            return JSValue(object: str, in: ctx)
        }
        let storeSet: @convention(block) (String, JSValue) -> Void = { [weak self] key, val in
            let ctx = JSContext.current()!
            guard let scope = self?.currentInvocation?.scope else { return }
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
            guard let scope = self?.currentInvocation?.scope else { return }
            MITMScriptStore.shared.delete(scope: scope, key: key)
        }
        let storeKeys: @convention(block) () -> [String] = { [weak self] in
            guard let scope = self?.currentInvocation?.scope else { return [] }
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
            self?.currentInvocation?.directive = .done
        }
        let exitBlock: @convention(block) () -> Void = { [weak self] in
            self?.currentInvocation?.directive = .exit
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
                self.currentInvocation?.directive = .respond(
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
            self.currentInvocation?.directive = .respond(
                SynthesizedResponse(status: status, headers: headers, body: body)
            )
        }
        anywhere.setObject(respondBlock, forKeyedSubscript: "respond" as NSString)
    }

    // MARK: - Anywhere.http

    /// Installs ``Anywhere.http`` — `get(url[, options])`, `post(url[,
    /// options])`, and `request(options)`, each returning a Promise that
    /// resolves to `{ status, headers, body, url }` or rejects with an Error.
    ///
    /// Available only inside a buffered `script` rule driven by ``applyAsync``:
    /// the script is an `async function process(ctx)` that `await`s the call.
    /// While the fetch is in flight the connection is parked but the shared
    /// script queue stays free (see ``applyAsync``). The call rejects on the
    /// synchronous fallback path and in `stream-script`, where there is no
    /// place to suspend (see ``Invocation/allowsHTTP``).
    ///
    /// `options`: `{ method, headers, body, timeout, redirect, insecure }`.
    /// `headers` is `[[name, value], …]` or a `{ name: value }` object; `body`
    /// is bytes (Uint8Array / ArrayBuffer / string); `timeout` is milliseconds
    /// (default ``httpDefaultTimeout``, clamped to ``httpMaxTimeout``);
    /// `redirect` is `"follow"` (default) or `"manual"`; `insecure` defaults to
    /// the global Allow-Insecure setting.
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
        // request({ url, method, … }) — the all-options form; `url` is read
        // from the spec, which doubles as the options object.
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

    /// Validates one ``Anywhere.http`` call against the current invocation and
    /// the caps, builds the `URLRequest`, and returns the Promise handed back
    /// to the script. The Promise's executor fires the request on
    /// ``MITMScriptHTTPClient``; its completion hops to ``scriptQueue`` and
    /// resumes the script through ``resumeFetch``. Runs inside a JS span, so
    /// ``currentInvocation`` names the awaiting invocation.
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
        // Validate the method against the RFC 9110 token alphabet (identical to
        // a header field-name). URLSession would itself reject a control-char
        // method, but checking here makes the doc's "methods produced by
        // scripts are validated" guarantee hold at this layer and rejects a
        // CR/LF smuggling attempt with a clear error.
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
            // `inv` is alive here — the executor runs synchronously as the
            // Promise is constructed — so bind it under a fresh name, leaving the
            // weak `inv` capture intact for the completion below, which needs it
            // weak to drop a delivered (e.g. idle-watchdog-reverted) or torn-down
            // invocation instead of resuming it. Counting the fetch and reserving
            // the global slot inside the executor keeps them on the same path the
            // completion's decrement/release undoes, so a Promise that fails to
            // construct leaks nothing. `self` is strong through the completion +
            // resume hop so the engine and its JSContext outlive an in-flight
            // fetch.
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
                // `request.timeoutInterval = timeout` above is the inactivity
                // bound (the documented per-request `timeout`); the total
                // wall-clock cap is the invocation idle ceiling so a
                // slow-but-progressing fetch isn't cut off at the inactivity
                // bound while still never outliving the invocation's backstop.
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

    /// Resumes a parked script when one of its ``Anywhere.http`` fetches
    /// completes. Runs on ``scriptQueue`` under ``invocationLock``. Settling
    /// the fetch's Promise drains JSC's microtasks and runs the script's
    /// `await` continuation synchronously: it either suspends again at another
    /// await (a new fetch armed; ``startHTTP`` reads ``currentInvocation``) or
    /// runs to completion, at which point the top-level settle handler
    /// (``finishSuccess`` / ``finishRejected``) delivers the Outcome.
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
        // A fetch just resolved — progress. Re-arm the idle watchdog so the
        // continuation (which may suspend again on another fetch or a
        // never-settling promise) gets a fresh window.
        if !inv.delivered { armWatchdog(for: inv) }
        // Settle even if `inv` already delivered (e.g. another awaited leg
        // rejected `process`): resolving an already-settled sibling Promise is
        // a JS no-op, and a `Promise.all` the script awaited still needs its
        // other legs settled to release JSC's references.
        currentInvocation = inv
        defer { currentInvocation = nil }
        // Settling the promise runs the script's `await` continuation
        // synchronously (user code after the await), so guard it like the other
        // spans — a `while(true)` after an `Anywhere.http` await wedges here.
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

    /// Builds the JS response object `{ status, headers, body, url }` for a
    /// resolved ``Anywhere.http`` Promise. `body` goes through
    /// ``makeUint8Array`` so it counts against the shared typed-array budget;
    /// `headers` mirrors `ctx.headers` as `[[name, value], …]`.
    private static func makeHTTPResponse(_ response: MITMScriptHTTPClient.Response, in ctx: JSContext) -> JSValue {
        let obj = JSValue(newObjectIn: ctx)!
        obj.setObject(response.status, forKeyedSubscript: "status" as NSString)
        let pairs: [[String]] = response.headers.map { [$0.name, $0.value] }
        obj.setObject(pairs, forKeyedSubscript: "headers" as NSString)
        obj.setObject(makeUint8Array(in: ctx, from: response.body), forKeyedSubscript: "body" as NSString)
        obj.setObject(response.finalURL as Any, forKeyedSubscript: "url" as NSString)
        return obj
    }

    /// Parses request headers from `[[name, value], …]` (via
    /// ``headersFromValue``) or a `{ name: value }` object, dropping entries
    /// with an invalid field-name or a value carrying CR / LF / NUL — the same
    /// validators the ctx-header readback uses.
    private static func requestHeadersFromValue(_ value: JSValue, in ctx: JSContext) -> [(name: String, value: String)] {
        if value.isArray {
            // ``headersFromValue`` validates the field-name token and rejects
            // CR/LF/NUL in values, but does NOT apply ``forbiddenRequestHeaders``
            // — only the object branch below did, so the array form could set
            // ``Host`` (internal-vhost access / domain-fronting, especially
            // behind the SSRF guard) and the framing / hop-by-hop headers the
            // filter exists to block. Apply the same filter here so both header
            // forms agree.
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

    /// Request headers a script may not set on an ``Anywhere.http`` call.
    /// `Host` would enable domain-fronting / internal-vhost access (especially
    /// combined with the SSRF guard in ``MITMScriptHTTPClient``); the rest are
    /// framing / hop-by-hop controls (request-smuggling vectors) that
    /// `URLSession` manages itself.
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
        // Hard cap: if we've already pinned ``hardTypedArrayBudget``
        // bytes across all engines, refuse the allocation and return
        // an empty view. JSC's GC may free the existing pins shortly,
        // but until it does, growing further risks an out-of-memory
        // crash. The script sees a smaller-than-expected body, which the
        // user can debug.
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
        guard exception == nil else { return nil }
        // ``JSObjectGetTypedArrayBytesPtr`` points at the start of the backing
        // buffer, not the view, so it ignores ``byteOffset``. Add it so a
        // subarray (e.g. ``body.subarray(pos, end)``) reads its own slice
        // rather than the buffer's head.
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
                // Bound the length in UInt64 space BEFORE narrowing to Int.
                // ``Int(len)`` TRAPS (it does not truncate) for len ≥ 2^63, and
                // even a sub-2^63 len can overflow the ``idx + needed`` addition —
                // either crashes the extension on crafted wire. ``end - idx`` is
                // the remaining byte count (always ≥ 0, since ``readVarint``
                // returns an index ≤ end), so a length within it narrows to a
                // valid in-range Int and the subdata range below can't overrun.
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

    /// Pulls a JS array of ``{field, wire, value}`` entries back into
    /// Swift. Validates shape strictly so a malformed entry surfaces
    /// as a catchable JS error rather than silently encoding garbage:
    /// wrong-length fixed payloads, non-numeric varints, and
    /// out-of-range field numbers all throw.
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
        // Drop ASCII whitespace / newlines first: wrapped or pretty-printed
        // tokens in the wild carry them, and they'd otherwise throw off the
        // padding math below (and `Data(base64Encoded:)` rejects them without
        // `.ignoreUnknownCharacters`). Stripping here keeps decode lenient as
        // documented while the padding count stays correct.
        s = s.filter { !$0.isWhitespace }
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
    /// Sharing across connections is safe because every script invocation runs
    /// on ``MITMScriptTransform/scriptQueue`` — a single process-wide serial
    /// queue — and each engine additionally guards its ``JSContext`` with
    /// ``invocationLock``, so no two scripts ever touch one engine's context
    /// concurrently. (NOTE: serialization comes from that script queue, NOT the
    /// lwIP queue — the lwIP queue only *dispatches* the work onto it. A caller
    /// that ran ``apply``/``applyFrame`` synchronously on the lwIP queue would
    /// break this invariant and run two contexts of the same engine — or the
    /// same context from two queues — concurrently.) Creation happens under
    /// ``registryLock`` so two callers racing to first-use a rule set can't
    /// build two engines for it — that would split the ``compiled`` cache and
    /// ``globalThis`` state and produce silent, hard-to-diagnose crosstalk
    /// within the rule set.
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
