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
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMScriptEngine")

/// Input-body bytes pinned by suspended async invocations, summed across all engines.
nonisolated private let mitmScriptSuspendedBodyBytes = Atomic<Int>(0)

/// In-flight Anywhere.http fetches across all engines, bounded by httpMaxConcurrentGlobal.
nonisolated private let mitmScriptGlobalFetchCount = Atomic<Int>(0)

actor MITMScriptEngine {

    nonisolated var unownedExecutor: UnownedSerialExecutor {
        JSCConcurrencyBridge.shared.executor.asUnownedSerialExecutor()
    }

    typealias Message = HTTPMessage
    
    struct SynthesizedResponse: Sendable {
        let status: Int
        let headers: [(name: String, value: String)]
        let body: Data
    }

    enum Outcome {
        case modified(Message)
        case done(Message)
        case exit
        case respond(SynthesizedResponse)
    }
    
    struct FrameContext {
        let phase: MITMPhase
        let method: String?
        let url: String?
        let originalUrl: String?
        let status: Int?
        let headers: [(name: String, value: String)]
        let frameIndex: Int
        let isLast: Bool
        let ruleSetID: UUID?
    }
    
    enum FrameOutcome {
        case modified(body: Data, state: JSValue?)
        case done(body: Data)
        case exit
    }
    
    fileprivate enum Directive: Sendable {
        case done
        case exit
        case respond(SynthesizedResponse)
    }
    
    fileprivate final class Invocation {
        let scope: UUID?
        let allowsHTTP: Bool
        var directive: Directive?
        
        let original: Message?
        var ctxValue: JSValue?
        var continuation: CheckedContinuation<Outcome, Never>?
        var resultPromise: JSValue?
        var inFlightFetches = 0
        var totalFetches = 0
        var delivered = false
        var pinnedBodyBytes = 0
        
        var watchdogDisarm: AsyncInbox<Void>?

        init(scope: UUID?, original: Message, continuation: CheckedContinuation<Outcome, Never>) {
            self.scope = scope
            self.allowsHTTP = true
            self.original = original
            self.continuation = continuation
        }

        /// Lightweight sync-span invocation: carries only scope, HTTP gate, and directive slot.
        init(scope: UUID?, allowsHTTP: Bool) {
            self.scope = scope
            self.allowsHTTP = allowsHTTP
            self.original = nil
            self.continuation = nil
        }
    }

    private var context: JSContext
    
    private struct CompiledEntry {
        let byteCount: Int
        let function: JSValue
    }
    
    private var compiled: [Int: CompiledEntry] = [:]

    private static let sharedVM: JSVirtualMachine = JSVirtualMachine()!
    
    private var liveInvocations: [ObjectIdentifier: Invocation] = [:]
    private var currentInvocation: Invocation?

    // MARK: - Watchdog task tree
    
    private struct WatchdogJob: Sendable {
        let id: ObjectIdentifier
        let disarm: AsyncInbox<Void>
    }
    private let watchdogJobs: AsyncStream<WatchdogJob>
    private nonisolated let watchdogJobContinuation: AsyncStream<WatchdogJob>.Continuation
    private var watchdogRoot: Task<Void, Never>?
    
    nonisolated private func activeScope() -> UUID? {
        assumeIsolated { $0.currentInvocation?.scope }
    }
    
    nonisolated private func setActiveDirective(_ directive: Directive) {
        assumeIsolated { $0.currentInvocation?.directive = directive }
    }
    
    private static let maxSuspendedBodyBytes: Int = 16 * 1024 * 1024

    // MARK: Anywhere.http caps

    private static let httpDefaultTimeout: TimeInterval = 10
    private static let httpMaxTimeout: TimeInterval = 30
    private static let httpMaxConcurrentPerInvocation = 4
    private static let httpMaxTotalPerInvocation = 16
    private static let httpMaxResponseBytes = 4 * 1024 * 1024
    private static let httpMaxConcurrentGlobal = 32
    
    private static let invocationIdleTimeout: TimeInterval = httpMaxTimeout + 30
    
    nonisolated private let isFormattingException = Atomic(false)

    init() {
        self.context = JSContext(virtualMachine: Self.sharedVM)
        (self.watchdogJobs, self.watchdogJobContinuation) = AsyncStream.makeStream(of: WatchdogJob.self)
        configureContext(context)
    }

    // MARK: - Watchdog tree driver
    
    private func runWatchdogTree() async {
        await withDiscardingTaskGroup { group in
            for await job in watchdogJobs {
                group.addTask { await self.runWatchdog(id: job.id, disarm: job.disarm) }
            }
            group.cancelAll()
        }
    }
    
    private func runWatchdog(id: ObjectIdentifier, disarm: AsyncInbox<Void>) async {
        let timedOut = await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                do { try await Task.sleep(for: .seconds(Self.invocationIdleTimeout)); return true }
                catch { return false }   // cancelled with the tree
            }
            group.addTask {
                _ = try? await disarm.next(); return false   // disarmed by deliver / re-arm
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
        guard timedOut else { return }
        guard let invocation = liveInvocations[id],
              !invocation.delivered,
              let original = invocation.original else { return }
        logger.warning("[MITM][JS] process(ctx) did not settle within \(Self.invocationIdleTimeout)s; reverting")
        deliver(.modified(original), for: invocation)
    }
    
    fileprivate func shutdown() {
        watchdogJobContinuation.finish()
        watchdogRoot?.cancel()
        watchdogRoot = nil
    }
    
    nonisolated private func configureContext(_ context: JSContext) {
        context.exceptionHandler = { [weak self] context, exception in
            defer { context?.exception = exception }
            if self?.isFormattingException.load(ordering: .relaxed) == true {
                logger.warning("[MITM][JS] uncaught (nested throw while formatting exception)")
                return
            }
            self?.isFormattingException.store(true, ordering: .relaxed)
            defer { self?.isFormattingException.store(false, ordering: .relaxed) }
            if let exception {
                logger.warning("[MITM][JS] uncaught: \(String(describing: exception))")
            } else {
                logger.warning("[MITM][JS] uncaught: <unknown>")
            }
        }
        installAnywhereGlobals(context: context)
    }
    
    @inline(__always)
    private func runUserScript<T>(_ label: String, _ body: () -> T) -> T {
        MITMScriptWatchdog.begin(label)
        defer { MITMScriptWatchdog.end() }
        return body()
    }
    
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
    
    private func isThenable(_ value: JSValue) -> Bool {
        guard value.isObject,
              let thenVal = value.objectForKeyedSubscript("then"),
              thenVal.isObject,
              let ref = thenVal.jsValueRef
        else { return false }
        let ctxRef = context.jsGlobalContextRef
        var exception: JSValueRef?
        guard let object = JSValueToObject(ctxRef, ref, &exception), exception == nil else {
            return false
        }
        return JSObjectIsFunction(ctxRef, object)
    }
    
    func applyAsync(
        _ message: Message,
        source: String,
        sourceKey: Int
    ) async -> Outcome {
        await JSCConcurrencyBridge.shared.runParked { (continuation: CheckedContinuation<Outcome, Never>) in
            self.runApply(message, source: source, sourceKey: sourceKey, continuation: continuation)
        }
    }
    
    private func runApply(
        _ message: Message,
        source: String,
        sourceKey: Int,
        continuation: CheckedContinuation<Outcome, Never>
    ) {
        let invocation = Invocation(scope: message.ruleSetID, original: message, continuation: continuation)
        let bodyBytes = message.body.count
        let pinned = Self.suspendedBodyBytes()
        if pinned + bodyBytes > Self.maxSuspendedBodyBytes {
            logger.warning("[MITM][JS] suspended-body budget reached (\(pinned) B pinned by awaiting scripts); passing this flow through unmodified")
            deliver(.modified(message), for: invocation)
            return
        }
        guard let function = compileIfNeeded(source, key: sourceKey) else {
            deliver(.modified(message), for: invocation)
            return
        }
        let contextValue = makeContextValue(message)
        invocation.ctxValue = contextValue
        currentInvocation = invocation
        let returned = runUserScript(source) { function.call(withArguments: [contextValue]) }
        guard let returned, isThenable(returned) else {
            currentInvocation = nil
            let updated = readBack(message, from: contextValue)
            deliver(finalize(original: message, updated: updated, directive: invocation.directive), for: invocation)
            return
        }
        invocation.pinnedBodyBytes = bodyBytes
        Self.addSuspendedBodyBytes(bodyBytes)
        invocation.resultPromise = returned
        liveInvocations[ObjectIdentifier(invocation)] = invocation
        currentInvocation = nil
        // Arm first: an already-settled promise delivers synchronously and deliver() cancels the timer.
        armWatchdog(for: invocation)
        attachSettleHandlers(to: returned, for: ObjectIdentifier(invocation))
    }
    
    private func attachSettleHandlers(to promise: JSValue, for id: ObjectIdentifier) {
        let onFulfilled: @convention(block) (JSValue) -> Void = { [weak self] _ in
            guard let self else { return }
            self.assumeIsolated { engine in
                guard let invocation = engine.liveInvocations[id] else { return }
                engine.finishSuccess(invocation)
            }
        }
        let onRejected: @convention(block) (JSValue) -> Void = { [weak self] reason in
            guard let self else { return }
            self.assumeIsolated { engine in
                guard let invocation = engine.liveInvocations[id] else { return }
                engine.finishRejected(invocation, reason: reason)
            }
        }
        promise.invokeMethod("then", withArguments: [onFulfilled, onRejected])
        if context.exception != nil { context.exception = nil }
    }

    private func finishSuccess(_ invocation: Invocation) {
        guard !invocation.delivered, let original = invocation.original, let ctxArg = invocation.ctxValue else { return }
        let updated = readBack(original, from: ctxArg)
        deliver(finalize(original: original, updated: updated, directive: invocation.directive), for: invocation)
    }
    
    private func finishRejected(_ invocation: Invocation, reason: JSValue?) {
        guard !invocation.delivered, let original = invocation.original else { return }
        let ctxArg = invocation.ctxValue ?? makeContextValue(original)
        let updated = readBack(original, from: ctxArg)
        context.exception = nil
        if let directive = invocation.directive {
            deliver(outcome(forDirective: directive, original: original, updated: updated), for: invocation)
        } else {
            if let reason {
                logger.warning("[MITM][JS] process(ctx) promise rejected: \(String(describing: reason))")
            }
            deliver(.modified(original), for: invocation)
        }
    }
    
    private func deliver(_ outcome: Outcome, for invocation: Invocation) {
        guard !invocation.delivered else { return }
        invocation.delivered = true
        invocation.watchdogDisarm?.finish()
        invocation.watchdogDisarm = nil
        liveInvocations.removeValue(forKey: ObjectIdentifier(invocation))
        if invocation.pinnedBodyBytes > 0 {
            Self.addSuspendedBodyBytes(-invocation.pinnedBodyBytes)
            invocation.pinnedBodyBytes = 0
        }
        invocation.resultPromise = nil
        invocation.ctxValue = nil
        let continuation = invocation.continuation
        invocation.continuation = nil
        continuation?.resume(returning: outcome)
    }
    
    private func armWatchdog(for invocation: Invocation) {
        if watchdogRoot == nil {
            watchdogRoot = Task { await self.runWatchdogTree() }
        }
        invocation.watchdogDisarm?.finish()
        let disarm = AsyncInbox<Void>(capacity: 1)
        invocation.watchdogDisarm = disarm
        watchdogJobContinuation.yield(WatchdogJob(id: ObjectIdentifier(invocation), disarm: disarm))
    }

    private static func suspendedBodyBytes() -> Int {
        mitmScriptSuspendedBodyBytes.load(ordering: .relaxed)
    }

    private static func addSuspendedBodyBytes(_ delta: Int) {
        mitmScriptSuspendedBodyBytes.wrappingAdd(delta, ordering: .relaxed)
    }
    
    func applyFrame(
        _ frame: Data,
        source: String,
        sourceKey: Int,
        frameContext: FrameContext,
        state: JSValue?
    ) -> FrameOutcome {
        guard let function = compileIfNeeded(source, key: sourceKey) else {
            return .modified(body: frame, state: state)
        }
        let invocation = Invocation(scope: frameContext.ruleSetID, allowsHTTP: false)
        currentInvocation = invocation
        defer { currentInvocation = nil }
        let ctxArg = makeFrameContextValue(frameContext, frame: frame, state: state)
        _ = runUserScript(source) { function.call(withArguments: [ctxArg]) }
        let body: Data
        if let bodyVal = ctxArg.objectForKeyedSubscript("body"),
           let bytes = Self.bytesFromValue(bodyVal, in: context) {
            body = bytes
        } else {
            body = frame
        }
        let updatedState = ctxArg.objectForKeyedSubscript("state")
        let hadException = context.exception != nil
        if let directive = invocation.directive {
            context.exception = nil
            switch directive {
            case .done: return .done(body: body)
            case .exit: return .exit
            case .respond:
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
    
    func precompile(source: String, sourceKey: Int) {
        _ = compileIfNeeded(source, key: sourceKey)
    }
    
    func pruneCompiled(keeping keep: Set<Int>) {
        let stale = compiled.keys.filter { !keep.contains($0) }
        for key in stale { compiled.removeValue(forKey: key) }
    }
    
    fileprivate func resetOnReload(keepingCompiled keep: Set<Int>) {
        guard currentInvocation == nil, liveInvocations.isEmpty else {
            pruneCompiled(keeping: keep)
            return
        }
        compiled.removeAll()
        context = JSContext(virtualMachine: Self.sharedVM)
        configureContext(context)
    }
    
    private func compileIfNeeded(_ source: String, key: Int) -> JSValue? {
        let byteCount = source.utf8.count
        if let cached = compiled[key] {
            if cached.byteCount == byteCount { return cached.function }
            logger.warning("[MITM][JS] cache-key collision: recompiling under same key")
        }
        let wrapped = "(function(){\n\"use strict\";\n\(source)\nreturn process;\n})()"
        let value = runUserScript(source) { context.evaluateScript(wrapped) }
        if context.exception != nil {
            context.exception = nil
            return nil
        }
        guard let value, !value.isUndefined, !value.isNull else {
            logger.warning("[MITM][JS] script did not define process(ctx)")
            return nil
        }
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
        let object = JSValue(newObjectIn: context)!
        object.setObject(
            msg.phase == .httpRequest ? "request" : "response",
            forKeyedSubscript: "phase" as NSString
        )
        object.setObject(msg.method as Any, forKeyedSubscript: "method" as NSString)
        object.setObject(msg.url as Any, forKeyedSubscript: "url" as NSString)
        object.setObject(msg.originalUrl as Any, forKeyedSubscript: "originalUrl" as NSString)
        object.setObject(msg.status as Any, forKeyedSubscript: "status" as NSString)
        let pairs: [[String]] = msg.headers.map { [$0.name, $0.value] }
        object.setObject(pairs, forKeyedSubscript: "headers" as NSString)
        object.setObject(Self.makeUint8Array(in: context, from: msg.body), forKeyedSubscript: "body" as NSString)
        return object
    }
    
    private func makeFrameContextValue(
        _ ctx: FrameContext,
        frame: Data,
        state: JSValue?
    ) -> JSValue {
        let object = JSValue(newObjectIn: context)!
        object.setObject(
            ctx.phase == .httpRequest ? "request" : "response",
            forKeyedSubscript: "phase" as NSString
        )
        object.setObject(ctx.method as Any, forKeyedSubscript: "method" as NSString)
        object.setObject(ctx.url as Any, forKeyedSubscript: "url" as NSString)
        object.setObject(ctx.originalUrl as Any, forKeyedSubscript: "originalUrl" as NSString)
        object.setObject(ctx.status as Any, forKeyedSubscript: "status" as NSString)
        let pairs: [[String]] = ctx.headers.map { [$0.name, $0.value] }
        object.setObject(pairs, forKeyedSubscript: "headers" as NSString)

        let frameInfo = JSValue(newObjectIn: context)!
        frameInfo.setObject(ctx.frameIndex, forKeyedSubscript: "index" as NSString)
        frameInfo.setObject(ctx.isLast, forKeyedSubscript: "end" as NSString)
        object.setObject(frameInfo, forKeyedSubscript: "frame" as NSString)
        
        let stateValue: JSValue
        if let state, state.context === context {
            stateValue = state
        } else {
            stateValue = JSValue(newObjectIn: context)!
        }
        object.setObject(stateValue, forKeyedSubscript: "state" as NSString)

        object.setObject(Self.makeUint8Array(in: context, from: frame), forKeyedSubscript: "body" as NSString)
        return object
    }
    
    private func readBack(_ original: Message, from ctx: JSValue) -> Message {
        var message = original
        if let body = ctx.objectForKeyedSubscript("body"),
           let bytes = Self.bytesFromValue(body, in: context) {
            message.body = bytes
        }
        return message
    }
    
    private static func validatedArrayLength(_ value: JSValue, max: Int) -> Int? {
        guard let lengthVal = value.objectForKeyedSubscript("length"), lengthVal.isNumber else {
            return nil
        }
        let raw = lengthVal.toDouble()
        guard raw.isFinite, raw >= 0, raw <= Double(max) else { return nil }
        return Int(raw)
    }
    
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
            guard HTTPHeader.isValidName(name) else {
                logger.warning("[MITM][JS] dropping header with invalid name: \(name)")
                continue
            }
            guard HTTPHeader.isValidValue(val) else {
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

    nonisolated private func installAnywhereGlobals(context: JSContext) {
        let anywhere = JSValue(newObjectIn: context)!
        installCodecGlobals(on: anywhere, context: context)
        installCryptoGlobals(on: anywhere, context: context)
        installJWTGlobals(on: anywhere, context: context)
        installJSONGlobals(on: anywhere, context: context)
        installStoreGlobals(on: anywhere, context: context)
        installParamsGlobals(on: anywhere, context: context)
        installLogGlobals(on: anywhere, context: context)
        installControlGlobals(on: anywhere, context: context)
        installHTTPGlobals(on: anywhere, context: context)
        context.setObject(anywhere, forKeyedSubscript: "Anywhere" as NSString)
        // Must follow Anywhere install: the shim captures Anywhere.codec.utf8.
        installTextCodecGlobals(context: context)
    }
    
    nonisolated private func installTextCodecGlobals(context: JSContext) {
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

    nonisolated private func installCodecGlobals(on anywhere: JSValue, context: JSContext) {
        let codec = JSValue(newObjectIn: context)!

        let utf8 = JSValue(newObjectIn: context)!
        let utf8Encode: @convention(block) (String) -> JSValue = { str in
            let context = JSContext.current()!
            return Self.makeUint8Array(in: context, from: Data(str.utf8))
        }
        let utf8Decode: @convention(block) (JSValue) -> String = { val in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: context) ?? Data()
            // Lossy: invalid UTF-8 → U+FFFD so partial-text buffers still decode.
            return String(decoding: bytes, as: UTF8.self)
        }
        utf8.setObject(utf8Encode, forKeyedSubscript: "encode" as NSString)
        utf8.setObject(utf8Decode, forKeyedSubscript: "decode" as NSString)
        codec.setObject(utf8, forKeyedSubscript: "utf8" as NSString)

        let base64 = JSValue(newObjectIn: context)!
        let base64Encode: @convention(block) (JSValue) -> String = { val in
            let context = JSContext.current()!
            return (Self.bytesFromValue(val, in: context) ?? Data()).base64EncodedString()
        }
        let base64Decode: @convention(block) (String) -> JSValue = { str in
            let context = JSContext.current()!
            // Lenient: skip embedded whitespace so wrapped base64 still decodes.
            return Self.makeUint8Array(in: context, from: Data(base64Encoded: str, options: .ignoreUnknownCharacters) ?? Data())
        }
        base64.setObject(base64Encode, forKeyedSubscript: "encode" as NSString)
        base64.setObject(base64Decode, forKeyedSubscript: "decode" as NSString)
        codec.setObject(base64, forKeyedSubscript: "base64" as NSString)
        
        let base64url = JSValue(newObjectIn: context)!
        let base64URLEncodeBlock: @convention(block) (JSValue) -> String = { val in
            let context = JSContext.current()!
            return Self.encodeBase64URL(Self.bytesFromValue(val, in: context) ?? Data())
        }
        let base64URLDecodeBlock: @convention(block) (String) -> JSValue = { str in
            let context = JSContext.current()!
            return Self.makeUint8Array(in: context, from: Self.decodeBase64URL(str) ?? Data())
        }
        base64url.setObject(base64URLEncodeBlock, forKeyedSubscript: "encode" as NSString)
        base64url.setObject(base64URLDecodeBlock, forKeyedSubscript: "decode" as NSString)
        codec.setObject(base64url, forKeyedSubscript: "base64url" as NSString)

        let hex = JSValue(newObjectIn: context)!
        let hexEncode: @convention(block) (JSValue) -> String = { val in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: context) ?? Data()
            return bytes.map { String(format: "%02x", $0) }.joined()
        }
        let hexDecode: @convention(block) (String) -> JSValue = { str in
            let context = JSContext.current()!
            return Self.makeUint8Array(in: context, from: Self.decodeHex(str))
        }
        hex.setObject(hexEncode, forKeyedSubscript: "encode" as NSString)
        hex.setObject(hexDecode, forKeyedSubscript: "decode" as NSString)
        codec.setObject(hex, forKeyedSubscript: "hex" as NSString)
        
        let protobuf = JSValue(newObjectIn: context)!
        let pbDecodeBlock: @convention(block) (JSValue) -> JSValue = { val in
            let context = JSContext.current()!
            guard let bytes = Self.bytesFromValue(val, in: context) else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.decode: expected Uint8Array/ArrayBuffer/string",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            do {
                let entries = try Self.protobufDecodeWire(bytes)
                return Self.makeProtobufEntries(entries, in: context)
            } catch {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.decode: \(AnywhereError.describe(error))",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
        }
        let pbEncodeBlock: @convention(block) (JSValue) -> JSValue = { val in
            let context = JSContext.current()!
            do {
                let entries = try Self.parseProtobufEntries(val, in: context)
                return Self.makeUint8Array(in: context, from: Self.protobufEncodeWire(entries))
            } catch {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.encode: \(AnywhereError.describe(error))",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
        }
        let pbEncodeVarintBlock: @convention(block) (JSValue) -> JSValue = { val in
            let context = JSContext.current()!
            guard let u = Self.uint64FromJSValue(val) else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.encodeVarint: expected non-negative Number or BigInt",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            return Self.makeUint8Array(in: context, from: Self.writeVarint(u))
        }
        let pbDecodeVarintBlock: @convention(block) (JSValue, JSValue) -> JSValue = { bytesVal, offsetVal in
            let context = JSContext.current()!
            guard let bytes = Self.bytesFromValue(bytesVal, in: context) else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.decodeVarint: expected Uint8Array/ArrayBuffer/string",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            let offset: Int
            if offsetVal.isUndefined || offsetVal.isNull {
                offset = 0
            } else if offsetVal.isNumber {
                offset = Int(offsetVal.toInt32())
            } else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.decodeVarint: offset must be a Number",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            guard offset >= 0, offset <= bytes.count else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.decodeVarint: offset out of range",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            guard let (value, end) = Self.readVarint(bytes, from: offset) else {
                return JSValue(nullIn: context)
            }
            let object = JSValue(newObjectIn: context)!
            object.setObject(Self.makeBigInt(value, in: context), forKeyedSubscript: "value" as NSString)
            object.setObject(end - offset, forKeyedSubscript: "consumed" as NSString)
            return object
        }
        protobuf.setObject(pbDecodeBlock, forKeyedSubscript: "decode" as NSString)
        protobuf.setObject(pbEncodeBlock, forKeyedSubscript: "encode" as NSString)
        protobuf.setObject(pbEncodeVarintBlock, forKeyedSubscript: "encodeVarint" as NSString)
        protobuf.setObject(pbDecodeVarintBlock, forKeyedSubscript: "decodeVarint" as NSString)
        codec.setObject(protobuf, forKeyedSubscript: "protobuf" as NSString)

        installCompressionCodec(on: codec, named: "gzip", codec: .gzip, context: context)
        installCompressionCodec(on: codec, named: "deflate", codec: .deflate, context: context)
        installCompressionCodec(on: codec, named: "brotli", codec: .brotli, context: context)

        anywhere.setObject(codec, forKeyedSubscript: "codec" as NSString)
    }
    
    nonisolated private func installCompressionCodec(on codecNamespace: JSValue, named name: String, codec codecKind: MITMBodyCodec.Codec, context: JSContext) {
        let object = JSValue(newObjectIn: context)!
        let encodeBlock: @convention(block) (JSValue) -> JSValue = { val in
            let context = JSContext.current()!
            guard let bytes = Self.bytesFromValue(val, in: context) else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.codec.\(name).encode: expected Uint8Array/ArrayBuffer/string",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            guard let out = MITMBodyCodec.encode(bytes, codec: codecKind) else {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.codec.\(name).encode failed", in: context)
                return JSValue(undefinedIn: context)
            }
            return Self.makeUint8Array(in: context, from: out)
        }
        let decodeBlock: @convention(block) (JSValue) -> JSValue = { val in
            let context = JSContext.current()!
            guard let bytes = Self.bytesFromValue(val, in: context) else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.codec.\(name).decode: expected Uint8Array/ArrayBuffer/string",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            guard let out = MITMBodyCodec.decode(bytes, codec: codecKind) else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.codec.\(name).decode failed (malformed input or exceeds \(MITMBodyCodec.maxBufferedBodyBytes) B cap)",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            return Self.makeUint8Array(in: context, from: out)
        }
        object.setObject(encodeBlock, forKeyedSubscript: "encode" as NSString)
        object.setObject(decodeBlock, forKeyedSubscript: "decode" as NSString)
        codecNamespace.setObject(object, forKeyedSubscript: name as NSString)
    }

    nonisolated private func installCryptoGlobals(on anywhere: JSValue, context: JSContext) {
        let crypto = JSValue(newObjectIn: context)!
        let md5Block: @convention(block) (JSValue) -> JSValue = { val in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: context) ?? Data()
            return Self.makeUint8Array(in: context, from: Data(Insecure.MD5.hash(data: bytes)))
        }
        let sha1Block: @convention(block) (JSValue) -> JSValue = { val in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: context) ?? Data()
            return Self.makeUint8Array(in: context, from: Data(Insecure.SHA1.hash(data: bytes)))
        }
        let sha256Block: @convention(block) (JSValue) -> JSValue = { val in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: context) ?? Data()
            return Self.makeUint8Array(in: context, from: Data(SHA256.hash(data: bytes)))
        }
        let sha384Block: @convention(block) (JSValue) -> JSValue = { val in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: context) ?? Data()
            return Self.makeUint8Array(in: context, from: Data(SHA384.hash(data: bytes)))
        }
        let sha512Block: @convention(block) (JSValue) -> JSValue = { val in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(val, in: context) ?? Data()
            return Self.makeUint8Array(in: context, from: Data(SHA512.hash(data: bytes)))
        }
        let hmacSHA1Block: @convention(block) (JSValue, JSValue) -> JSValue = { keyVal, dataVal in
            let context = JSContext.current()!
            let key = Self.bytesFromValue(keyVal, in: context) ?? Data()
            let data = Self.bytesFromValue(dataVal, in: context) ?? Data()
            let mac = HMAC<Insecure.SHA1>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Self.makeUint8Array(in: context, from: Data(mac))
        }
        let hmacSHA256Block: @convention(block) (JSValue, JSValue) -> JSValue = { keyVal, dataVal in
            let context = JSContext.current()!
            let key = Self.bytesFromValue(keyVal, in: context) ?? Data()
            let data = Self.bytesFromValue(dataVal, in: context) ?? Data()
            let mac = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Self.makeUint8Array(in: context, from: Data(mac))
        }
        let hmacSHA384Block: @convention(block) (JSValue, JSValue) -> JSValue = { keyVal, dataVal in
            let context = JSContext.current()!
            let key = Self.bytesFromValue(keyVal, in: context) ?? Data()
            let data = Self.bytesFromValue(dataVal, in: context) ?? Data()
            let mac = HMAC<SHA384>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Self.makeUint8Array(in: context, from: Data(mac))
        }
        let hmacSHA512Block: @convention(block) (JSValue, JSValue) -> JSValue = { keyVal, dataVal in
            let context = JSContext.current()!
            let key = Self.bytesFromValue(keyVal, in: context) ?? Data()
            let data = Self.bytesFromValue(dataVal, in: context) ?? Data()
            let mac = HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Self.makeUint8Array(in: context, from: Data(mac))
        }
        let randomBytesBlock: @convention(block) (JSValue) -> JSValue = { lenVal in
            let context = JSContext.current()!
            let lengthDouble = lenVal.toDouble()
            guard lengthDouble.isFinite, lengthDouble >= 0, lengthDouble <= 65536, lengthDouble == lengthDouble.rounded() else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.crypto.randomBytes: length must be an integer in [0, 65536]",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            let randomByteCount = Int(lengthDouble)
            if randomByteCount == 0 { return Self.makeUint8Array(in: context, from: Data()) }
            var bytes = [UInt8](repeating: 0, count: randomByteCount)
            let status = bytes.withUnsafeMutableBufferPointer { buffer in
                SecRandomCopyBytes(kSecRandomDefault, randomByteCount, buffer.baseAddress!)
            }
            guard status == errSecSuccess else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.crypto.randomBytes: SecRandomCopyBytes failed (status \(status))",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            return Self.makeUint8Array(in: context, from: Data(bytes))
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
        
        let aesGCM = JSValue(newObjectIn: context)!
        let aesGCMEncryptBlock: @convention(block) (JSValue) -> JSValue = { spec in
            let context = JSContext.current()!
            guard !spec.isUndefined, !spec.isNull else {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: expected a spec object", in: context)
                return JSValue(undefinedIn: context)
            }
            guard let key = Self.bytesFromValue(spec.objectForKeyedSubscript("key"), in: context),
                  key.count == 16 || key.count == 24 || key.count == 32 else {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: key must be a Uint8Array of length 16, 24, or 32", in: context)
                return JSValue(undefinedIn: context)
            }
            guard let plaintext = Self.bytesFromValue(spec.objectForKeyedSubscript("plaintext"), in: context) else {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: plaintext must be Uint8Array/ArrayBuffer/string", in: context)
                return JSValue(undefinedIn: context)
            }
            let nonceData: Data?
            let nonceVal = spec.objectForKeyedSubscript("nonce")
            if let nonceVal, !nonceVal.isUndefined, !nonceVal.isNull {
                guard let n = Self.bytesFromValue(nonceVal, in: context) else {
                    context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: nonce must be Uint8Array/ArrayBuffer/string", in: context)
                    return JSValue(undefinedIn: context)
                }
                guard n.count == 12 else {
                    context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: nonce must be 12 bytes", in: context)
                    return JSValue(undefinedIn: context)
                }
                nonceData = n
            } else {
                nonceData = nil
            }
            let aadData: Data?
            let aadVal = spec.objectForKeyedSubscript("aad")
            if let aadVal, !aadVal.isUndefined, !aadVal.isNull {
                guard let a = Self.bytesFromValue(aadVal, in: context) else {
                    context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: aad must be Uint8Array/ArrayBuffer/string", in: context)
                    return JSValue(undefinedIn: context)
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
                let out = JSValue(newObjectIn: context)!
                out.setObject(Self.makeUint8Array(in: context, from: Data(box.nonce)), forKeyedSubscript: "nonce" as NSString)
                out.setObject(Self.makeUint8Array(in: context, from: box.ciphertext), forKeyedSubscript: "ciphertext" as NSString)
                out.setObject(Self.makeUint8Array(in: context, from: box.tag), forKeyedSubscript: "tag" as NSString)
                return out
            } catch {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: \(error)", in: context)
                return JSValue(undefinedIn: context)
            }
        }
        let aesGCMDecryptBlock: @convention(block) (JSValue) -> JSValue = { spec in
            let context = JSContext.current()!
            guard !spec.isUndefined, !spec.isNull else {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: expected a spec object", in: context)
                return JSValue(undefinedIn: context)
            }
            guard let key = Self.bytesFromValue(spec.objectForKeyedSubscript("key"), in: context),
                  key.count == 16 || key.count == 24 || key.count == 32 else {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: key must be a Uint8Array of length 16, 24, or 32", in: context)
                return JSValue(undefinedIn: context)
            }
            guard let nonce = Self.bytesFromValue(spec.objectForKeyedSubscript("nonce"), in: context),
                  nonce.count == 12 else {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: nonce must be a Uint8Array of length 12", in: context)
                return JSValue(undefinedIn: context)
            }
            guard let ciphertext = Self.bytesFromValue(spec.objectForKeyedSubscript("ciphertext"), in: context) else {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: ciphertext must be Uint8Array/ArrayBuffer/string", in: context)
                return JSValue(undefinedIn: context)
            }
            guard let tag = Self.bytesFromValue(spec.objectForKeyedSubscript("tag"), in: context),
                  tag.count == 16 else {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: tag must be a Uint8Array of length 16", in: context)
                return JSValue(undefinedIn: context)
            }
            let aadData: Data?
            let aadVal = spec.objectForKeyedSubscript("aad")
            if let aadVal, !aadVal.isUndefined, !aadVal.isNull {
                guard let a = Self.bytesFromValue(aadVal, in: context) else {
                    context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: aad must be Uint8Array/ArrayBuffer/string", in: context)
                    return JSValue(undefinedIn: context)
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
                return Self.makeUint8Array(in: context, from: plaintext)
            } catch {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: \(error)", in: context)
                return JSValue(undefinedIn: context)
            }
        }
        aesGCM.setObject(aesGCMEncryptBlock, forKeyedSubscript: "encrypt" as NSString)
        aesGCM.setObject(aesGCMDecryptBlock, forKeyedSubscript: "decrypt" as NSString)
        crypto.setObject(aesGCM, forKeyedSubscript: "aesGCM" as NSString)
        anywhere.setObject(crypto, forKeyedSubscript: "crypto" as NSString)
    }
    
    nonisolated private func installJWTGlobals(on anywhere: JSValue, context: JSContext) {
        let jwt = JSValue(newObjectIn: context)!
        let jwtDecodeBlock: @convention(block) (String) -> JSValue = { token in
            let context = JSContext.current()!
            let parts = token.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count == 2 || parts.count == 3 else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.jwt.decode: expected 2 or 3 dot-separated segments, got \(parts.count)",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            guard let headerBytes = Self.decodeBase64URL(String(parts[0])) else {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.jwt.decode: header is not valid base64url", in: context)
                return JSValue(undefinedIn: context)
            }
            guard let payloadBytes = Self.decodeBase64URL(String(parts[1])) else {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.jwt.decode: payload is not valid base64url", in: context)
                return JSValue(undefinedIn: context)
            }
            let signatureBytes: Data
            if parts.count == 3 {
                guard let sig = Self.decodeBase64URL(String(parts[2])) else {
                    context.exception = JSValue(newErrorFromMessage: "Anywhere.jwt.decode: signature is not valid base64url", in: context)
                    return JSValue(undefinedIn: context)
                }
                signatureBytes = sig
            } else {
                signatureBytes = Data()
            }
            guard let headerString = String(data: headerBytes, encoding: .utf8),
                  let headerObject = Self.parseJSON(headerString, in: context) else {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.jwt.decode: header is not valid JSON", in: context)
                return JSValue(undefinedIn: context)
            }
            let payloadValue: JSValue
            if let payloadStr = String(data: payloadBytes, encoding: .utf8),
               let parsed = Self.parseJSON(payloadStr, in: context) {
                payloadValue = parsed
            } else {
                payloadValue = Self.makeUint8Array(in: context, from: payloadBytes)
            }
            let signingInput = "\(parts[0]).\(parts[1])"
            let result = JSValue(newObjectIn: context)!
            result.setObject(headerObject, forKeyedSubscript: "header" as NSString)
            result.setObject(payloadValue, forKeyedSubscript: "payload" as NSString)
            result.setObject(Self.makeUint8Array(in: context, from: signatureBytes), forKeyedSubscript: "signature" as NSString)
            result.setObject(Self.makeUint8Array(in: context, from: Data(signingInput.utf8)), forKeyedSubscript: "signingInput" as NSString)
            return result
        }
        let jwtEncodeBlock: @convention(block) (JSValue) -> JSValue = { spec in
            let context = JSContext.current()!
            guard !spec.isUndefined, !spec.isNull else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.jwt.encode: expected a spec object with {header, payload, signature?}",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            guard let headerSeg = Self.encodeJWTSegment(spec.objectForKeyedSubscript("header"), in: context) else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.jwt.encode: header must be an object, string, or Uint8Array",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            guard let payloadSeg = Self.encodeJWTSegment(spec.objectForKeyedSubscript("payload"), in: context) else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.jwt.encode: payload must be an object, string, or Uint8Array",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            let signatureSeg: String
            let sigVal = spec.objectForKeyedSubscript("signature")
            if let sigVal, !sigVal.isUndefined, !sigVal.isNull {
                guard let sigBytes = Self.bytesFromValue(sigVal, in: context) else {
                    context.exception = JSValue(
                        newErrorFromMessage: "Anywhere.jwt.encode: signature must be a Uint8Array (the raw signature bytes)",
                        in: context
                    )
                    return JSValue(undefinedIn: context)
                }
                signatureSeg = Self.encodeBase64URL(sigBytes)
            } else {
                signatureSeg = ""
            }
            return JSValue(object: "\(headerSeg).\(payloadSeg).\(signatureSeg)", in: context)
        }
        jwt.setObject(jwtDecodeBlock, forKeyedSubscript: "decode" as NSString)
        jwt.setObject(jwtEncodeBlock, forKeyedSubscript: "encode" as NSString)
        anywhere.setObject(jwt, forKeyedSubscript: "jwt" as NSString)
    }
    
    nonisolated private func installJSONGlobals(on anywhere: JSValue, context: JSContext) {
        let json = JSValue(newObjectIn: context)!
        
        let addBlock: @convention(block) (JSValue, String, JSValue) -> JSValue = { body, path, value in
            let context = JSContext.current()!
            guard let v = Self.jsonValue(from: value, in: context) else {
                logger.warning("[MITM][JS] Anywhere.json.add: value is undefined; use delete() to remove a field. Body unchanged.")
                return Self.jsonPassthrough(body, in: context)
            }
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.add: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: context)
            }
            return Self.runJSONOp(body, in: context) { root in
                root = MITMJSONPatch.applyAtPath(root, segments: segments, mode: .add, value: v)
            }
        }
        
        let replaceBlock: @convention(block) (JSValue, String, JSValue) -> JSValue = { body, path, value in
            let context = JSContext.current()!
            guard let v = Self.jsonValue(from: value, in: context) else {
                logger.warning("[MITM][JS] Anywhere.json.replace: value is undefined; body unchanged")
                return Self.jsonPassthrough(body, in: context)
            }
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.replace: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: context)
            }
            return Self.runJSONOp(body, in: context) { root in
                root = MITMJSONPatch.applyAtPath(root, segments: segments, mode: .replace, value: v)
            }
        }
        
        let replaceRecursiveBlock: @convention(block) (JSValue, String, JSValue) -> JSValue = { body, key, value in
            let context = JSContext.current()!
            guard let v = Self.jsonValue(from: value, in: context) else {
                logger.warning("[MITM][JS] Anywhere.json.replaceRecursive: value is undefined; body unchanged")
                return Self.jsonPassthrough(body, in: context)
            }
            return Self.runJSONOp(body, in: context) { root in
                MITMJSONPatch.replaceKeyRecursive(root, key: key, value: v)
            }
        }

        let deleteBlock: @convention(block) (JSValue, String) -> JSValue = { body, path in
            let context = JSContext.current()!
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.delete: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: context)
            }
            return Self.runJSONOp(body, in: context) { root in
                root = MITMJSONPatch.applyAtPath(root, segments: segments, mode: .delete, value: nil)
            }
        }

        let deleteRecursiveBlock: @convention(block) (JSValue, String) -> JSValue = { body, key in
            let context = JSContext.current()!
            return Self.runJSONOp(body, in: context) { root in
                MITMJSONPatch.deleteKeyRecursive(root, key: key)
            }
        }

        let removeWhereKeyExistsBlock: @convention(block) (JSValue, String, String) -> JSValue = { body, path, key in
            let context = JSContext.current()!
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.removeWhereKeyExists: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: context)
            }
            return Self.runJSONOp(body, in: context) { root in
                guard let array = MITMJSONPatch.resolveNode(root, segments: segments) as? NSMutableArray else { return }
                let kept = array.filter { ($0 as? NSDictionary)?.object(forKey: key) == nil }
                array.setArray(kept)
            }
        }

        let removeWhereFieldInBlock: @convention(block) (JSValue, String, String, JSValue) -> JSValue = { body, path, field, valuesVal in
            let context = JSContext.current()!
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[MITM][JS] Anywhere.json.removeWhereFieldIn: malformed path \"\(path)\"; body unchanged")
                return Self.jsonPassthrough(body, in: context)
            }
            let matchValues = Self.jsonArrayValues(from: valuesVal, in: context)
            return Self.runJSONOp(body, in: context) { root in
                guard let array = MITMJSONPatch.resolveNode(root, segments: segments) as? NSMutableArray else { return }
                let kept = array.filter { element in
                    guard let object = element as? NSDictionary,
                          let fieldValue = object.object(forKey: field) else { return true }
                    return !matchValues.contains { MITMJSONPatch.valueEquals($0, fieldValue) }
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

    // MARK: - Anywhere.json internals
    
    private static func runJSONOp(_ body: JSValue, in ctx: JSContext, _ mutate: (inout Any) -> Void) -> JSValue {
        let original = bytesFromValue(body, in: ctx) ?? Data()
        guard var root = MITMJSONPatch.parse(original) else {
            return makeUint8Array(in: ctx, from: original)
        }
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

    nonisolated private func installStoreGlobals(on anywhere: JSValue, context: JSContext) {
        let store = JSValue(newObjectIn: context)!
        let storeGet: @convention(block) (String, Bool) -> JSValue = { [weak self] key, onDisk in
            let context = JSContext.current()!
            guard let scope = self?.activeScope(),
                  let bytes = MITMScriptStore.shared.get(scope: scope, key: key, onDisk: onDisk)
            else { return JSValue(undefinedIn: context) }
            return Self.makeUint8Array(in: context, from: bytes)
        }
        let storeGetString: @convention(block) (String, Bool) -> JSValue = { [weak self] key, onDisk in
            let context = JSContext.current()!
            guard let scope = self?.activeScope(),
                  let bytes = MITMScriptStore.shared.get(scope: scope, key: key, onDisk: onDisk),
                  let string = String(data: bytes, encoding: .utf8)
            else { return JSValue(undefinedIn: context) }
            return JSValue(object: string, in: context)
        }
        let storeSet: @convention(block) (String, JSValue, Bool) -> Void = { [weak self] key, val, onDisk in
            let context = JSContext.current()!
            guard let scope = self?.activeScope() else { return }
            let bytes = Self.bytesFromValue(val, in: context) ?? Data()
            do {
                try MITMScriptStore.shared.set(scope: scope, key: key, value: bytes, onDisk: onDisk)
            } catch AnywhereError.mitm(.scriptStoreCapacityExceeded) {
                let cap = onDisk ? MITMScriptDiskStore.maxBytesPerScope : MITMScriptStore.maxBytesPerScope
                let error = JSValue(
                    newErrorFromMessage: "Anywhere.store: capacity exceeded (per-scope cap is \(cap) bytes)",
                    in: context
                )
                context.exception = error
            } catch AnywhereError.mitm(.scriptStoreWriteFailed) {
                let error = JSValue(newErrorFromMessage: "Anywhere.store: on-disk write failed", in: context)
                context.exception = error
            } catch {
                let err = JSValue(newErrorFromMessage: "Anywhere.store: \(error)", in: context)
                context.exception = err
            }
        }
        let storeDelete: @convention(block) (String, Bool) -> Void = { [weak self] key, onDisk in
            guard let scope = self?.activeScope() else { return }
            MITMScriptStore.shared.delete(scope: scope, key: key, onDisk: onDisk)
        }
        let storeKeys: @convention(block) (Bool) -> [String] = { [weak self] onDisk in
            guard let scope = self?.activeScope() else { return [] }
            return MITMScriptStore.shared.keys(scope: scope, onDisk: onDisk)
        }
        store.setObject(storeGet, forKeyedSubscript: "get" as NSString)
        store.setObject(storeGetString, forKeyedSubscript: "getString" as NSString)
        store.setObject(storeSet, forKeyedSubscript: "set" as NSString)
        store.setObject(storeDelete, forKeyedSubscript: "delete" as NSString)
        store.setObject(storeKeys, forKeyedSubscript: "keys" as NSString)
        anywhere.setObject(store, forKeyedSubscript: "store" as NSString)
    }
    
    nonisolated private func installParamsGlobals(on anywhere: JSValue, context: JSContext) {
        let params = JSValue(newObjectIn: context)!
        let paramsGet: @convention(block) (String) -> JSValue = { [weak self] key in
            let context = JSContext.current()!
            guard let scope = self?.activeScope(),
                  let value = MITMParamStore.shared.get(scope: scope, key: key)
            else { return JSValue(undefinedIn: context) }
            return JSValue(object: value, in: context)
        }
        let paramsKeys: @convention(block) () -> [String] = { [weak self] in
            guard let scope = self?.activeScope() else { return [] }
            return MITMParamStore.shared.keys(scope: scope)
        }
        let paramsAll: @convention(block) () -> [String: String] = { [weak self] in
            guard let scope = self?.activeScope() else { return [:] }
            return MITMParamStore.shared.all(scope: scope)
        }
        params.setObject(paramsGet, forKeyedSubscript: "get" as NSString)
        params.setObject(paramsKeys, forKeyedSubscript: "keys" as NSString)
        params.setObject(paramsAll, forKeyedSubscript: "all" as NSString)
        anywhere.setObject(params, forKeyedSubscript: "params" as NSString)
    }

    nonisolated private func installLogGlobals(on anywhere: JSValue, context: JSContext) {
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

    nonisolated private func installControlGlobals(on anywhere: JSValue, context: JSContext) {
        let doneBlock: @convention(block) () -> Void = { [weak self] in
            self?.setActiveDirective(.done)
        }
        let exitBlock: @convention(block) () -> Void = { [weak self] in
            self?.setActiveDirective(.exit)
        }
        anywhere.setObject(doneBlock, forKeyedSubscript: "done" as NSString)
        anywhere.setObject(exitBlock, forKeyedSubscript: "exit" as NSString)

        let respondBlock: @convention(block) (JSValue) -> Void = { [weak self] spec in
            guard let self else { return }
            guard !spec.isUndefined, !spec.isNull else {
                self.setActiveDirective(.respond(
                    SynthesizedResponse(status: 200, headers: [], body: Data())
                ))
                return
            }
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
                let context = JSContext.current()!
                body = Self.bytesFromValue(bodyVal, in: context) ?? Data()
            } else {
                body = Data()
            }
            self.setActiveDirective(.respond(
                SynthesizedResponse(status: status, headers: headers, body: body)
            ))
        }
        anywhere.setObject(respondBlock, forKeyedSubscript: "respond" as NSString)
    }

    // MARK: - Anywhere.http
    
    nonisolated private func installHTTPGlobals(on anywhere: JSValue, context: JSContext) {
        let http = JSValue(newObjectIn: context)!
        let getBlock: @convention(block) (JSValue, JSValue) -> JSValue = { [weak self] urlVal, optsVal in
            let context = JSContext.current()!
            guard let self else { return Self.rejected("Anywhere.http: engine released", in: context) }
            // The block runs on the actor's JSC queue.
            return self.assumeIsolated { $0.startHTTP(defaultMethod: "GET", urlVal: urlVal, optsVal: optsVal, in: context) }
        }
        let postBlock: @convention(block) (JSValue, JSValue) -> JSValue = { [weak self] urlVal, optsVal in
            let context = JSContext.current()!
            guard let self else { return Self.rejected("Anywhere.http: engine released", in: context) }
            return self.assumeIsolated { $0.startHTTP(defaultMethod: "POST", urlVal: urlVal, optsVal: optsVal, in: context) }
        }
        let requestBlock: @convention(block) (JSValue) -> JSValue = { [weak self] specVal in
            let context = JSContext.current()!
            guard let self else { return Self.rejected("Anywhere.http: engine released", in: context) }
            let urlVal: JSValue = specVal.objectForKeyedSubscript("url") ?? JSValue(undefinedIn: context)
            return self.assumeIsolated { $0.startHTTP(defaultMethod: "GET", urlVal: urlVal, optsVal: specVal, in: context) }
        }
        http.setObject(getBlock, forKeyedSubscript: "get" as NSString)
        http.setObject(postBlock, forKeyedSubscript: "post" as NSString)
        http.setObject(requestBlock, forKeyedSubscript: "request" as NSString)
        anywhere.setObject(http, forKeyedSubscript: "http" as NSString)
    }

    private func startHTTP(defaultMethod: String, urlVal: JSValue, optsVal: JSValue, in ctx: JSContext) -> JSValue {
        guard let invocation = currentInvocation, invocation.allowsHTTP else {
            return Self.rejected(
                "Anywhere.http is only available inside a buffered `script` rule — an `async function process(ctx)` that awaits it. It is unavailable in stream-script.",
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
        if invocation.totalFetches >= Self.httpMaxTotalPerInvocation {
            return Self.rejected("Anywhere.http: per-invocation request cap (\(Self.httpMaxTotalPerInvocation)) reached", in: ctx)
        }
        if invocation.inFlightFetches >= Self.httpMaxConcurrentPerInvocation {
            return Self.rejected("Anywhere.http: too many concurrent requests in this invocation (max \(Self.httpMaxConcurrentPerInvocation))", in: ctx)
        }
        if Self.globalFetchCount() >= Self.httpMaxConcurrentGlobal {
            return Self.rejected("Anywhere.http: global concurrent request cap (\(Self.httpMaxConcurrentGlobal)) reached", in: ctx)
        }

        let options: JSValue? = optsVal.isObject ? optsVal : nil
        var request = URLRequest(url: url)
        let method = (options?.objectForKeyedSubscript("method"))
            .flatMap { $0.isString ? $0.toString() : nil }?
            .uppercased() ?? defaultMethod
        guard HTTPHeader.isValidName(method) else {
            return Self.rejected("Anywhere.http: invalid method token", in: ctx)
        }
        request.httpMethod = method
        if let headersVal = options?.objectForKeyedSubscript("headers"), !headersVal.isUndefined, !headersVal.isNull {
            for header in Self.requestHeadersFromValue(headersVal, in: ctx) {
                request.addValue(header.value, forHTTPHeaderField: header.name)
            }
        }
        if let bodyVal = options?.objectForKeyedSubscript("body"), !bodyVal.isUndefined, !bodyVal.isNull {
            request.httpBody = Self.bytesFromValue(bodyVal, in: ctx) ?? Data()
        }
        var timeout = Self.httpDefaultTimeout
        if let timeoutVal = options?.objectForKeyedSubscript("timeout"), timeoutVal.isNumber {
            let timeoutMilliseconds = timeoutVal.toDouble()
            if timeoutMilliseconds.isFinite, timeoutMilliseconds > 0 { timeout = min(timeoutMilliseconds / 1000.0, Self.httpMaxTimeout) }
        }
        request.timeoutInterval = timeout
        let followRedirects = (options?.objectForKeyedSubscript("redirect"))
            .flatMap { $0.isString ? $0.toString() : nil } != "manual"
        let insecure: Bool
        if let insecureVal = options?.objectForKeyedSubscript("insecure"), insecureVal.isBoolean {
            insecure = insecureVal.toBool()
        } else {
            insecure = AWCore.getAllowInsecure()
        }

        let maxBytes = Self.httpMaxResponseBytes

        let promise = JSValue(newPromiseIn: ctx, fromExecutor: { [weak self] resolve, reject in
            guard let self else {
                reject?.call(withArguments: [Self.error("Anywhere.http: engine released", in: ctx)])
                return
            }
            self.assumeIsolated { engine in
                guard let liveInvocation = engine.currentInvocation else {
                    reject?.call(withArguments: [Self.error("Anywhere.http: invocation released", in: ctx)])
                    return
                }
                liveInvocation.inFlightFetches += 1
                liveInvocation.totalFetches += 1
                Self.reserveGlobalFetchSlot()
                let fetchID = engine.registerPendingFetch(invocation: liveInvocation, resolve: resolve, reject: reject)
                Task { [request] in
                    let result: Result<MITMScriptHTTPClient.Response, Error>
                    do {
                        let response = try await MITMScriptHTTPClient.shared.send(
                            request,
                            followRedirects: followRedirects,
                            insecure: insecure,
                            maxBytes: maxBytes,
                            resourceTimeout: Self.invocationIdleTimeout
                        )
                        result = .success(response)
                    } catch {
                        result = .failure(error)
                    }
                    engine.completeFetch(id: fetchID, result: result)
                }
            }
        })
        return promise ?? Self.rejected("Anywhere.http: could not create Promise", in: ctx)
    }
    
    private struct PendingFetch {
        weak var invocation: Invocation?
        let resolve: JSValue?
        let reject: JSValue?
    }
    private var pendingFetches: [Int: PendingFetch] = [:]
    private var nextFetchID = 0

    private func registerPendingFetch(invocation: Invocation, resolve: JSValue?, reject: JSValue?) -> Int {
        nextFetchID += 1
        pendingFetches[nextFetchID] = PendingFetch(invocation: invocation, resolve: resolve, reject: reject)
        return nextFetchID
    }
    
    private func completeFetch(id: Int, result: Result<MITMScriptHTTPClient.Response, Error>) {
        Self.releaseGlobalFetchSlot()
        guard let pending = pendingFetches.removeValue(forKey: id) else { return }
        guard let invocation = pending.invocation else { return }
        resumeFetch(invocation: invocation, resolve: pending.resolve, reject: pending.reject, result: result)
    }
    
    private func resumeFetch(
        invocation: Invocation,
        resolve: JSValue?,
        reject: JSValue?,
        result: Result<MITMScriptHTTPClient.Response, Error>
    ) {
        if invocation.inFlightFetches > 0 { invocation.inFlightFetches -= 1 }
        if !invocation.delivered { armWatchdog(for: invocation) }
        currentInvocation = invocation
        defer { currentInvocation = nil }
        _ = runUserScript("async script (Anywhere.http resume continuation)") {
            switch result {
            case .success(let response):
                resolve?.call(withArguments: [Self.makeHTTPResponse(response, in: context)])
            case .failure(let error):
                reject?.call(withArguments: [Self.error("Anywhere.http: \(AnywhereError.describe(error))", in: context)])
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
        let object = JSValue(newObjectIn: ctx)!
        object.setObject(response.status, forKeyedSubscript: "status" as NSString)
        let pairs: [[String]] = response.headers.map { [$0.name, $0.value] }
        object.setObject(pairs, forKeyedSubscript: "headers" as NSString)
        object.setObject(makeUint8Array(in: ctx, from: response.body), forKeyedSubscript: "body" as NSString)
        object.setObject(response.finalURL as Any, forKeyedSubscript: "url" as NSString)
        return object
    }
    
    private static func requestHeadersFromValue(_ value: JSValue, in ctx: JSContext) -> [(name: String, value: String)] {
        if value.isArray {
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
            guard HTTPHeader.isValidName(name) else {
                logger.warning("[MITM][JS] Anywhere.http: dropping request header with invalid name: \(name)")
                continue
            }
            guard HTTPHeader.isValidValue(val) else {
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
    
    private static let forbiddenRequestHeaders: Set<String> = [
        "host", "content-length", "connection", "transfer-encoding",
        "upgrade", "keep-alive", "te", "trailer", "expect", "proxy-connection",
    ]

    // MARK: Global Anywhere.http in-flight counter

    private static func reserveGlobalFetchSlot() {
        mitmScriptGlobalFetchCount.wrappingAdd(1, ordering: .relaxed)
    }
    private static func releaseGlobalFetchSlot() {
        var current = mitmScriptGlobalFetchCount.load(ordering: .relaxed)
        while current > 0 {
            let (exchanged, original) = mitmScriptGlobalFetchCount.weakCompareExchange(
                expected: current, desired: current - 1, ordering: .relaxed
            )
            if exchanged { return }
            current = original
        }
    }
    private static func globalFetchCount() -> Int {
        mitmScriptGlobalFetchCount.load(ordering: .relaxed)
    }

    // MARK: - Body bridging

    private static func makeUint8Array(in context: JSContext, from data: Data) -> JSValue {
        let count = data.count
        let ctxRef = context.jsGlobalContextRef
        var exception: JSValueRef?
        guard let object = JSObjectMakeTypedArray(ctxRef, kJSTypedArrayTypeUint8Array, count, &exception),
              exception == nil else {
            return JSValue(undefinedIn: context)
        }
        if count > 0 {
            guard let pointer = JSObjectGetTypedArrayBytesPtr(ctxRef, object, &exception), exception == nil else {
                return JSValue(undefinedIn: context)
            }
            data.copyBytes(to: pointer.assumingMemoryBound(to: UInt8.self), count: count)
        }
        return JSValue(jsValueRef: object, in: context)
    }

    private static func bytesFromValue(_ value: JSValue, in context: JSContext) -> Data? {
        if value.isNull || value.isUndefined { return nil }
        if value.isString {
            return value.toString().map { Data($0.utf8) }
        }
        return typedArrayBytesFromValue(value, in: context)
    }
    
    private static func typedArrayBytesFromValue(_ value: JSValue, in context: JSContext) -> Data? {
        if value.isNull || value.isUndefined { return nil }
        let ctxRef = context.jsGlobalContextRef
        guard let ref = value.jsValueRef else { return nil }
        var exception: JSValueRef?
        let kind = JSValueGetTypedArrayType(ctxRef, ref, &exception)
        if exception != nil { return nil }
        if kind == kJSTypedArrayTypeNone { return nil }
        guard let object = JSValueToObject(ctxRef, ref, &exception), exception == nil else {
            return nil
        }
        if kind == kJSTypedArrayTypeArrayBuffer {
            let length = JSObjectGetArrayBufferByteLength(ctxRef, object, &exception)
            guard exception == nil,
                  let pointer = JSObjectGetArrayBufferBytesPtr(ctxRef, object, &exception),
                  exception == nil
            else { return nil }
            return Data(bytes: pointer, count: length)
        }
        let length = JSObjectGetTypedArrayByteLength(ctxRef, object, &exception)
        guard exception == nil else { return nil }
        let offset = JSObjectGetTypedArrayByteOffset(ctxRef, object, &exception)
        guard exception == nil,
              let pointer = JSObjectGetTypedArrayBytesPtr(ctxRef, object, &exception),
              exception == nil
        else { return nil }
        return Data(bytes: pointer + offset, count: length)
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
    
    fileprivate enum ProtobufFieldValue {
        case varint(UInt64)
        case bytes(Data)
    }

    fileprivate struct ProtobufEntry {
        let field: UInt32
        let wire: UInt8
        let value: ProtobufFieldValue
    }

    fileprivate static func readVarint(_ data: Data, from offset: Int) -> (UInt64, Int)? {
        guard offset >= data.startIndex, offset <= data.endIndex else { return nil }
        var result: UInt64 = 0
        var shift: UInt64 = 0
        var index = offset
        var bytesRead = 0
        let end = data.endIndex
        while index < end {
            if bytesRead >= 10 { return nil }
            let byte = data[index]
            result |= UInt64(byte & 0x7F) << shift
            index += 1
            bytesRead += 1
            if byte & 0x80 == 0 {
                return (result, index)
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
        var index = data.startIndex
        let end = data.endIndex
        while index < end {
            guard let (tag, next) = readVarint(data, from: index) else {
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "truncated or oversized tag varint at offset \(index - data.startIndex)"))
            }
            index = next
            let wire = UInt8(tag & 0x7)
            let fieldRaw = tag >> 3
            // Field 0 is reserved; max is 2^29-1 per the protobuf spec.
            guard fieldRaw > 0, fieldRaw <= 536870911 else {
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "invalid field number \(fieldRaw)"))
            }
            let field = UInt32(fieldRaw)
            switch wire {
            case 0:
                guard let (v, n) = readVarint(data, from: index) else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "truncated varint for field \(field)"))
                }
                index = n
                entries.append(ProtobufEntry(field: field, wire: 0, value: .varint(v)))
            case 1:
                guard index + 8 <= end else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "truncated fixed64 for field \(field)"))
                }
                entries.append(ProtobufEntry(field: field, wire: 1, value: .bytes(data.subdata(in: index..<index + 8))))
                index += 8
            case 2:
                guard let (length, n) = readVarint(data, from: index) else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "truncated length for field \(field)"))
                }
                index = n
                guard length <= UInt64(end - index) else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "length-delimited field \(field) (len=\(length)) exceeds message"))
                }
                let needed = Int(length)
                entries.append(ProtobufEntry(field: field, wire: 2, value: .bytes(data.subdata(in: index..<index + needed))))
                index += needed
            case 5:
                guard index + 4 <= end else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "truncated fixed32 for field \(field)"))
                }
                entries.append(ProtobufEntry(field: field, wire: 5, value: .bytes(data.subdata(in: index..<index + 4))))
                index += 4
            case 3, 4:
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "deprecated group wire type \(wire) is not supported"))
            default:
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "unknown wire type \(wire)"))
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
            throw AnywhereError.mitm(.scriptMessageMalformed(detail: "expected an array of {field, wire, value} entries"))
        }
        guard let count = Self.validatedArrayLength(val, max: 10_000_000) else {
            throw AnywhereError.mitm(.scriptMessageMalformed(detail: "input array length is missing, negative, or too large"))
        }
        var entries: [ProtobufEntry] = []
        entries.reserveCapacity(count)
        for index in 0..<count {
            guard let entryVal = val.objectAtIndexedSubscript(index),
                  !entryVal.isUndefined, !entryVal.isNull else {
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index) is null/undefined"))
            }
            let fieldVal = entryVal.objectForKeyedSubscript("field")
            guard let fieldVal, fieldVal.isNumber else {
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).field must be a Number"))
            }
            let fieldNum = fieldVal.toInt32()
            guard fieldNum > 0, fieldNum <= 536_870_911 else {
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).field \(fieldNum) out of range (1…2^29-1)"))
            }
            let wireVal = entryVal.objectForKeyedSubscript("wire")
            guard let wireVal, wireVal.isNumber else {
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).wire must be a Number"))
            }
            let wireNum = UInt8(truncatingIfNeeded: wireVal.toInt32())
            let valueVal = entryVal.objectForKeyedSubscript("value")
            switch wireNum {
            case 0:
                guard let v = valueVal.flatMap({ uint64FromJSValue($0) }) else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).value (wire 0) must be a non-negative integer Number or BigInt"))
                }
                entries.append(ProtobufEntry(field: UInt32(fieldNum), wire: 0, value: .varint(v)))
            case 1:
                guard let bytes = valueVal.flatMap({ bytesFromValue($0, in: context) }), bytes.count == 8 else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).value (wire 1) must be a Uint8Array of length 8"))
                }
                entries.append(ProtobufEntry(field: UInt32(fieldNum), wire: 1, value: .bytes(bytes)))
            case 2:
                guard let bytes = valueVal.flatMap({ bytesFromValue($0, in: context) }) else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).value (wire 2) must be Uint8Array/ArrayBuffer/string"))
                }
                entries.append(ProtobufEntry(field: UInt32(fieldNum), wire: 2, value: .bytes(bytes)))
            case 5:
                guard let bytes = valueVal.flatMap({ bytesFromValue($0, in: context) }), bytes.count == 4 else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).value (wire 5) must be a Uint8Array of length 4"))
                }
                entries.append(ProtobufEntry(field: UInt32(fieldNum), wire: 5, value: .bytes(bytes)))
            case 3, 4:
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).wire = \(wireNum): deprecated group wire types not supported"))
            default:
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).wire = \(wireNum): unknown wire type"))
            }
        }
        return entries
    }
    
    fileprivate static func makeProtobufEntries(_ entries: [ProtobufEntry], in context: JSContext) -> JSValue {
        let array = JSValue(newArrayIn: context)!
        let bigIntFn = context.objectForKeyedSubscript("BigInt")
        for (idx, entry) in entries.enumerated() {
            let object = JSValue(newObjectIn: context)!
            object.setObject(NSNumber(value: entry.field), forKeyedSubscript: "field" as NSString)
            object.setObject(NSNumber(value: entry.wire), forKeyedSubscript: "wire" as NSString)
            let v: JSValue
            switch entry.value {
            case .varint(let u):
                v = bigIntFn?.call(withArguments: [String(u)]) ?? JSValue(undefinedIn: context)
            case .bytes(let d):
                v = makeUint8Array(in: context, from: d)
            }
            object.setObject(v, forKeyedSubscript: "value" as NSString)
            array.setObject(object, atIndexedSubscript: idx)
        }
        return array
    }
    
    fileprivate static func makeBigInt(_ value: UInt64, in context: JSContext) -> JSValue {
        let bigIntFn = context.objectForKeyedSubscript("BigInt")
        return bigIntFn?.call(withArguments: [String(value)]) ?? JSValue(undefinedIn: context)
    }
    
    fileprivate static func uint64FromJSValue(_ val: JSValue) -> UInt64? {
        if val.isUndefined || val.isNull { return nil }
        if val.isNumber {
            let d = val.toDouble()
            guard d.isFinite, d >= 0, d <= 9_007_199_254_740_991.0, d == d.rounded() else {
                return nil
            }
            return UInt64(d)
        }
        guard let string = val.toString() else { return nil }
        return UInt64(string)
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
        s = s.filter { !$0.isWhitespace }
        let mod = s.count % 4
        if mod > 0 {
            s += String(repeating: "=", count: 4 - mod)
        }
        return Data(base64Encoded: s)
    }
    
    fileprivate static func parseJSON(_ str: String, in context: JSContext) -> JSValue? {
        let json = context.objectForKeyedSubscript("JSON")
        let result = json?.invokeMethod("parse", withArguments: [str])
        if context.exception != nil {
            context.exception = nil
            return nil
        }
        return result
    }
    
    fileprivate static func encodeJWTSegment(_ value: JSValue?, in context: JSContext) -> String? {
        guard let value, !value.isUndefined, !value.isNull else { return nil }
        if let bytes = bytesFromValue(value, in: context) {
            return encodeBase64URL(bytes)
        }
        let json = context.objectForKeyedSubscript("JSON")
        guard let result = json?.invokeMethod("stringify", withArguments: [value]),
              !result.isUndefined,
              let string = result.toString() else {
            return nil
        }
        return encodeBase64URL(Data(string.utf8))
    }
}

extension MITMScriptEngine {
    private struct EngineRegistry {
        var engines: [UUID: MITMScriptEngine] = [:]
        var scopelessEngine: MITMScriptEngine?
    }
    private static let registry = Mutex(EngineRegistry())

    static func sharedEngine(forScope scope: UUID?) -> MITMScriptEngine {
        registry.withLock { registry -> MITMScriptEngine in
            guard let scope else {
                if let engine = registry.scopelessEngine { return engine }
                let engine = MITMScriptEngine()
                registry.scopelessEngine = engine
                return engine
            }
            if let engine = registry.engines[scope] { return engine }
            let engine = MITMScriptEngine()
            registry.engines[scope] = engine
            return engine
        }
    }

    static func purgeEngines(activeIDs: Set<UUID>) {
        let dropped: [MITMScriptEngine] = registry.withLock { registry in
            let removed = registry.engines.filter { !activeIDs.contains($0.key) }.map { $0.value }
            registry.engines = registry.engines.filter { activeIDs.contains($0.key) }
            return removed
        }
        guard !dropped.isEmpty else { return }
        JSCConcurrencyBridge.shared.enqueue {
            for engine in dropped {
                engine.assumeIsolated { $0.shutdown() }
            }
            withExtendedLifetime(dropped) {}
        }
    }
    
    static func resetCachesOnReload(keepByScope: [UUID: Set<Int>]) {
        JSCConcurrencyBridge.shared.enqueue {
            let snapshot: [(engine: MITMScriptEngine, keep: Set<Int>)] = registry.withLock { registry in
                registry.engines.map { (engine: $0.value, keep: keepByScope[$0.key] ?? []) }
            }
            for item in snapshot {
                item.engine.assumeIsolated { $0.resetOnReload(keepingCompiled: item.keep) }
            }
        }
    }
    
    final class Provider: Sendable {
        private let scope: UUID?
        init(scope: UUID?) { self.scope = scope }
        func get() -> MITMScriptEngine { MITMScriptEngine.sharedEngine(forScope: scope) }
    }
}
