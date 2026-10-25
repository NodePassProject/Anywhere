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

nonisolated private let mitmScriptSuspendedBodyBytes = Atomic<Int>(0)

nonisolated private let mitmScriptGlobalFetchCount = Atomic<Int>(0)

nonisolated private let mitmScriptRuleSetNames = Mutex<[UUID: String]>([:])

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
        let originalURL: String?
        let status: Int?
        let headers: [(name: String, value: String)]
        let frameIndex: Int
        let isLast: Bool
        let ruleSetID: UUID?
    }

    enum FrameOutcome {
        case modified(body: Data)
        case done(body: Data)
        case exit
    }

    fileprivate enum Directive: Sendable {
        case done
        case exit
        case respond(SynthesizedResponse)
    }

    final class ScriptRun: @unchecked Sendable {
        private static let idSequence = Atomic<UInt64>(0)

        let id = ScriptRun.idSequence.wrappingAdd(1, ordering: .relaxed).newValue
        let startedAt = MonotonicClock.now

        let scope: UUID?
        let allowsHTTP: Bool
        let context: JSContext

        fileprivate var directive: Directive?
        fileprivate let original: Message?
        fileprivate var contextValue: JSValue?
        fileprivate var continuation: CheckedContinuation<Outcome, Never>?
        fileprivate var resultPromise: JSValue?
        fileprivate var inFlightFetches = 0
        fileprivate var totalFetches = 0
        fileprivate var isDelivered = false

        fileprivate var isClosed = false
        fileprivate var pinnedBodyBytes = 0
        fileprivate var watchdogDisarm: AsyncInbox<Void>?

        fileprivate var streamState: JSValue?
        fileprivate var streamProcess: JSValue?
        fileprivate var streamCompileAttempted = false

        fileprivate var isFormattingException = false

        fileprivate var pendingFetches: [Int: PendingFetch] = [:]
        private var nextFetchID = 0

        fileprivate func claimFetchID() -> Int {
            nextFetchID += 1
            return nextFetchID
        }

        var logPrefix: String {
            guard let scope, let name = mitmScriptRuleSetNames.withLock({ $0[scope] }) else { return "[Script]" }
            return "[Script] \(name)"
        }

        fileprivate init(scope: UUID?, allowsHTTP: Bool, context: JSContext, original: Message?) {
            self.scope = scope
            self.allowsHTTP = allowsHTTP
            self.context = context
            self.original = original
        }

        fileprivate func teardown() {
            isClosed = true
            for fetch in pendingFetches.values { fetch.task?.cancel() }
            pendingFetches.removeAll()
            resultPromise = nil
            contextValue = nil
            streamState = nil
            streamProcess = nil
            context.exception = nil
            context.exceptionHandler = nil
        }
    }

    fileprivate struct PendingFetch {
        let resolve: JSValue?
        let reject: JSValue?
        var task: Task<Void, Never>?
    }

    private static let sharedVirtualMachine = JSVirtualMachine()!

    private var liveRuns: [UInt64: ScriptRun] = [:]

    // MARK: - Watchdog task tree

    private struct WatchdogJob: Sendable {
        let id: UInt64
        let disarm: AsyncInbox<Void>
    }
    private let watchdogJobs: AsyncStream<WatchdogJob>
    private nonisolated let watchdogJobContinuation: AsyncStream<WatchdogJob>.Continuation
    private var watchdogRoot: Task<Void, Never>?

    private static let maxSuspendedBodyBytes: Int = 16 * 1024 * 1024

    private static let maxLiveRuns = 32

    // MARK: Anywhere.http caps

    private static let httpDefaultTimeout: TimeInterval = 10
    private static let httpMaxTimeout: TimeInterval = 30
    private static let httpMaxConcurrentPerInvocation = 4
    private static let httpMaxTotalPerInvocation = 16
    private static let httpMaxResponseBytes = 4 * 1024 * 1024
    private static let httpMaxConcurrentGlobal = 32

    private static let invocationIdleTimeout: TimeInterval = httpMaxTimeout + 30

    private static let invocationAbsoluteTimeout: TimeInterval = invocationIdleTimeout * 3

    init() {
        (self.watchdogJobs, self.watchdogJobContinuation) = AsyncStream.makeStream(of: WatchdogJob.self)
    }

    static func warmVirtualMachine() {
        JSCConcurrencyBridge.shared.enqueue { _ = warmedVirtualMachine }
    }

    private static let warmedVirtualMachine: Bool = {
        let engine = MITMScriptEngine()
        let run = engine.makeRun(scope: nil, allowsHTTP: false, original: nil)
        run.teardown()
        withExtendedLifetime(engine) {}
        return true
    }()

    // MARK: - Run construction

    nonisolated private func makeRun(scope: UUID?, allowsHTTP: Bool, original: Message?) -> ScriptRun {
        let context = JSContext(virtualMachine: Self.sharedVirtualMachine)!
        let run = ScriptRun(scope: scope, allowsHTTP: allowsHTTP, context: context, original: original)
        configureContext(context, for: run)
        return run
    }

    nonisolated private func configureContext(_ context: JSContext, for run: ScriptRun) {
        context.exceptionHandler = { [weak run] context, exception in
            defer { context?.exception = exception }
            guard let run else { return }
            if run.isFormattingException {
                logger.warning("\(run.logPrefix): Uncaught exception")
                return
            }
            run.isFormattingException = true
            defer { run.isFormattingException = false }
            logger.warning("\(run.logPrefix): \(exception.map(Self.describe) ?? "Uncaught exception")")
        }
        installAnywhereGlobals(context: context, for: run)
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

    private func runWatchdog(id: UInt64, disarm: AsyncInbox<Void>) async {
        let timedOut = await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                do {
                    try await Task.sleep(seconds: Self.invocationIdleTimeout, precision: .relaxed)
                    return true
                } catch {
                    return false
                }
            }
            group.addTask {
                _ = try? await disarm.next()
                return false
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
        guard timedOut else { return }
        guard let run = liveRuns[id], !run.isDelivered, let original = run.original else { return }
        logger.warning("\(run.logPrefix): process(ctx) timed out")
        deliver(.modified(original), for: run)
    }

    private func dropRuns(notIn activeIDs: Set<UUID>) {
        for run in Array(liveRuns.values) {
            guard let scope = run.scope, !activeIDs.contains(scope) else { continue }
            if !run.isDelivered, let original = run.original {
                deliver(.modified(original), for: run)
            } else {
                liveRuns.removeValue(forKey: run.id)
                run.teardown()
            }
        }
    }

    @inline(__always)
    private func runUserScript<T>(_ label: String, _ body: () -> T) -> T {
        MITMScriptWatchdog.begin(label)
        defer { MITMScriptWatchdog.end() }
        return body()
    }

    private func finalize(_ run: ScriptRun, original: Message, updated: Message) -> Outcome {
        let hadException = run.context.exception != nil
        run.context.exception = nil
        if let directive = run.directive {
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
            logger.warning("[Script] Anywhere.respond unavailable in response phase")
            return .modified(updated)
        }
    }

    private func isThenable(_ value: JSValue, in context: JSContext) -> Bool {
        guard value.isObject,
              let thenValue = value.objectForKeyedSubscript("then"),
              thenValue.isObject,
              let ref = thenValue.jsValueRef
        else { return false }
        let contextRef = context.jsGlobalContextRef
        var exception: JSValueRef?
        guard let object = JSValueToObject(contextRef, ref, &exception), exception == nil else {
            return false
        }
        return JSObjectIsFunction(contextRef, object)
    }

    // MARK: - Script

    private final class CancelHandle: Sendable {
        let state = Mutex<(runID: UInt64?, isCancelled: Bool)>((runID: nil, isCancelled: false))
    }

    func applyAsync(
        _ message: Message,
        source: String
    ) async -> Outcome {
        let cancelHandle = CancelHandle()
        return await withTaskCancellationHandler {
            await JSCConcurrencyBridge.shared.runParked { (continuation: CheckedContinuation<Outcome, Never>) in
                self.runApply(message, source: source, continuation: continuation, cancelHandle: cancelHandle)
            }
        } onCancel: {
            JSCConcurrencyBridge.shared.enqueue { [self] in
                self.assumeIsolated { $0.cancelRun(cancelHandle) }
            }
        }
    }

    private func cancelRun(_ cancelHandle: CancelHandle) {
        let runID = cancelHandle.state.withLock { state -> UInt64? in
            state.isCancelled = true
            return state.runID
        }
        guard let runID, let run = liveRuns[runID], !run.isDelivered, let original = run.original else { return }
        deliver(.modified(original), for: run)
    }

    private func runApply(
        _ message: Message,
        source: String,
        continuation: CheckedContinuation<Outcome, Never>,
        cancelHandle: CancelHandle
    ) {
        let bodyBytes = message.body.count
        let pinned = Self.suspendedBodyBytes()
        if pinned + bodyBytes > Self.maxSuspendedBodyBytes {
            logger.warning("[Script] Suspended body budget exceeded")
            continuation.resume(returning: .modified(message))
            return
        }
        if liveRuns.count >= Self.maxLiveRuns {
            logger.warning("[Script] Too many concurrent scripts")
            continuation.resume(returning: .modified(message))
            return
        }

        let run = makeRun(scope: message.ruleSetID, allowsHTTP: true, original: message)
        run.continuation = continuation

        guard let function = compile(source, in: run) else {
            deliver(.modified(message), for: run)
            return
        }

        runUserScript(source) {
            let contextValue = makeContextValue(message, in: run.context)
            run.contextValue = contextValue
            let returned = function.call(withArguments: [contextValue])
            guard let returned, isThenable(returned, in: run.context) else {
                let updated = readBack(message, from: contextValue, in: run.context)
                deliver(finalize(run, original: message, updated: updated), for: run)
                return
            }
            run.pinnedBodyBytes = bodyBytes
            Self.addSuspendedBodyBytes(bodyBytes)
            run.resultPromise = returned
            liveRuns[run.id] = run
            armWatchdog(for: run)
            attachSettleHandlers(to: returned, for: run)
            let isCancelled = cancelHandle.state.withLock { state -> Bool in
                state.runID = run.id
                return state.isCancelled
            }
            if isCancelled { deliver(.modified(message), for: run) }
        }
    }

    private func attachSettleHandlers(to promise: JSValue, for run: ScriptRun) {
        let id = run.id
        let onFulfilled: @convention(block) (JSValue) -> Void = { [weak self] _ in
            guard let self else { return }
            self.assumeIsolated { engine in
                guard let run = engine.liveRuns[id] else { return }
                engine.finishSuccess(run)
            }
        }
        let onRejected: @convention(block) (JSValue) -> Void = { [weak self] reason in
            guard let self else { return }
            self.assumeIsolated { engine in
                guard let run = engine.liveRuns[id] else { return }
                engine.finishRejected(run, reason: reason)
            }
        }
        promise.invokeMethod("then", withArguments: [onFulfilled, onRejected])
        if run.context.exception != nil { run.context.exception = nil }
    }

    private func finishSuccess(_ run: ScriptRun) {
        guard !run.isDelivered, let original = run.original, let contextArgument = run.contextValue else { return }
        let updated = readBack(original, from: contextArgument, in: run.context)
        deliver(finalize(run, original: original, updated: updated), for: run)
    }

    private func finishRejected(_ run: ScriptRun, reason: JSValue?) {
        guard !run.isDelivered, let original = run.original else { return }
        let contextArgument = run.contextValue ?? makeContextValue(original, in: run.context)
        let updated = readBack(original, from: contextArgument, in: run.context)
        run.context.exception = nil
        if let directive = run.directive {
            deliver(outcome(forDirective: directive, original: original, updated: updated), for: run)
        } else {
            if let reason {
                logger.warning("\(run.logPrefix): process(ctx) rejected: \(Self.describe(reason))")
            }
            deliver(.modified(original), for: run)
        }
    }

    private func deliver(_ outcome: Outcome, for run: ScriptRun) {
        guard !run.isDelivered else { return }
        run.isDelivered = true
        run.watchdogDisarm?.finish()
        run.watchdogDisarm = nil
        liveRuns.removeValue(forKey: run.id)
        if run.pinnedBodyBytes > 0 {
            Self.addSuspendedBodyBytes(-run.pinnedBodyBytes)
            run.pinnedBodyBytes = 0
        }
        let continuation = run.continuation
        run.continuation = nil
        run.teardown()
        continuation?.resume(returning: outcome)
    }

    private func armWatchdog(for run: ScriptRun) {
        if watchdogRoot == nil {
            watchdogRoot = Task { await self.runWatchdogTree() }
        }
        run.watchdogDisarm?.finish()
        let disarm = AsyncInbox<Void>(capacity: 1)
        run.watchdogDisarm = disarm
        watchdogJobContinuation.yield(WatchdogJob(id: run.id, disarm: disarm))
    }

    private static func suspendedBodyBytes() -> Int {
        mitmScriptSuspendedBodyBytes.load(ordering: .relaxed)
    }

    private static func addSuspendedBodyBytes(_ delta: Int) {
        mitmScriptSuspendedBodyBytes.wrappingAdd(delta, ordering: .relaxed)
    }

    // MARK: - Stream Script

    func openStreamRun(scope: UUID?) -> ScriptRun? {
        guard liveRuns.count < Self.maxLiveRuns else {
            logger.warning("[Script] Too many concurrent scripts")
            return nil
        }
        let run = makeRun(scope: scope, allowsHTTP: false, original: nil)
        liveRuns[run.id] = run
        return run
    }

    func closeStreamRun(_ run: ScriptRun) {
        liveRuns.removeValue(forKey: run.id)
        run.teardown()
    }

    func applyFrame(
        _ frame: Data,
        source: String,
        frameContext: FrameContext,
        run: ScriptRun
    ) -> FrameOutcome {
        guard !run.isClosed else { return .modified(body: frame) }
        if !run.streamCompileAttempted {
            run.streamCompileAttempted = true
            run.streamProcess = compile(source, in: run)
        }
        guard let function = run.streamProcess else {
            return .modified(body: frame)
        }
        run.directive = nil
        let context = run.context
        let body: Data = runUserScript(source) {
            let contextArgument = makeFrameContextValue(frameContext, frame: frame, in: run)
            _ = function.call(withArguments: [contextArgument])
            var result = frame
            if let bodyValue = contextArgument.objectForKeyedSubscript("body"),
               let bytes = Self.bytesFromValue(bodyValue, in: context) {
                result = bytes
            }
            run.streamState = contextArgument.objectForKeyedSubscript("state")
            return result
        }
        let hadException = context.exception != nil
        if let directive = run.directive {
            context.exception = nil
            switch directive {
            case .done: return .done(body: body)
            case .exit: return .exit
            case .respond:
                logger.warning("\(run.logPrefix): Anywhere.respond unavailable in streamScript")
                return .modified(body: body)
            }
        }
        if hadException {
            context.exception = nil
            return .modified(body: frame)
        }
        return .modified(body: body)
    }

    // MARK: - Compilation

    private static let wrapperLineCount = 2

    private static func describe(_ exception: JSValue) -> String {
        let message = exception.toString() ?? "Uncaught exception"
        guard let line = exception.objectForKeyedSubscript("line"), line.isNumber else { return message }
        let sourceLine = Int(line.toInt32()) - wrapperLineCount
        return sourceLine > 0 ? "line \(sourceLine): \(message)" : message
    }

    private func compile(_ source: String, in run: ScriptRun) -> JSValue? {
        let context = run.context
        let wrapped = "(function(){\n\"use strict\";\n\(source)\nreturn process;\n})()"
        let value = runUserScript(source) { context.evaluateScript(wrapped) }
        if context.exception != nil {
            context.exception = nil
            return nil
        }
        guard let value, !value.isUndefined, !value.isNull else {
            logger.warning("\(run.logPrefix): process(ctx) not defined")
            return nil
        }
        guard let ref = value.jsValueRef else { return nil }
        let contextRef = context.jsGlobalContextRef
        var exception: JSValueRef?
        guard let object = JSValueToObject(contextRef, ref, &exception),
              exception == nil,
              JSObjectIsFunction(contextRef, object)
        else {
            logger.warning("\(run.logPrefix): process is not a function")
            return nil
        }
        return value
    }

    // MARK: - Context bridging

    private func makeContextValue(_ message: Message, in context: JSContext) -> JSValue {
        let object = JSValue(newObjectIn: context)!
        object.setObject(
            message.phase == .httpRequest ? "request" : "response",
            forKeyedSubscript: "phase" as NSString
        )
        object.setObject(message.method as Any, forKeyedSubscript: "method" as NSString)
        object.setObject(message.url as Any, forKeyedSubscript: "url" as NSString)
        object.setObject(message.originalURL as Any, forKeyedSubscript: "originalUrl" as NSString)
        object.setObject(message.status as Any, forKeyedSubscript: "status" as NSString)
        let pairs: [[String]] = message.headers.map { [$0.name, $0.value] }
        object.setObject(pairs, forKeyedSubscript: "headers" as NSString)
        object.setObject(Self.makeUint8Array(in: context, from: message.body), forKeyedSubscript: "body" as NSString)
        return object
    }

    private func makeFrameContextValue(
        _ frameContext: FrameContext,
        frame: Data,
        in run: ScriptRun
    ) -> JSValue {
        let context = run.context
        let object = JSValue(newObjectIn: context)!
        object.setObject(
            frameContext.phase == .httpRequest ? "request" : "response",
            forKeyedSubscript: "phase" as NSString
        )
        object.setObject(frameContext.method as Any, forKeyedSubscript: "method" as NSString)
        object.setObject(frameContext.url as Any, forKeyedSubscript: "url" as NSString)
        object.setObject(frameContext.originalURL as Any, forKeyedSubscript: "originalUrl" as NSString)
        object.setObject(frameContext.status as Any, forKeyedSubscript: "status" as NSString)
        let pairs: [[String]] = frameContext.headers.map { [$0.name, $0.value] }
        object.setObject(pairs, forKeyedSubscript: "headers" as NSString)

        let frameInfo = JSValue(newObjectIn: context)!
        frameInfo.setObject(frameContext.frameIndex, forKeyedSubscript: "index" as NSString)
        frameInfo.setObject(frameContext.isLast, forKeyedSubscript: "end" as NSString)
        object.setObject(frameInfo, forKeyedSubscript: "frame" as NSString)

        let stateValue = run.streamState ?? JSValue(newObjectIn: context)!
        object.setObject(stateValue, forKeyedSubscript: "state" as NSString)

        object.setObject(Self.makeUint8Array(in: context, from: frame), forKeyedSubscript: "body" as NSString)
        return object
    }

    private func readBack(_ original: Message, from contextValue: JSValue, in context: JSContext) -> Message {
        var message = original
        if let body = contextValue.objectForKeyedSubscript("body"),
           let bytes = Self.bytesFromValue(body, in: context) {
            message.body = bytes
        }
        return message
    }

    private static func validatedArrayLength(_ value: JSValue, maxLength: Int) -> Int? {
        guard let lengthValue = value.objectForKeyedSubscript("length"), lengthValue.isNumber else {
            return nil
        }
        let raw = lengthValue.toDouble()
        guard raw.isFinite, raw >= 0, raw <= Double(maxLength) else { return nil }
        return Int(raw)
    }

    private static func headersFromValue(_ value: JSValue) -> [(name: String, value: String)]? {
        guard value.isArray else { return nil }
        guard let length = Self.validatedArrayLength(value, maxLength: 100_000) else {
            logger.warning("[Script] Invalid ctx.headers")
            return nil
        }
        if length == 0 { return [] }
        var result: [(name: String, value: String)] = []
        result.reserveCapacity(length)
        for index in 0..<length {
            guard let entry = value.objectAtIndexedSubscript(index),
                  entry.isArray,
                  let entryLength = entry.objectForKeyedSubscript("length")?.toInt32(),
                  entryLength == 2
            else {
                logger.warning("[Script] Invalid ctx.headers entry")
                continue
            }
            guard let nameElement = entry.objectAtIndexedSubscript(0),
                  let valueElement = entry.objectAtIndexedSubscript(1),
                  !nameElement.isUndefined, !nameElement.isNull,
                  !valueElement.isUndefined, !valueElement.isNull,
                  let name = nameElement.toString(),
                  let value = valueElement.toString()
            else {
                logger.warning("[Script] Invalid ctx.headers entry")
                continue
            }
            guard HTTPHeader.isValidName(name) else {
                logger.warning("[Script] Invalid header name: \(name)")
                continue
            }
            guard HTTPHeader.isValidValue(value) else {
                logger.warning("[Script] Invalid header value: \(name)")
                continue
            }
            result.append((name: name, value: value))
        }
        if result.isEmpty {
            logger.warning("[Script] ctx.headers has no valid entries")
            return nil
        }
        return result
    }

    // MARK: - Anywhere globals

    private static let bootstrapSource = #"""
    (function (resolve, control) {
      "use strict";
      var pin = function (target, name, value, enumerable) {
        Object.defineProperty(target, name, { value: value, writable: true, enumerable: enumerable, configurable: true });
        return value;
      };
      var lazy = function (target, name, enumerable, make) {
        Object.defineProperty(target, name, {
          get: function () {
            var value = make();
            return value === undefined ? undefined : pin(this, name, value, enumerable);
          },
          set: function (value) { pin(this, name, value, enumerable); },
          enumerable: enumerable,
          configurable: true
        });
      };
      var Anywhere = {};
      lazy(Anywhere, "codec", true, function () {
        var codec = {};
        ["utf8", "base64", "base64url", "hex", "protobuf", "gzip", "deflate", "brotli"].forEach(function (name) {
          lazy(codec, name, true, function () { return resolve("codec." + name); });
        });
        return codec;
      });
      ["crypto", "jwt", "json", "store", "params", "log", "http"].forEach(function (name) {
        lazy(Anywhere, name, true, function () { return resolve(name); });
      });
      Anywhere.done = function () { control("done"); };
      Anywhere.exit = function () { control("exit"); };
      Anywhere.respond = function (spec) { control("respond", spec); };
      globalThis.Anywhere = Anywhere;

      var textCodecs = null;
      var textCodec = function (name) {
        if (textCodecs === null) {
          var native = resolve("textCodecs");
          if (native === undefined) { return undefined; }
          var TextEncoder = function TextEncoder() { this.encoding = "utf-8"; };
          TextEncoder.prototype.encode = function (input) { return native.encode(input); };
          var TextDecoder = function TextDecoder(label, options) {
            this.encoding = (label == null ? "utf-8" : String(label)).toLowerCase();
            this.fatal = !!(options && options.fatal);
            this.ignoreBOM = !!(options && options.ignoreBOM);
          };
          TextDecoder.prototype.decode = function (input) { return native.decode(input); };
          textCodecs = { TextEncoder: TextEncoder, TextDecoder: TextDecoder };
          pin(globalThis, "TextEncoder", TextEncoder, false);
          pin(globalThis, "TextDecoder", TextDecoder, false);
        }
        return textCodecs[name];
      };
      ["TextEncoder", "TextDecoder"].forEach(function (name) {
        Object.defineProperty(globalThis, name, {
          get: function () { return textCodec(name); },
          set: function (value) { pin(globalThis, name, value, false); },
          enumerable: false,
          configurable: true
        });
      });
    })
    """#

    nonisolated private func installAnywhereGlobals(context: JSContext, for run: ScriptRun) {
        let resolve: @convention(block) (String) -> JSValue = { [weak self, weak run] name in
            let context = JSContext.current()!
            guard let self, let run, let value = self.makeNamespace(name, in: context, for: run) else {
                return JSValue(undefinedIn: context)
            }
            return value
        }
        let control: @convention(block) (String, JSValue) -> Void = { [weak run] directive, argument in
            guard let run else { return }
            switch directive {
            case "done": run.directive = .done
            case "exit": run.directive = .exit
            case "respond": run.directive = .respond(Self.synthesizedResponse(from: argument))
            default: break
            }
        }
        guard let bootstrap = context.evaluateScript(Self.bootstrapSource),
              context.exception == nil,
              bootstrap.call(withArguments: [resolve, control]) != nil,
              context.exception == nil
        else {
            context.exception = nil
            logger.error("\(run.logPrefix): Anywhere API installation failed")
            return
        }
    }

    nonisolated private func makeNamespace(_ name: String, in context: JSContext, for run: ScriptRun) -> JSValue? {
        switch name {
        case "crypto":     return makeCryptoNamespace(in: context)
        case "jwt":        return makeJWTNamespace(in: context)
        case "json":       return makeJSONNamespace(in: context)
        case "store":      return makeStoreNamespace(in: context, scope: run.scope)
        case "params":     return makeParamsNamespace(in: context, scope: run.scope)
        case "log":        return makeLogNamespace(in: context, for: run)
        case "http":       return makeHTTPNamespace(in: context, for: run)
        case "textCodecs": return makeTextCodecNatives(in: context)
        default:
            guard name.hasPrefix("codec.") else { return nil }
            return makeCodec(named: String(name.dropFirst("codec.".count)), in: context)
        }
    }

    nonisolated private func makeTextCodecNatives(in context: JSContext) -> JSValue {
        let natives = JSValue(newObjectIn: context)!
        let encode: @convention(block) (JSValue) -> JSValue = { input in
            let context = JSContext.current()!
            let text = (input.isUndefined || input.isNull) ? "" : (input.toString() ?? "")
            return Self.makeUint8Array(in: context, from: Data(text.utf8))
        }
        let decode: @convention(block) (JSValue) -> String = { input in
            let context = JSContext.current()!
            guard !input.isUndefined, !input.isNull else { return "" }
            return String(decoding: Self.bytesFromValue(input, in: context) ?? Data(), as: UTF8.self)
        }
        natives.setObject(encode, forKeyedSubscript: "encode" as NSString)
        natives.setObject(decode, forKeyedSubscript: "decode" as NSString)
        return natives
    }

    nonisolated private func makeCodec(named name: String, in context: JSContext) -> JSValue? {
        switch name {
        case "utf8":      return makeUTF8Codec(in: context)
        case "base64":    return makeBase64Codec(in: context)
        case "base64url": return makeBase64URLCodec(in: context)
        case "hex":       return makeHexCodec(in: context)
        case "protobuf":  return makeProtobufCodec(in: context)
        case "gzip":      return makeCompressionCodec(named: name, codec: .gzip, in: context)
        case "deflate":   return makeCompressionCodec(named: name, codec: .deflate, in: context)
        case "brotli":    return makeCompressionCodec(named: name, codec: .brotli, in: context)
        default:          return nil
        }
    }

    nonisolated private func makeUTF8Codec(in context: JSContext) -> JSValue {
        let utf8 = JSValue(newObjectIn: context)!
        let utf8Encode: @convention(block) (String) -> JSValue = { string in
            let context = JSContext.current()!
            return Self.makeUint8Array(in: context, from: Data(string.utf8))
        }
        let utf8Decode: @convention(block) (JSValue) -> String = { value in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(value, in: context) ?? Data()
            return String(decoding: bytes, as: UTF8.self)
        }
        utf8.setObject(utf8Encode, forKeyedSubscript: "encode" as NSString)
        utf8.setObject(utf8Decode, forKeyedSubscript: "decode" as NSString)
        return utf8
    }

    nonisolated private func makeBase64Codec(in context: JSContext) -> JSValue {
        let base64 = JSValue(newObjectIn: context)!
        let base64Encode: @convention(block) (JSValue) -> String = { value in
            let context = JSContext.current()!
            return (Self.bytesFromValue(value, in: context) ?? Data()).base64EncodedString()
        }
        let base64Decode: @convention(block) (String) -> JSValue = { string in
            let context = JSContext.current()!
            return Self.makeUint8Array(in: context, from: Data(base64Encoded: string, options: .ignoreUnknownCharacters) ?? Data())
        }
        base64.setObject(base64Encode, forKeyedSubscript: "encode" as NSString)
        base64.setObject(base64Decode, forKeyedSubscript: "decode" as NSString)
        return base64
    }

    nonisolated private func makeBase64URLCodec(in context: JSContext) -> JSValue {
        let base64url = JSValue(newObjectIn: context)!
        let base64URLEncodeBlock: @convention(block) (JSValue) -> String = { value in
            let context = JSContext.current()!
            return Self.encodeBase64URL(Self.bytesFromValue(value, in: context) ?? Data())
        }
        let base64URLDecodeBlock: @convention(block) (String) -> JSValue = { string in
            let context = JSContext.current()!
            return Self.makeUint8Array(in: context, from: Self.decodeBase64URL(string) ?? Data())
        }
        base64url.setObject(base64URLEncodeBlock, forKeyedSubscript: "encode" as NSString)
        base64url.setObject(base64URLDecodeBlock, forKeyedSubscript: "decode" as NSString)
        return base64url
    }

    nonisolated private func makeHexCodec(in context: JSContext) -> JSValue {
        let hex = JSValue(newObjectIn: context)!
        let hexEncode: @convention(block) (JSValue) -> String = { value in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(value, in: context) ?? Data()
            return bytes.map { String(format: "%02x", $0) }.joined()
        }
        let hexDecode: @convention(block) (String) -> JSValue = { string in
            let context = JSContext.current()!
            return Self.makeUint8Array(in: context, from: Self.decodeHex(string))
        }
        hex.setObject(hexEncode, forKeyedSubscript: "encode" as NSString)
        hex.setObject(hexDecode, forKeyedSubscript: "decode" as NSString)
        return hex
    }

    nonisolated private func makeProtobufCodec(in context: JSContext) -> JSValue {
        let protobuf = JSValue(newObjectIn: context)!
        let protobufDecodeBlock: @convention(block) (JSValue) -> JSValue = { value in
            let context = JSContext.current()!
            guard let bytes = Self.bytesFromValue(value, in: context) else {
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
        let protobufEncodeBlock: @convention(block) (JSValue) -> JSValue = { value in
            let context = JSContext.current()!
            do {
                let entries = try Self.parseProtobufEntries(value, in: context)
                return Self.makeUint8Array(in: context, from: Self.protobufEncodeWire(entries))
            } catch {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.encode: \(AnywhereError.describe(error))",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
        }
        let protobufEncodeVarintBlock: @convention(block) (JSValue) -> JSValue = { value in
            let context = JSContext.current()!
            guard let varint = Self.uint64FromJSValue(value) else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.encodeVarint: expected non-negative Number or BigInt",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            return Self.makeUint8Array(in: context, from: Self.writeVarint(varint))
        }
        let protobufDecodeVarintBlock: @convention(block) (JSValue, JSValue) -> JSValue = { bytesValue, offsetValue in
            let context = JSContext.current()!
            guard let bytes = Self.bytesFromValue(bytesValue, in: context) else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.protobuf.decodeVarint: expected Uint8Array/ArrayBuffer/string",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            let offset: Int
            if offsetValue.isUndefined || offsetValue.isNull {
                offset = 0
            } else if offsetValue.isNumber {
                offset = Int(offsetValue.toInt32())
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
        protobuf.setObject(protobufDecodeBlock, forKeyedSubscript: "decode" as NSString)
        protobuf.setObject(protobufEncodeBlock, forKeyedSubscript: "encode" as NSString)
        protobuf.setObject(protobufEncodeVarintBlock, forKeyedSubscript: "encodeVarint" as NSString)
        protobuf.setObject(protobufDecodeVarintBlock, forKeyedSubscript: "decodeVarint" as NSString)
        return protobuf
    }

    nonisolated private func makeCompressionCodec(named name: String, codec codecKind: MITMBodyCodec.Codec, in context: JSContext) -> JSValue {
        let object = JSValue(newObjectIn: context)!
        let encodeBlock: @convention(block) (JSValue) -> JSValue = { value in
            let context = JSContext.current()!
            guard let bytes = Self.bytesFromValue(value, in: context) else {
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
        let decodeBlock: @convention(block) (JSValue) -> JSValue = { value in
            let context = JSContext.current()!
            guard let bytes = Self.bytesFromValue(value, in: context) else {
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
        return object
    }

    nonisolated private func makeCryptoNamespace(in context: JSContext) -> JSValue {
        let crypto = JSValue(newObjectIn: context)!
        let md5Block: @convention(block) (JSValue) -> JSValue = { value in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(value, in: context) ?? Data()
            return Self.makeUint8Array(in: context, from: Data(Insecure.MD5.hash(data: bytes)))
        }
        let sha1Block: @convention(block) (JSValue) -> JSValue = { value in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(value, in: context) ?? Data()
            return Self.makeUint8Array(in: context, from: Data(Insecure.SHA1.hash(data: bytes)))
        }
        let sha256Block: @convention(block) (JSValue) -> JSValue = { value in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(value, in: context) ?? Data()
            return Self.makeUint8Array(in: context, from: Data(SHA256.hash(data: bytes)))
        }
        let sha384Block: @convention(block) (JSValue) -> JSValue = { value in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(value, in: context) ?? Data()
            return Self.makeUint8Array(in: context, from: Data(SHA384.hash(data: bytes)))
        }
        let sha512Block: @convention(block) (JSValue) -> JSValue = { value in
            let context = JSContext.current()!
            let bytes = Self.bytesFromValue(value, in: context) ?? Data()
            return Self.makeUint8Array(in: context, from: Data(SHA512.hash(data: bytes)))
        }
        let hmacSHA1Block: @convention(block) (JSValue, JSValue) -> JSValue = { keyValue, dataValue in
            let context = JSContext.current()!
            let key = Self.bytesFromValue(keyValue, in: context) ?? Data()
            let data = Self.bytesFromValue(dataValue, in: context) ?? Data()
            let mac = HMAC<Insecure.SHA1>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Self.makeUint8Array(in: context, from: Data(mac))
        }
        let hmacSHA256Block: @convention(block) (JSValue, JSValue) -> JSValue = { keyValue, dataValue in
            let context = JSContext.current()!
            let key = Self.bytesFromValue(keyValue, in: context) ?? Data()
            let data = Self.bytesFromValue(dataValue, in: context) ?? Data()
            let mac = HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Self.makeUint8Array(in: context, from: Data(mac))
        }
        let hmacSHA384Block: @convention(block) (JSValue, JSValue) -> JSValue = { keyValue, dataValue in
            let context = JSContext.current()!
            let key = Self.bytesFromValue(keyValue, in: context) ?? Data()
            let data = Self.bytesFromValue(dataValue, in: context) ?? Data()
            let mac = HMAC<SHA384>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Self.makeUint8Array(in: context, from: Data(mac))
        }
        let hmacSHA512Block: @convention(block) (JSValue, JSValue) -> JSValue = { keyValue, dataValue in
            let context = JSContext.current()!
            let key = Self.bytesFromValue(keyValue, in: context) ?? Data()
            let data = Self.bytesFromValue(dataValue, in: context) ?? Data()
            let mac = HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: key))
            return Self.makeUint8Array(in: context, from: Data(mac))
        }
        let randomBytesBlock: @convention(block) (JSValue) -> JSValue = { lengthValue in
            let context = JSContext.current()!
            let lengthDouble = lengthValue.toDouble()
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
            let nonceValue = spec.objectForKeyedSubscript("nonce")
            if let nonceValue, !nonceValue.isUndefined, !nonceValue.isNull {
                guard let nonceBytes = Self.bytesFromValue(nonceValue, in: context) else {
                    context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: nonce must be Uint8Array/ArrayBuffer/string", in: context)
                    return JSValue(undefinedIn: context)
                }
                guard nonceBytes.count == 12 else {
                    context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: nonce must be 12 bytes", in: context)
                    return JSValue(undefinedIn: context)
                }
                nonceData = nonceBytes
            } else {
                nonceData = nil
            }
            let aadData: Data?
            let aadValue = spec.objectForKeyedSubscript("aad")
            if let aadValue, !aadValue.isUndefined, !aadValue.isNull {
                guard let aadBytes = Self.bytesFromValue(aadValue, in: context) else {
                    context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.encrypt: aad must be Uint8Array/ArrayBuffer/string", in: context)
                    return JSValue(undefinedIn: context)
                }
                aadData = aadBytes
            } else {
                aadData = nil
            }
            do {
                let symmetricKey = SymmetricKey(data: key)
                let nonce: AES.GCM.Nonce
                if let nonceData {
                    nonce = try AES.GCM.Nonce(data: nonceData)
                } else {
                    nonce = AES.GCM.Nonce()
                }
                let box: AES.GCM.SealedBox
                if let aadData {
                    box = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce, authenticating: aadData)
                } else {
                    box = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce)
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
            let aadValue = spec.objectForKeyedSubscript("aad")
            if let aadValue, !aadValue.isUndefined, !aadValue.isNull {
                guard let aadBytes = Self.bytesFromValue(aadValue, in: context) else {
                    context.exception = JSValue(newErrorFromMessage: "Anywhere.crypto.aesGCM.decrypt: aad must be Uint8Array/ArrayBuffer/string", in: context)
                    return JSValue(undefinedIn: context)
                }
                aadData = aadBytes
            } else {
                aadData = nil
            }
            do {
                let symmetricKey = SymmetricKey(data: key)
                let gcmNonce = try AES.GCM.Nonce(data: nonce)
                let box = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
                let plaintext: Data
                if let aadData {
                    plaintext = try AES.GCM.open(box, using: symmetricKey, authenticating: aadData)
                } else {
                    plaintext = try AES.GCM.open(box, using: symmetricKey)
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
        return crypto
    }

    nonisolated private func makeJWTNamespace(in context: JSContext) -> JSValue {
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
                guard let signature = Self.decodeBase64URL(String(parts[2])) else {
                    context.exception = JSValue(newErrorFromMessage: "Anywhere.jwt.decode: signature is not valid base64url", in: context)
                    return JSValue(undefinedIn: context)
                }
                signatureBytes = signature
            } else {
                signatureBytes = Data()
            }
            guard let headerString = String(data: headerBytes, encoding: .utf8),
                  let headerObject = Self.parseJSON(headerString, in: context) else {
                context.exception = JSValue(newErrorFromMessage: "Anywhere.jwt.decode: header is not valid JSON", in: context)
                return JSValue(undefinedIn: context)
            }
            let payloadValue: JSValue
            if let payloadString = String(data: payloadBytes, encoding: .utf8),
               let parsed = Self.parseJSON(payloadString, in: context) {
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
            guard let headerSegment = Self.encodeJWTSegment(spec.objectForKeyedSubscript("header"), in: context) else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.jwt.encode: header must be an object, string, or Uint8Array",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            guard let payloadSegment = Self.encodeJWTSegment(spec.objectForKeyedSubscript("payload"), in: context) else {
                context.exception = JSValue(
                    newErrorFromMessage: "Anywhere.jwt.encode: payload must be an object, string, or Uint8Array",
                    in: context
                )
                return JSValue(undefinedIn: context)
            }
            let signatureSegment: String
            let signatureValue = spec.objectForKeyedSubscript("signature")
            if let signatureValue, !signatureValue.isUndefined, !signatureValue.isNull {
                guard let signatureBytes = Self.bytesFromValue(signatureValue, in: context) else {
                    context.exception = JSValue(
                        newErrorFromMessage: "Anywhere.jwt.encode: signature must be a Uint8Array (the raw signature bytes)",
                        in: context
                    )
                    return JSValue(undefinedIn: context)
                }
                signatureSegment = Self.encodeBase64URL(signatureBytes)
            } else {
                signatureSegment = ""
            }
            return JSValue(object: "\(headerSegment).\(payloadSegment).\(signatureSegment)", in: context)
        }
        jwt.setObject(jwtDecodeBlock, forKeyedSubscript: "decode" as NSString)
        jwt.setObject(jwtEncodeBlock, forKeyedSubscript: "encode" as NSString)
        return jwt
    }

    nonisolated private func makeJSONNamespace(in context: JSContext) -> JSValue {
        let json = JSValue(newObjectIn: context)!

        let addBlock: @convention(block) (JSValue, String, JSValue) -> JSValue = { body, path, value in
            let context = JSContext.current()!
            guard let resolvedValue = Self.jsonValue(from: value, in: context) else {
                logger.warning("[Script] Anywhere.json.add: Value is undefined")
                return Self.jsonPassthrough(body, in: context)
            }
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[Script] Anywhere.json.add: Invalid path: \(path)")
                return Self.jsonPassthrough(body, in: context)
            }
            return Self.runJSONOperation(body, in: context) { root in
                MITMJSONPatch.applyAtPath(&root, segments: segments, mode: .add, value: resolvedValue)
            }
        }

        let replaceBlock: @convention(block) (JSValue, String, JSValue) -> JSValue = { body, path, value in
            let context = JSContext.current()!
            guard let resolvedValue = Self.jsonValue(from: value, in: context) else {
                logger.warning("[Script] Anywhere.json.replace: Value is undefined")
                return Self.jsonPassthrough(body, in: context)
            }
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[Script] Anywhere.json.replace: Invalid path: \(path)")
                return Self.jsonPassthrough(body, in: context)
            }
            return Self.runJSONOperation(body, in: context) { root in
                MITMJSONPatch.applyAtPath(&root, segments: segments, mode: .replace, value: resolvedValue)
            }
        }

        let replaceRecursiveBlock: @convention(block) (JSValue, String, JSValue) -> JSValue = { body, key, value in
            let context = JSContext.current()!
            guard let resolvedValue = Self.jsonValue(from: value, in: context) else {
                logger.warning("[Script] Anywhere.json.replaceRecursive: Value is undefined")
                return Self.jsonPassthrough(body, in: context)
            }
            return Self.runJSONOperation(body, in: context) { root in
                MITMJSONPatch.replaceKeyRecursive(root, key: key, value: resolvedValue)
            }
        }

        let deleteBlock: @convention(block) (JSValue, String) -> JSValue = { body, path in
            let context = JSContext.current()!
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[Script] Anywhere.json.delete: Invalid path: \(path)")
                return Self.jsonPassthrough(body, in: context)
            }
            return Self.runJSONOperation(body, in: context) { root in
                MITMJSONPatch.applyAtPath(&root, segments: segments, mode: .delete, value: nil)
            }
        }

        let deleteRecursiveBlock: @convention(block) (JSValue, String) -> JSValue = { body, key in
            let context = JSContext.current()!
            return Self.runJSONOperation(body, in: context) { root in
                MITMJSONPatch.deleteKeyRecursive(root, key: key)
            }
        }

        let removeWhereKeyExistsBlock: @convention(block) (JSValue, String, String) -> JSValue = { body, path, key in
            let context = JSContext.current()!
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[Script] Anywhere.json.removeWhereKeyExists: Invalid path: \(path)")
                return Self.jsonPassthrough(body, in: context)
            }
            return Self.runJSONOperation(body, in: context) { root in
                MITMJSONPatch.removeWhereKeyExists(root, segments: segments, key: key)
            }
        }

        let removeWhereFieldInBlock: @convention(block) (JSValue, String, String, JSValue) -> JSValue = { body, path, field, valuesValue in
            let context = JSContext.current()!
            guard let segments = MITMJSONPatch.parseJSONPath(path) else {
                logger.warning("[Script] Anywhere.json.removeWhereFieldIn: Invalid path: \(path)")
                return Self.jsonPassthrough(body, in: context)
            }
            let matchValues = Self.jsonArrayValues(from: valuesValue, in: context)
            return Self.runJSONOperation(body, in: context) { root in
                MITMJSONPatch.removeWhereFieldIn(root, segments: segments, field: field, values: matchValues)
            }
        }

        json.setObject(addBlock, forKeyedSubscript: "add" as NSString)
        json.setObject(replaceBlock, forKeyedSubscript: "replace" as NSString)
        json.setObject(replaceRecursiveBlock, forKeyedSubscript: "replaceRecursive" as NSString)
        json.setObject(deleteBlock, forKeyedSubscript: "delete" as NSString)
        json.setObject(deleteRecursiveBlock, forKeyedSubscript: "deleteRecursive" as NSString)
        json.setObject(removeWhereKeyExistsBlock, forKeyedSubscript: "removeWhereKeyExists" as NSString)
        json.setObject(removeWhereFieldInBlock, forKeyedSubscript: "removeWhereFieldIn" as NSString)
        return json
    }

    // MARK: - Anywhere.json internals

    private static func runJSONOperation(_ body: JSValue, in context: JSContext, _ mutate: (inout Any) -> Bool) -> JSValue {
        let original = bytesFromValue(body, in: context) ?? Data()
        guard var root = MITMJSONPatch.parse(original), mutate(&root) else {
            return makeUint8Array(in: context, from: original)
        }
        guard let out = MITMJSONPatch.serialize(root) else {
            logger.warning("[Script] Anywhere.json: Result not serializable")
            return makeUint8Array(in: context, from: original)
        }
        return makeUint8Array(in: context, from: out)
    }

    private static func jsonPassthrough(_ body: JSValue, in context: JSContext) -> JSValue {
        makeUint8Array(in: context, from: bytesFromValue(body, in: context) ?? Data())
    }

    private static func jsonValue(from value: JSValue, in context: JSContext) -> Any? {
        if value.isUndefined { return nil }
        if value.isNull { return NSNull() }
        return value.toObject()
    }

    private static func jsonArrayValues(from value: JSValue, in context: JSContext) -> [Any] {
        if value.isUndefined || value.isNull { return [] }
        if value.isArray, let array = value.toArray() { return array }
        if let single = jsonValue(from: value, in: context) { return [single] }
        return []
    }

    nonisolated private func makeStoreNamespace(in context: JSContext, scope: UUID?) -> JSValue {
        let store = JSValue(newObjectIn: context)!
        let storeGet: @convention(block) (String, Bool) -> JSValue = { key, onDisk in
            let context = JSContext.current()!
            guard let scope,
                  let bytes = MITMScriptStore.shared.value(forKey: key, scope: scope, onDisk: onDisk)
            else { return JSValue(undefinedIn: context) }
            return Self.makeUint8Array(in: context, from: bytes)
        }
        let storeGetString: @convention(block) (String, Bool) -> JSValue = { key, onDisk in
            let context = JSContext.current()!
            guard let scope,
                  let bytes = MITMScriptStore.shared.value(forKey: key, scope: scope, onDisk: onDisk),
                  let string = String(data: bytes, encoding: .utf8)
            else { return JSValue(undefinedIn: context) }
            return JSValue(object: string, in: context)
        }
        let storeSet: @convention(block) (String, JSValue, Bool) -> Void = { key, value, onDisk in
            let context = JSContext.current()!
            guard let scope else { return }
            let bytes = Self.bytesFromValue(value, in: context) ?? Data()
            do {
                try MITMScriptStore.shared.setValue(bytes, forKey: key, scope: scope, onDisk: onDisk)
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
                let exception = JSValue(newErrorFromMessage: "Anywhere.store: \(error)", in: context)
                context.exception = exception
            }
        }
        let storeDelete: @convention(block) (String, Bool) -> Void = { key, onDisk in
            guard let scope else { return }
            MITMScriptStore.shared.removeValue(forKey: key, scope: scope, onDisk: onDisk)
        }
        let storeKeys: @convention(block) (Bool) -> [String] = { onDisk in
            guard let scope else { return [] }
            return MITMScriptStore.shared.keys(scope: scope, onDisk: onDisk)
        }
        store.setObject(storeGet, forKeyedSubscript: "get" as NSString)
        store.setObject(storeGetString, forKeyedSubscript: "getString" as NSString)
        store.setObject(storeSet, forKeyedSubscript: "set" as NSString)
        store.setObject(storeDelete, forKeyedSubscript: "delete" as NSString)
        store.setObject(storeKeys, forKeyedSubscript: "keys" as NSString)
        return store
    }

    nonisolated private func makeParamsNamespace(in context: JSContext, scope: UUID?) -> JSValue {
        let params = JSValue(newObjectIn: context)!
        let paramsGet: @convention(block) (String) -> JSValue = { key in
            let context = JSContext.current()!
            guard let scope,
                  let value = MITMParameterStore.shared.value(forKey: key, scope: scope)
            else { return JSValue(undefinedIn: context) }
            return JSValue(object: value, in: context)
        }
        let paramsKeys: @convention(block) () -> [String] = {
            guard let scope else { return [] }
            return MITMParameterStore.shared.keys(scope: scope)
        }
        let paramsAll: @convention(block) () -> [String: String] = {
            guard let scope else { return [:] }
            return MITMParameterStore.shared.values(scope: scope)
        }
        params.setObject(paramsGet, forKeyedSubscript: "get" as NSString)
        params.setObject(paramsKeys, forKeyedSubscript: "keys" as NSString)
        params.setObject(paramsAll, forKeyedSubscript: "all" as NSString)
        return params
    }

    nonisolated private func makeLogNamespace(in context: JSContext, for run: ScriptRun) -> JSValue {
        let log = JSValue(newObjectIn: context)!
        let prefix = run.logPrefix
        let logInfo: @convention(block) (String) -> Void = { message in
            logger.info("\(prefix): \(message)")
        }
        let logWarning: @convention(block) (String) -> Void = { message in
            logger.warning("\(prefix): \(message)")
        }
        let logError: @convention(block) (String) -> Void = { message in
            logger.error("\(prefix): \(message)")
        }
        let logDebug: @convention(block) (String) -> Void = { message in
            logger.debug("\(prefix): \(message)")
        }
        log.setObject(logInfo, forKeyedSubscript: "info" as NSString)
        log.setObject(logWarning, forKeyedSubscript: "warning" as NSString)
        log.setObject(logError, forKeyedSubscript: "error" as NSString)
        log.setObject(logDebug, forKeyedSubscript: "debug" as NSString)
        return log
    }

    private static func synthesizedResponse(from spec: JSValue) -> SynthesizedResponse {
        guard !spec.isUndefined, !spec.isNull else {
            return SynthesizedResponse(status: 200, headers: [], body: Data())
        }
        let status: Int
        if let statusValue = spec.objectForKeyedSubscript("status"),
           statusValue.isNumber {
            let statusDouble = statusValue.toDouble()
            let raw = Int(exactly: statusDouble) ?? -1
            if (100...599).contains(raw) {
                status = raw
            } else {
                logger.warning("[Script] Anywhere.respond: Invalid status: \(statusDouble)")
                status = 200
            }
        } else {
            status = 200
        }
        var headers: [(name: String, value: String)] = []
        if let headersValue = spec.objectForKeyedSubscript("headers"),
           !headersValue.isUndefined, !headersValue.isNull,
           let parsed = Self.headersFromValue(headersValue) {
            headers = parsed
        }
        let body: Data
        if let bodyValue = spec.objectForKeyedSubscript("body"),
           !bodyValue.isUndefined, !bodyValue.isNull {
            let context = JSContext.current()!
            body = Self.bytesFromValue(bodyValue, in: context) ?? Data()
        } else {
            body = Data()
        }
        return SynthesizedResponse(status: status, headers: headers, body: body)
    }

    // MARK: - Anywhere.http

    nonisolated private func makeHTTPNamespace(in context: JSContext, for run: ScriptRun) -> JSValue {
        let http = JSValue(newObjectIn: context)!
        let getBlock: @convention(block) (JSValue, JSValue) -> JSValue = { [weak self, weak run] urlValue, optionsValue in
            let context = JSContext.current()!
            guard let self, let run else { return Self.rejected("Anywhere.http: invocation released", in: context) }
            return self.assumeIsolated { $0.startHTTP(run: run, defaultMethod: "GET", urlValue: urlValue, optionsValue: optionsValue) }
        }
        let postBlock: @convention(block) (JSValue, JSValue) -> JSValue = { [weak self, weak run] urlValue, optionsValue in
            let context = JSContext.current()!
            guard let self, let run else { return Self.rejected("Anywhere.http: invocation released", in: context) }
            return self.assumeIsolated { $0.startHTTP(run: run, defaultMethod: "POST", urlValue: urlValue, optionsValue: optionsValue) }
        }
        let requestBlock: @convention(block) (JSValue) -> JSValue = { [weak self, weak run] specValue in
            let context = JSContext.current()!
            guard let self, let run else { return Self.rejected("Anywhere.http: invocation released", in: context) }
            let urlValue: JSValue = specValue.objectForKeyedSubscript("url") ?? JSValue(undefinedIn: context)
            return self.assumeIsolated { $0.startHTTP(run: run, defaultMethod: "GET", urlValue: urlValue, optionsValue: specValue) }
        }
        http.setObject(getBlock, forKeyedSubscript: "get" as NSString)
        http.setObject(postBlock, forKeyedSubscript: "post" as NSString)
        http.setObject(requestBlock, forKeyedSubscript: "request" as NSString)
        return http
    }

    private func startHTTP(run: ScriptRun, defaultMethod: String, urlValue: JSValue, optionsValue: JSValue) -> JSValue {
        let context = run.context
        guard run.allowsHTTP else {
            return Self.rejected(
                "Anywhere.http is only available inside a buffered `script` rule — an `async function process(ctx)` that awaits it. It is unavailable in stream-script.",
                in: context
            )
        }
        guard !urlValue.isUndefined, !urlValue.isNull,
              let urlString = urlValue.toString(),
              let url = URL(string: urlString),
              let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = url.host, !host.isEmpty
        else {
            return Self.rejected("Anywhere.http: expected an absolute http(s) URL", in: context)
        }
        if run.totalFetches >= Self.httpMaxTotalPerInvocation {
            return Self.rejected("Anywhere.http: per-invocation request cap (\(Self.httpMaxTotalPerInvocation)) reached", in: context)
        }
        if run.inFlightFetches >= Self.httpMaxConcurrentPerInvocation {
            return Self.rejected("Anywhere.http: too many concurrent requests in this invocation (max \(Self.httpMaxConcurrentPerInvocation))", in: context)
        }
        if Self.globalFetchCount() >= Self.httpMaxConcurrentGlobal {
            return Self.rejected("Anywhere.http: global concurrent request cap (\(Self.httpMaxConcurrentGlobal)) reached", in: context)
        }

        let options: JSValue? = optionsValue.isObject ? optionsValue : nil
        var request = URLRequest(url: url)
        let method = (options?.objectForKeyedSubscript("method"))
            .flatMap { $0.isString ? $0.toString() : nil }?
            .uppercased() ?? defaultMethod
        guard HTTPHeader.isValidName(method) else {
            return Self.rejected("Anywhere.http: invalid method token", in: context)
        }
        request.httpMethod = method
        if let headersValue = options?.objectForKeyedSubscript("headers"), !headersValue.isUndefined, !headersValue.isNull {
            for header in Self.requestHeadersFromValue(headersValue, in: context) {
                request.addValue(header.value, forHTTPHeaderField: header.name)
            }
        }
        if let bodyValue = options?.objectForKeyedSubscript("body"), !bodyValue.isUndefined, !bodyValue.isNull {
            request.httpBody = Self.bytesFromValue(bodyValue, in: context) ?? Data()
        }
        var timeout = Self.httpDefaultTimeout
        if let timeoutValue = options?.objectForKeyedSubscript("timeout"), timeoutValue.isNumber {
            let timeoutMilliseconds = timeoutValue.toDouble()
            if timeoutMilliseconds.isFinite, timeoutMilliseconds > 0 { timeout = min(timeoutMilliseconds / 1000.0, Self.httpMaxTimeout) }
        }
        request.timeoutInterval = timeout
        let followRedirects = (options?.objectForKeyedSubscript("redirect"))
            .flatMap { $0.isString ? $0.toString() : nil } != "manual"
        let insecure: Bool
        if let insecureValue = options?.objectForKeyedSubscript("insecure"), insecureValue.isBoolean {
            insecure = insecureValue.toBool()
        } else {
            insecure = AWCore.getAllowInsecure()
        }

        let maxBytes = Self.httpMaxResponseBytes

        let promise = JSValue(newPromiseIn: context, fromExecutor: { [weak self, weak run] resolve, reject in
            guard let self, let run else {
                reject?.call(withArguments: [Self.error("Anywhere.http: invocation released", in: context)])
                return
            }
            self.assumeIsolated { engine in
                run.inFlightFetches += 1
                run.totalFetches += 1
                Self.reserveGlobalFetchSlot()
                let runID = run.id
                let fetchID = run.claimFetchID()
                let task = Task { [request] in
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
                    engine.completeFetch(runID: runID, fetchID: fetchID, result: result)
                }
                run.pendingFetches[fetchID] = PendingFetch(resolve: resolve, reject: reject, task: task)
            }
        })
        return promise ?? Self.rejected("Anywhere.http: could not create Promise", in: context)
    }

    private func completeFetch(
        runID: UInt64,
        fetchID: Int,
        result: Result<MITMScriptHTTPClient.Response, Error>
    ) {
        Self.releaseGlobalFetchSlot()
        guard let run = liveRuns[runID],
              let pending = run.pendingFetches.removeValue(forKey: fetchID) else { return }
        resumeFetch(run: run, resolve: pending.resolve, reject: pending.reject, result: result)
    }

    private func resumeFetch(
        run: ScriptRun,
        resolve: JSValue?,
        reject: JSValue?,
        result: Result<MITMScriptHTTPClient.Response, Error>
    ) {
        if run.inFlightFetches > 0 { run.inFlightFetches -= 1 }
        guard !run.isDelivered else { return }
        if MonotonicClock.now - run.startedAt > Self.invocationAbsoluteTimeout,
           let original = run.original {
            logger.warning("\(run.logPrefix): process(ctx) timed out")
            deliver(.modified(original), for: run)
            return
        }
        armWatchdog(for: run)
        let context = run.context
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

    private static func error(_ message: String, in context: JSContext) -> JSValue {
        JSValue(newErrorFromMessage: message, in: context) ?? JSValue(newObjectIn: context)!
    }

    private static func rejected(_ message: String, in context: JSContext) -> JSValue {
        JSValue(newPromiseRejectedWithReason: error(message, in: context) as Any, in: context) ?? JSValue(undefinedIn: context)
    }

    private static func makeHTTPResponse(_ response: MITMScriptHTTPClient.Response, in context: JSContext) -> JSValue {
        let object = JSValue(newObjectIn: context)!
        object.setObject(response.status, forKeyedSubscript: "status" as NSString)
        let pairs: [[String]] = response.headers.map { [$0.name, $0.value] }
        object.setObject(pairs, forKeyedSubscript: "headers" as NSString)
        object.setObject(makeUint8Array(in: context, from: response.body), forKeyedSubscript: "body" as NSString)
        object.setObject(response.finalURL as Any, forKeyedSubscript: "url" as NSString)
        return object
    }

    private static func requestHeadersFromValue(_ value: JSValue, in context: JSContext) -> [(name: String, value: String)] {
        if value.isArray {
            return (headersFromValue(value) ?? []).filter { entry in
                guard !Self.forbiddenRequestHeaders.contains(entry.name.lowercased()) else {
                    logger.warning("[Script] Anywhere.http: Forbidden header: \(entry.name)")
                    return false
                }
                return true
            }
        }
        guard value.isObject,
              let keys = context.objectForKeyedSubscript("Object")?.invokeMethod("keys", withArguments: [value]),
              keys.isArray
        else { return [] }
        guard let length = Self.validatedArrayLength(keys, maxLength: 100_000) else { return [] }
        var out: [(name: String, value: String)] = []
        out.reserveCapacity(length)
        for index in 0..<length {
            guard let keyValue = keys.objectAtIndexedSubscript(index), let name = keyValue.toString(),
                  let valueElement = value.objectForKeyedSubscript(name), !valueElement.isUndefined, !valueElement.isNull,
                  let value = valueElement.toString()
            else { continue }
            guard HTTPHeader.isValidName(name) else {
                logger.warning("[Script] Anywhere.http: Invalid header name: \(name)")
                continue
            }
            guard HTTPHeader.isValidValue(value) else {
                logger.warning("[Script] Anywhere.http: Invalid header value: \(name)")
                continue
            }
            guard !Self.forbiddenRequestHeaders.contains(name.lowercased()) else {
                logger.warning("[Script] Anywhere.http: Forbidden header: \(name)")
                continue
            }
            out.append((name: name, value: value))
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
        let contextRef = context.jsGlobalContextRef
        var exception: JSValueRef?
        guard let object = JSObjectMakeTypedArray(contextRef, kJSTypedArrayTypeUint8Array, count, &exception),
              exception == nil else {
            return JSValue(undefinedIn: context)
        }
        if count > 0 {
            guard let pointer = JSObjectGetTypedArrayBytesPtr(contextRef, object, &exception), exception == nil else {
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
        let contextRef = context.jsGlobalContextRef
        guard let ref = value.jsValueRef else { return nil }
        var exception: JSValueRef?
        let kind = JSValueGetTypedArrayType(contextRef, ref, &exception)
        if exception != nil { return nil }
        if kind == kJSTypedArrayTypeNone { return nil }
        guard let object = JSValueToObject(contextRef, ref, &exception), exception == nil else {
            return nil
        }
        if kind == kJSTypedArrayTypeArrayBuffer {
            let length = JSObjectGetArrayBufferByteLength(contextRef, object, &exception)
            guard exception == nil,
                  let pointer = JSObjectGetArrayBufferBytesPtr(contextRef, object, &exception),
                  exception == nil
            else { return nil }
            return Data(bytes: pointer, count: length)
        }
        let length = JSObjectGetTypedArrayByteLength(contextRef, object, &exception)
        guard exception == nil else { return nil }
        let offset = JSObjectGetTypedArrayByteOffset(contextRef, object, &exception)
        guard exception == nil,
              let pointer = JSObjectGetTypedArrayBytesPtr(contextRef, object, &exception),
              exception == nil
        else { return nil }
        return Data(bytes: pointer + offset, count: length)
    }

    private static func decodeHex(_ string: String) -> Data {
        var out = Data()
        var iterator = string.unicodeScalars.makeIterator()
        while let highScalar = iterator.next() {
            guard let lowScalar = iterator.next() else {
                logger.warning("[Script] Anywhere.hex.decode: Odd-length input")
                return Data()
            }
            guard let high = hexNibble(highScalar), let low = hexNibble(lowScalar) else {
                logger.warning("[Script] Anywhere.hex.decode: Invalid hex character")
                return Data()
            }
            out.append((high << 4) | low)
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

    private enum ProtobufFieldValue {
        case varint(UInt64)
        case bytes(Data)
    }

    private struct ProtobufEntry {
        let field: UInt32
        let wire: UInt8
        let value: ProtobufFieldValue
    }

    private static func readVarint(_ data: Data, from offset: Int) -> (UInt64, Int)? {
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

    private static func writeVarint(_ value: UInt64) -> Data {
        var remaining = value
        var out = Data()
        out.reserveCapacity(10)
        while true {
            if remaining < 0x80 {
                out.append(UInt8(remaining))
                return out
            }
            out.append(UInt8((remaining & 0x7F) | 0x80))
            remaining >>= 7
        }
    }

    private static func protobufDecodeWire(_ data: Data) throws -> [ProtobufEntry] {
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
            guard fieldRaw > 0, fieldRaw <= 536870911 else {
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "invalid field number \(fieldRaw)"))
            }
            let field = UInt32(fieldRaw)
            switch wire {
            case 0:
                guard let (varint, nextIndex) = readVarint(data, from: index) else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "truncated varint for field \(field)"))
                }
                index = nextIndex
                entries.append(ProtobufEntry(field: field, wire: 0, value: .varint(varint)))
            case 1:
                guard index + 8 <= end else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "truncated fixed64 for field \(field)"))
                }
                entries.append(ProtobufEntry(field: field, wire: 1, value: .bytes(data.subdata(in: index..<index + 8))))
                index += 8
            case 2:
                guard let (length, nextIndex) = readVarint(data, from: index) else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "truncated length for field \(field)"))
                }
                index = nextIndex
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

    private static func protobufEncodeWire(_ entries: [ProtobufEntry]) -> Data {
        var out = Data()
        for entry in entries {
            let tag = UInt64(entry.field) << 3 | UInt64(entry.wire)
            out.append(writeVarint(tag))
            switch entry.value {
            case .varint(let varint):
                out.append(writeVarint(varint))
            case .bytes(let bytes):
                if entry.wire == 2 {
                    out.append(writeVarint(UInt64(bytes.count)))
                }
                out.append(bytes)
            }
        }
        return out
    }

    private static func parseProtobufEntries(_ value: JSValue, in context: JSContext) throws -> [ProtobufEntry] {
        guard value.isArray else {
            throw AnywhereError.mitm(.scriptMessageMalformed(detail: "expected an array of {field, wire, value} entries"))
        }
        guard let count = Self.validatedArrayLength(value, maxLength: 10_000_000) else {
            throw AnywhereError.mitm(.scriptMessageMalformed(detail: "input array length is missing, negative, or too large"))
        }
        var entries: [ProtobufEntry] = []
        entries.reserveCapacity(count)
        for index in 0..<count {
            guard let entryValue = value.objectAtIndexedSubscript(index),
                  !entryValue.isUndefined, !entryValue.isNull else {
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index) is null/undefined"))
            }
            let fieldValue = entryValue.objectForKeyedSubscript("field")
            guard let fieldValue, fieldValue.isNumber else {
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).field must be a Number"))
            }
            let fieldNumber = fieldValue.toInt32()
            guard fieldNumber > 0, fieldNumber <= 536_870_911 else {
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).field \(fieldNumber) out of range (1…2^29-1)"))
            }
            let wireValue = entryValue.objectForKeyedSubscript("wire")
            guard let wireValue, wireValue.isNumber else {
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).wire must be a Number"))
            }
            let wireType = UInt8(truncatingIfNeeded: wireValue.toInt32())
            let valueField = entryValue.objectForKeyedSubscript("value")
            switch wireType {
            case 0:
                guard let varint = valueField.flatMap({ uint64FromJSValue($0) }) else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).value (wire 0) must be a non-negative integer Number or BigInt"))
                }
                entries.append(ProtobufEntry(field: UInt32(fieldNumber), wire: 0, value: .varint(varint)))
            case 1:
                guard let bytes = valueField.flatMap({ bytesFromValue($0, in: context) }), bytes.count == 8 else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).value (wire 1) must be a Uint8Array of length 8"))
                }
                entries.append(ProtobufEntry(field: UInt32(fieldNumber), wire: 1, value: .bytes(bytes)))
            case 2:
                guard let bytes = valueField.flatMap({ bytesFromValue($0, in: context) }) else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).value (wire 2) must be Uint8Array/ArrayBuffer/string"))
                }
                entries.append(ProtobufEntry(field: UInt32(fieldNumber), wire: 2, value: .bytes(bytes)))
            case 5:
                guard let bytes = valueField.flatMap({ bytesFromValue($0, in: context) }), bytes.count == 4 else {
                    throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).value (wire 5) must be a Uint8Array of length 4"))
                }
                entries.append(ProtobufEntry(field: UInt32(fieldNumber), wire: 5, value: .bytes(bytes)))
            case 3, 4:
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).wire = \(wireType): deprecated group wire types not supported"))
            default:
                throw AnywhereError.mitm(.scriptMessageMalformed(detail: "entry \(index).wire = \(wireType): unknown wire type"))
            }
        }
        return entries
    }

    private static func makeProtobufEntries(_ entries: [ProtobufEntry], in context: JSContext) -> JSValue {
        let array = JSValue(newArrayIn: context)!
        let bigIntFunction = context.objectForKeyedSubscript("BigInt")
        for (index, entry) in entries.enumerated() {
            let object = JSValue(newObjectIn: context)!
            object.setObject(NSNumber(value: entry.field), forKeyedSubscript: "field" as NSString)
            object.setObject(NSNumber(value: entry.wire), forKeyedSubscript: "wire" as NSString)
            let jsValue: JSValue
            switch entry.value {
            case .varint(let varint):
                jsValue = bigIntFunction?.call(withArguments: [String(varint)]) ?? JSValue(undefinedIn: context)
            case .bytes(let bytes):
                jsValue = makeUint8Array(in: context, from: bytes)
            }
            object.setObject(jsValue, forKeyedSubscript: "value" as NSString)
            array.setObject(object, atIndexedSubscript: index)
        }
        return array
    }

    private static func makeBigInt(_ value: UInt64, in context: JSContext) -> JSValue {
        let bigIntFunction = context.objectForKeyedSubscript("BigInt")
        return bigIntFunction?.call(withArguments: [String(value)]) ?? JSValue(undefinedIn: context)
    }

    private static func uint64FromJSValue(_ value: JSValue) -> UInt64? {
        if value.isUndefined || value.isNull { return nil }
        if value.isNumber {
            let double = value.toDouble()
            guard double.isFinite, double >= 0, double <= 9_007_199_254_740_991.0, double == double.rounded() else {
                return nil
            }
            return UInt64(double)
        }
        guard let string = value.toString() else { return nil }
        return UInt64(string)
    }

    // MARK: - Base64URL / JWT helpers

    private static func encodeBase64URL(_ data: Data) -> String {
        var normalized = data.base64EncodedString()
        normalized = normalized.replacingOccurrences(of: "+", with: "-")
        normalized = normalized.replacingOccurrences(of: "/", with: "_")
        normalized = normalized.replacingOccurrences(of: "=", with: "")
        return normalized
    }

    private static func decodeBase64URL(_ string: String) -> Data? {
        var normalized = string.replacingOccurrences(of: "-", with: "+")
        normalized = normalized.replacingOccurrences(of: "_", with: "/")
        normalized = normalized.filter { !$0.isWhitespace }
        let remainder = normalized.count % 4
        if remainder > 0 {
            normalized += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: normalized)
    }

    private static func parseJSON(_ string: String, in context: JSContext) -> JSValue? {
        let json = context.objectForKeyedSubscript("JSON")
        let result = json?.invokeMethod("parse", withArguments: [string])
        if context.exception != nil {
            context.exception = nil
            return nil
        }
        return result
    }

    private static func encodeJWTSegment(_ value: JSValue?, in context: JSContext) -> String? {
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
    static let shared = MITMScriptEngine()

    static func setRuleSetNames(_ names: [UUID: String]) {
        mitmScriptRuleSetNames.withLock { $0 = names }
    }

    static func purgeRuns(activeIDs: Set<UUID>) {
        JSCConcurrencyBridge.shared.enqueue {
            shared.assumeIsolated { $0.dropRuns(notIn: activeIDs) }
        }
    }
}
