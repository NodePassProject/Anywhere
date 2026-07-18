//
//  JSCConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/16/26.
//

import Foundation
import JavaScriptCore

extension JSVirtualMachine: @unchecked @retroactive Sendable { }
extension JSContext: @unchecked @retroactive Sendable { }
extension JSValue: @unchecked @retroactive Sendable { }

nonisolated final class JSCConcurrencyBridge: @unchecked Sendable {

    /// Shared home for all JavaScriptCore work in the extension.
    static let shared = JSCConcurrencyBridge()

    /// The serial executor every script invocation runs on. A ``BridgeExecutor`` (not a bare
    /// `DispatchQueue`) so a future script-engine actor can adopt it as its `unownedExecutor`,
    /// exactly as `TCPConnection` adopts the lwIP bridge's executor.
    let executor: BridgeExecutor

    private init() {
        self.executor = BridgeExecutor(label: "com.argsment.Anywhere.JSCConcurrencyBridge")
    }

    /// The JSC serial (home) queue — bridge-internal; callers enter the domain via ``enqueue``/``run``.
    private var queue: DispatchQueue { executor.queue }

    /// Fire-and-forget hop onto the JSC queue with a `Sendable`-checked closure — the sanctioned way
    /// to enter the isolation domain instead of reaching for `queue.async` directly.
    func enqueue(_ work: @escaping @convention(block) @Sendable () -> Void) {
        queue.async(execute: work)
    }

    /// True when the caller already runs on the JSC queue.
    var isOnQueue: Bool { executor.isOnQueue }

    // MARK: - Async hops

    /// One-shot hop: runs `body` on the JSC queue and resumes the caller with its result — the
    /// async seam between the pure-async pipeline and JSC's thread-affine, queue-confined state.
    func run<T>(_ body: @escaping () -> T) async -> T {
        await withCheckedContinuation { (continuation: CheckedContinuation<T, Never>) in
            queue.async { continuation.resume(returning: body()) }
        }
    }

    /// Parked hop: runs `body` on the JSC queue, handing it the `continuation` to resolve later —
    /// e.g. when a JS promise settles or the invocation's watchdog fires. Resumed exactly once.
    func runParked<T>(_ body: @escaping (CheckedContinuation<T, Never>) -> Void) async -> T {
        await withCheckedContinuation { (continuation: CheckedContinuation<T, Never>) in
            queue.async { body(continuation) }
        }
    }
}
