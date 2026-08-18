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
    static let shared = JSCConcurrencyBridge()
    
    let executor: BridgeExecutor

    private init() {
        self.executor = BridgeExecutor(label: "com.argsment.Anywhere.JSCConcurrencyBridge")
    }
    
    private var queue: DispatchQueue { executor.queue }
    
    func enqueue(_ work: @escaping @convention(block) @Sendable () -> Void) {
        queue.async { autoreleasepool { work() } }
    }
    
    var isOnQueue: Bool { executor.isOnQueue }

    // MARK: - Async hops
    
    private struct QueueHopBody<Body>: @unchecked Sendable { let body: Body }
    
    func run<T>(_ body: @escaping () -> T) async -> T {
        let hop = QueueHopBody(body: body)
        return await withCheckedContinuation { (continuation: CheckedContinuation<T, Never>) in
            queue.async {
                let value = autoreleasepool { hop.body() }
                continuation.resume(returning: value)
            }
        }
    }
    
    func runParked<T>(_ body: @escaping (CheckedContinuation<T, Never>) -> Void) async -> T {
        let hop = QueueHopBody(body: body)
        return await withCheckedContinuation { (continuation: CheckedContinuation<T, Never>) in
            queue.async { autoreleasepool { hop.body(continuation) } }
        }
    }
}
