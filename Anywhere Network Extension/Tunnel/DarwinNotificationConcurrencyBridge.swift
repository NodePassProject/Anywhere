//
//  DarwinNotificationConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation

nonisolated enum DarwinNotificationConcurrencyBridge {

    /// One retained box per stream, handed to `CFNotificationCenter` as the observer context and
    /// recovered in the C callback (which cannot capture). Holds the continuation the callback
    /// yields each posted name to; balanced by the `onTermination` release.
    private final class Observation: Sendable {
        let continuation: AsyncStream<String>.Continuation
        init(_ continuation: AsyncStream<String>.Continuation) { self.continuation = continuation }
    }

    /// Streams the raw names of Darwin notifications posted to the Darwin notify center for any of
    /// `names`, in delivery order. Registration is `.deliverImmediately`, matching the former direct
    /// `CFNotificationCenterAddObserver` observers.
    static func names(_ names: [CFString]) -> AsyncStream<String> {
        AsyncStream(String.self, bufferingPolicy: .unbounded) { continuation in
            let observation = Observation(continuation)
            let context = BridgeContext.passRetained(observation)
            let center = CFNotificationCenterGetDarwinNotifyCenter()

            let callback: CFNotificationCallback = { _, observer, name, _, _ in
                guard let observer, let name else { return }
                let observation = BridgeContext.unretained(observer, as: Observation.self)
                observation.continuation.yield(name.rawValue as String)
            }

            for name in names {
                CFNotificationCenterAddObserver(center, context, callback, name, nil, .deliverImmediately)
            }

            // Capture the `Sendable` box (not the raw pointer): it keeps the observation alive across
            // teardown, re-derives the same context pointer to unregister, then balances the retain.
            continuation.onTermination = { [observation] _ in
                CFNotificationCenterRemoveEveryObserver(
                    CFNotificationCenterGetDarwinNotifyCenter(),
                    BridgeContext.passUnretained(observation)
                )
                BridgeContext.release(observation)
            }
        }
    }
}
