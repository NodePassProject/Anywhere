//
//  H2FlowGate.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation

nonisolated struct H2FlowGate {

    /// One finishing `AsyncStream<Never>` per parked sender: finishing it is the wakeup.
    private var waiters: [AsyncStream<Never>.Continuation] = []

    /// Enrolls a waiter and returns the stream to suspend on. Call **under the owner's lock**, only
    /// once the window check has decided to park.
    mutating func enroll() -> AsyncStream<Never> {
        let (stream, continuation) = AsyncStream.makeStream(of: Never.self)
        waiters.append(continuation)
        return stream
    }

    /// Wakes every parked sender. Call **under the owner's lock** — finishing an `AsyncStream`
    /// continuation only marks the stream done; the suspended `park` resumes on its own executor.
    mutating func wakeAll() {
        for continuation in waiters { continuation.finish() }
        waiters.removeAll()
    }

    /// Suspends until woken, unless `enrollUnderLock` reports the window is already open (or the
    /// session is closed) by returning `nil`. `enrollUnderLock` runs the window check and, to park,
    /// calls ``enroll`` and returns its stream — all inside the owner's lock, so the decision and the
    /// enrollment are atomic.
    static func park(_ enrollUnderLock: () -> AsyncStream<Never>?) async {
        guard let stream = enrollUnderLock() else { return }
        for await _ in stream {}
    }
}
