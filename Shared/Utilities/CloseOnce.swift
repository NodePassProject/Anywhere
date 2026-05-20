//
//  CloseOnce.swift
//  Anywhere
//
//  Created by NodePassProject on 5/20/26.
//

import Foundation

/// Runs a resource's teardown exactly once, on its owning queue, keeping the
/// teardown closure's captures alive until it completes.
///
/// The leak this guards against: a `close()`/`cancel()` that dispatches
/// teardown with `[weak self]` can hold the owner's *last* reference — if the
/// owner deallocates before the queued block runs, `guard let self else
/// { return }` silently skips teardown and leaks the FD + its kernel buffers,
/// the dispatch sources, and any C-level connection state (e.g. an ngtcp2
/// conn). Only the one-shot terminal teardown needs this; operational,
/// repeating handlers (a read source's event handler, a retransmit timer)
/// should still capture `[weak self]` so libdispatch can't keep a live socket
/// pinned by an idle connection.
///
/// `fire` enforces the correct shape: teardown runs once, on `queue`, retained
/// until it returns. Write its closure with a **strong** `self` capture.
/// Pair every adopter with a DEBUG tripwire that turns a silent production
/// leak into a loud test-time failure the instant an owner is dropped without
/// being closed — keyed on the resource invariant, e.g.:
///
/// ```swift
/// #if DEBUG
/// deinit { assert(socketFD < 0 && readSource == nil, "\(Self.self) leaked: freed without close()") }
/// #endif
/// ```
final class CloseOnce {
    private let lock = UnfairLock()
    private var fired = false

    /// Latches closed and reports whether THIS call won the race and so owns
    /// running teardown. Idempotent — only the first caller gets `true`. Use
    /// directly when teardown can't be one closure (e.g. a fan-out that closes
    /// the FD from dispatch-source cancel handlers); otherwise use ``fire``.
    @discardableResult
    func begin() -> Bool {
        lock.withLock {
            if fired { return false }
            fired = true
            return true
        }
    }

    /// `true` once teardown has been initiated. Read from a DEBUG `deinit`
    /// tripwire to assert the owner was closed before being freed.
    var isClosed: Bool { lock.withLock { fired } }

    /// Runs `teardown` exactly once. When `runningOnQueue` is true the caller
    /// is already on `queue`, so teardown runs synchronously (preserving
    /// on-queue ordering); otherwise it is dispatched to `queue`. `teardown`
    /// is retained until it runs — capture `self` **strongly** inside it so
    /// the resource can't be freed mid-teardown.
    func fire(on queue: DispatchQueue, runningOnQueue: Bool, _ teardown: @escaping () -> Void) {
        guard begin() else { return }
        if runningOnQueue {
            teardown()
        } else {
            queue.async(execute: teardown)
        }
    }
}
