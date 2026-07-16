//
//  BridgeContext.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

// IMPORTANT: BridgeContext is allowed to use in *ConcurrencyBridge only
nonisolated enum BridgeContext {

    /// Hands the C side a **retained** pointer to `object` (one owning reference now lives
    /// in the C data structure). Balance it exactly once, later, with either ``consume``
    /// (from the terminal C callback) or ``release`` (from Swift-driven teardown).
    static func passRetained<T: AnyObject>(_ object: T) -> UnsafeMutableRawPointer {
        Unmanaged.passRetained(object).toOpaque()
    }

    /// Hands the C side an **unretained** pointer to `object` — no ownership transfer,
    /// for a back-reference whose Swift owner outlives the C entity and drives its
    /// teardown itself (ngtcp2's `conn_ref.user_data`, where `QUICConnection` calls
    /// `ngtcp2_conn_del`). Nothing to balance.
    static func passUnretained<T: AnyObject>(_ object: T) -> UnsafeMutableRawPointer {
        Unmanaged.passUnretained(object).toOpaque()
    }

    /// Recovers `object` from a context pointer **without** changing its reference count —
    /// for the ordinary callbacks (recv, sent, credit) that don't end the object's life.
    static func unretained<T: AnyObject>(_ pointer: UnsafeMutableRawPointer,
                                         as _: T.Type = T.self) -> T {
        Unmanaged<T>.fromOpaque(pointer).takeUnretainedValue()
    }

    /// Recovers `object` **and consumes** the C side's retained reference — for the single
    /// terminal callback after which the C library will never hand the pointer back (lwIP
    /// `tcp_err`, where the PCB is already freed).
    static func consume<T: AnyObject>(_ pointer: UnsafeMutableRawPointer,
                                      as _: T.Type = T.self) -> T {
        Unmanaged<T>.fromOpaque(pointer).takeRetainedValue()
    }

    /// Balances a ``passRetained`` reference when teardown is driven from Swift and the C
    /// side is told to drop the entity (lwIP `tcp_close` / `tcp_abort`), so no terminal
    /// callback will fire to ``consume`` it. Call once, paired with the original
    /// ``passRetained``.
    static func release<T: AnyObject>(_ object: T) {
        Unmanaged.passUnretained(object).release()
    }
}
