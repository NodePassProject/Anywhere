//
//  UnfairLock.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// A fast, unfair lock wrapper around os_unfair_lock.
/// Prefer this over NSLock for short critical sections.
final class UnfairLock {
    private var _lock = os_unfair_lock()

    @inline(__always)
    func lock() {
        os_unfair_lock_lock(&_lock)
    }

    @inline(__always)
    func unlock() {
        os_unfair_lock_unlock(&_lock)
    }

    @inline(__always)
    func withLock<T>(_ body: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try body()
    }
}

/// A read-write lock that allows multiple concurrent readers or one exclusive writer.
/// Uses pthread_rwlock for efficient reader-writer synchronization.
/// Ideal for data structures with frequent reads and infrequent writes.
final class ReadWriteLock {
    private var _lock = pthread_rwlock_t()

    init() {
        pthread_rwlock_init(&_lock, nil)
    }

    deinit {
        pthread_rwlock_destroy(&_lock)
    }

    /// Acquire read lock (shared - multiple readers allowed)
    @inline(__always)
    func readLock() {
        pthread_rwlock_rdlock(&_lock)
    }

    /// Release read lock
    @inline(__always)
    func readUnlock() {
        pthread_rwlock_unlock(&_lock)
    }

    /// Acquire write lock (exclusive - blocks all other access)
    @inline(__always)
    func writeLock() {
        pthread_rwlock_wrlock(&_lock)
    }

    /// Release write lock
    @inline(__always)
    func writeUnlock() {
        pthread_rwlock_unlock(&_lock)
    }

    /// Execute a read operation with automatic lock management
    @inline(__always)
    func withReadLock<T>(_ body: () throws -> T) rethrows -> T {
        readLock()
        defer { readUnlock() }
        return try body()
    }

    /// Execute a write operation with automatic lock management
    @inline(__always)
    func withWriteLock<T>(_ body: () throws -> T) rethrows -> T {
        writeLock()
        defer { writeUnlock() }
        return try body()
    }
}
