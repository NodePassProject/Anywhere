//
//  UnfairLock.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated final class UnfairLock {
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

nonisolated final class ReadWriteLock {
    private var _lock = pthread_rwlock_t()

    init() {
        pthread_rwlock_init(&_lock, nil)
    }

    @inline(__always)
    func readLock() {
        pthread_rwlock_rdlock(&_lock)
    }

    @inline(__always)
    func readUnlock() {
        pthread_rwlock_unlock(&_lock)
    }

    @inline(__always)
    func writeLock() {
        pthread_rwlock_wrlock(&_lock)
    }

    @inline(__always)
    func writeUnlock() {
        pthread_rwlock_unlock(&_lock)
    }

    @inline(__always)
    func withReadLock<T>(_ body: () throws -> T) rethrows -> T {
        readLock()
        defer { readUnlock() }
        return try body()
    }

    @inline(__always)
    func withWriteLock<T>(_ body: () throws -> T) rethrows -> T {
        writeLock()
        defer { writeUnlock() }
        return try body()
    }
}
