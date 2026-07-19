//
//  DialDeadline.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation
import Synchronization

nonisolated func raceDialDeadline<T: Sendable>(
    _ deadline: Duration,
    onExpire: @escaping @Sendable () -> Void = {},
    timeout: @autoclosure @escaping @Sendable () -> Error = AnywhereError.transport(.posix(.connect, errno: ETIMEDOUT)),
    _ body: @escaping @Sendable () async throws -> T
) async throws -> T {
    let expired = Atomic(false)
    return try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            do {
                return try await body()
            } catch {
                throw expired.load(ordering: .relaxed) ? timeout() : error
            }
        }
        group.addTask {
            try await Task.sleep(for: deadline)
            expired.store(true, ordering: .relaxed)
            onExpire()
            throw timeout()
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else { throw timeout() }
        return result
    }
}
