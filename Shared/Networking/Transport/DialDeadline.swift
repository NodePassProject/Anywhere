//
//  DialDeadline.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation

/// Races `body` against a wall-clock `deadline` in a throwing task group: the first
/// to finish wins, the loser is cancelled. `onExpire` runs on expiry before the
/// timeout error is thrown, for side effects (cancelling a carrier) that unblock a
/// `body` parked on an await that ignores task cancellation.
nonisolated func raceDialDeadline<T: Sendable>(
    _ deadline: Duration,
    onExpire: @escaping @Sendable () -> Void = {},
    timeout: @autoclosure @escaping @Sendable () -> Error = AnywhereError.transport(.posix(.connect, errno: ETIMEDOUT)),
    _ body: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await body() }
        group.addTask {
            try await Task.sleep(for: deadline)
            onExpire()
            throw timeout()
        }
        defer { group.cancelAll() }
        // First task to finish wins: `body`'s value/throw, or the deadline throw.
        guard let result = try await group.next() else { throw timeout() }
        return result
    }
}
