//
//  DialDeadline.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation
import Synchronization

nonisolated func withDialDeadline<T: Sendable>(
    _ duration: Duration,
    onExpiry: @escaping @Sendable () -> Void,
    error makeError: @escaping @Sendable () -> any Error,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    let winner = RaceClaim()
    return try await withThrowingTaskGroup(of: T?.self) { group in
        group.addTask {
            do {
                let value = try await operation()
                return winner.claim() ? value : nil
            } catch {
                if winner.claim() { throw error }
                return nil
            }
        }
        group.addTask {
            do { try await Task.sleep(for: duration) } catch { return nil }
            guard winner.claim() else { return nil }
            onExpiry()
            throw makeError()
        }
        defer { group.cancelAll() }
        while let result = try await group.next() {
            if let value = result { return value }
        }
        throw CancellationError()
    }
}

nonisolated final class RaceClaim: Sendable {
    private let claimed = Atomic<Bool>(false)

    func claim() -> Bool {
        !claimed.exchange(true, ordering: .relaxed)
    }
}
