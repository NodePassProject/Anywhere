//
//  SerialSendChain.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation
import Synchronization

nonisolated final class SerialSendChain: Sendable {
    private let tail = Mutex<Task<Void, Error>?>(nil)
    
    func run(_ body: @escaping @Sendable () async throws -> Void) async throws {
        try await enqueue(body).value
    }
    
    @discardableResult
    func enqueue(_ body: @escaping @Sendable () async throws -> Void) -> Task<Void, Error> {
        tail.withLock { tail in
            let previous = tail
            let task = Task<Void, Error> {
                _ = try? await previous?.value
                try await body()
            }
            tail = task
            return task
        }
    }
}
