//
//  BlockingProxyStream.swift
//  Anywhere
//
//  Created by saba-futai on 10/18/26.
//

import Foundation
import Synchronization

nonisolated final class BlockingProxyStream: Sendable {
    private let connection: ProxyConnection
    private let owner: SudokuConnectionFactory?
    private enum Phase: PhaseTransitionable {
        case open
        case closed
        case cancelled

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.open, .closed),
                 (.open, .cancelled),
                 (.closed, .cancelled):
                return true
            default:
                return false
            }
        }
    }
    private let phase = Mutex<Phase>(.open)
    private let pending = Mutex(SudokuDataQueue())

    init(connection: ProxyConnection, owner: SudokuConnectionFactory? = nil) {
        self.connection = connection
        self.owner = owner
    }

    func sendAll(_ data: Data) async throws {
        if data.isEmpty { return }
        if isClosed { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        try await connection.sendRaw(data)
    }

    func readSome(max: Int) async throws -> Data {
        guard max > 0 else { return Data() }
        if let buffered = pending.withLock({ $0.isEmpty ? nil : $0.read(max: max) }) {
            return buffered
        }
        if isClosed { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        guard let data = try await connection.receiveRaw(), !data.isEmpty else {
            markClosed()
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
        }
        if data.count > max {
            pending.withLock { $0.append(data, from: max) }
            return data.prefixData(max)
        }
        return data
    }

    func readExact(_ count: Int) async throws -> Data {
        guard count > 0 else { return Data() }
        var out = Data(capacity: count)
        pending.withLock { pending in
            if !pending.isEmpty { pending.drain(exact: count, into: &out) }
        }
        while out.count < count {
            if isClosed { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
            guard let data = try await connection.receiveRaw(), !data.isEmpty else {
                markClosed()
                throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
            }
            let need = count - out.count
            if data.count > need {
                out.append(data.prefixData(need))
                pending.withLock { $0.append(data, from: need) }
            } else {
                out.append(data)
            }
        }
        return out
    }

    func cancel() {
        guard phase.withLock({ Phase.transition(&$0, to: .cancelled) }) else { return }
        owner?.releaseConnection(connection)
        connection.cancel()
    }

    private var isClosed: Bool {
        phase.withLock { $0 != .open }
    }

    private func markClosed() {
        _ = phase.withLock { Phase.transition(&$0, to: .closed) }
    }
}
