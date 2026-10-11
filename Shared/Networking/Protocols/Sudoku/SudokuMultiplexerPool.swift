//
//  SudokuMultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 7/12/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "SudokuMultiplexerPool")

// MARK: - SudokuMultiplexerRegistry

nonisolated final class SudokuMultiplexerRegistry: Sendable {
    nonisolated static let shared = SudokuMultiplexerRegistry()

    private struct Key: Hashable {
        let serverAddress: String
        let serverPort: UInt16
        let directDialHost: String
        let outbound: Outbound
    }

    private struct State {
        var pools: [Key: SudokuMultiplexerPool] = [:]
        var sealed = false
    }
    private let state = Mutex(State())

    private init() {}

    func seal() { state.withLock { $0.sealed = true } }

    func unseal() { state.withLock { $0.sealed = false } }

    func pool(for configuration: ProxyConfiguration, directDialHost: String) -> SudokuMultiplexerPool? {
        guard case .sudoku = configuration.outbound else {
            return nil
        }
        let key = Key(
            serverAddress: configuration.serverAddress,
            serverPort: configuration.serverPort,
            directDialHost: directDialHost,
            outbound: configuration.outbound
        )
        let pool = state.withLock { state -> SudokuMultiplexerPool? in
            if let existing = state.pools[key] {
                return existing
            }
            guard !state.sealed else { return nil }
            let created = SudokuMultiplexerPool(configuration: configuration, directDialHost: directDialHost)
            state.pools[key] = created
            return created
        }
        guard let pool else {
            return nil
        }
        return pool
    }

    func closeAll() {
        let snapshot = state.withLock { state -> [SudokuMultiplexerPool] in
            let values = Array(state.pools.values)
            state.pools.removeAll(keepingCapacity: false)
            return values
        }
        for pool in snapshot {
            pool.closeAll()
        }
    }
}

nonisolated extension SudokuMultiplexerRegistry: TransportPool {
    func reclaim() { closeAll() }
}

// MARK: - SudokuMultiplexerPool

nonisolated final class SudokuMultiplexerPool: TransportPool {

    private typealias Base = MultiplexerPool<SudokuMuxClient, Void>
    private let pool = Base(extra: ())

    private static let bucket = "sudoku"

    private static let poolPolicy = MultiplexerPolicy(
        idleTimeout: 60,
        idleCheckInterval: 60,
        minIdleKeep: 1
    )

    private let configuration: ProxyConfiguration
    private let directDialHost: String

    private let inFlightDial = Mutex<Task<SudokuMuxClient, Error>?>(nil)

    init(configuration: ProxyConfiguration, directDialHost: String) {
        self.configuration = configuration
        self.directDialHost = directDialHost
        pool.startIdleEviction(Self.poolPolicy)
    }

    func reclaim() { pool.drainAll() }

    // MARK: - Acquire

    func dialTCP(host: String, port: UInt16) async throws -> (SudokuMuxClient, SudokuMuxStream) {
        let multiplexer = try await acquireMultiplexer()
        do {
            return (multiplexer, try await multiplexer.dialTCP(host: host, port: port))
        } catch {
            multiplexer.close(error: error)
            let retry = try await acquireMultiplexer()
            return (retry, try await retry.dialTCP(host: host, port: port))
        }
    }

    func noteStreamEnded(_ multiplexer: SudokuMuxClient) {
        pool.state.withLock { st in
            if st.lastActivity[ObjectIdentifier(multiplexer)] != nil {
                st.lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
            }
        }
    }

    // MARK: - Teardown

    func closeAll() {
        pool.retire()
    }

    // MARK: - Private

    private func acquireMultiplexer() async throws -> SudokuMuxClient {
        while true {
            if let existing = try reusableMultiplexer() {
                return existing
            }

            let (dial, isLeader) = inFlightDial.withLock { slot -> (Task<SudokuMuxClient, Error>, Bool) in
                if let existing = slot {
                    return (existing, false)
                }
                let dial = Task { [self] in try await dialMultiplexer() }
                slot = dial
                return (dial, true)
            }

            if isLeader {
                defer { inFlightDial.withLock { if $0 == dial { $0 = nil } } }
                return try await dial.value
            }

            do {
                return try await dial.value
            } catch {
                inFlightDial.withLock { if $0 == dial { $0 = nil } }
                continue
            }
        }
    }

    private func reusableMultiplexer() throws -> SudokuMuxClient? {
        try pool.state.withLock { st in
            if st.phase == .closed { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
            st.multiplexers[Self.bucket]?.removeAll { multiplexer in
                guard multiplexer.isClosed else { return false }
                st.lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
                return true
            }
            guard let existing = st.multiplexers[Self.bucket]?.first else { return nil }
            st.lastActivity[ObjectIdentifier(existing)] = MonotonicClock.now
            return existing
        }
    }

    private func dialMultiplexer() async throws -> SudokuMuxClient {
        let factory = SudokuConnectionFactory(
            configuration: configuration,
            initialTunnel: nil,
            directDialHost: directDialHost
        )
        let multiplexer: SudokuMuxClient
        do {
            let client = try SudokuNativeClient(configuration: configuration, factory: factory)
            multiplexer = try await client.openMux(ownsFactory: true) { [weak self] multiplexer in
                self?.pool.removeMultiplexer(multiplexer, key: Self.bucket)
            }
        } catch {
            factory.closeAll()
            throw error
        }
        let wasClosed: Bool = pool.state.withLock { st in
            if st.phase == .closed { return true }
            st.multiplexers[Self.bucket, default: []].append(multiplexer)
            st.lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
            return false
        }
        if !wasClosed { pool.noteMultiplexersChanged() }
        if wasClosed {
            multiplexer.close(error: nil)
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
        }
        return multiplexer
    }
}
