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

/// Keyed by `(server, port, direct-dial host, outbound settings)`; configs sharing the
/// tuple reuse one warm mux session.
nonisolated final class SudokuMultiplexerRegistry: Sendable {

    nonisolated static let shared = SudokuMultiplexerRegistry()

    private struct Key: Hashable {
        let serverAddress: String
        let serverPort: UInt16
        let directDialHost: String
        let outbound: Outbound
    }

    private let pools = Mutex<[Key: SudokuMultiplexerPool]>([:])

    private init() {}

    /// Creates the pool on first use.
    func pool(for configuration: ProxyConfiguration, directDialHost: String) -> SudokuMultiplexerPool? {
        guard case .sudoku = configuration.outbound else {
            logger.debug("[SudokuMultiplexerRegistry] outbound is not .sudoku — refusing to create pool")
            return nil
        }
        let key = Key(
            serverAddress: configuration.serverAddress,
            serverPort: configuration.serverPort,
            directDialHost: directDialHost,
            outbound: configuration.outbound
        )
        var reused = true
        let pool = pools.withLock { pools -> SudokuMultiplexerPool in
            if let existing = pools[key] {
                return existing
            }
            reused = false
            let created = SudokuMultiplexerPool(configuration: configuration, directDialHost: directDialHost)
            pools[key] = created
            return created
        }
        if reused {
            logger.debug("[SudokuMultiplexerRegistry] reuse pool \(configuration.serverAddress):\(configuration.serverPort)")
        } else {
            logger.debug("[SudokuMultiplexerRegistry] created pool \(configuration.serverAddress):\(configuration.serverPort)")
        }
        return pool
    }

    /// Called on wake/path change/stop because the kernel may have torn down the sockets.
    func closeAll() {
        let snapshot = pools.withLock { pools -> [SudokuMultiplexerPool] in
            let values = Array(pools.values)
            pools.removeAll(keepingCapacity: false)
            return values
        }
        if !snapshot.isEmpty {
            logger.debug("[SudokuMultiplexerRegistry] closeAll(\(snapshot.count) pools)")
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

/// Warm pool per `(server, port, direct-dial host, outbound settings)`. One Sudoku session
/// carries any number of streams, so the pool holds at most one live session and coalesces
/// cold-start bursts behind a single KIP handshake.
nonisolated final class SudokuMultiplexerPool: TransportPool {

    private typealias Base = MultiplexerPool<SudokuMuxClient, Bool>
    private let pool = Base(extra: false)

    /// Single bucket — every session here shares one endpoint + outbound settings.
    private static let bucket = "sudoku"

    /// Keeps one session warm across idle gaps so a follow-up request skips the KIP handshake;
    /// the 15s keepalive maintains it, and coalescing means there's rarely more than one.
    private static let poolPolicy = MultiplexerPolicy(
        idleTimeout: 60,
        idleCheckInterval: 60,
        minIdleKeep: 1
    )

    private let configuration: ProxyConfiguration
    private let directDialHost: String

    /// The in-flight cold-start dial, if one is running. Burst callers coalesce onto this one
    /// `Task` (the leader) and `await` its result instead of polling a flag — the same
    /// single-flight pattern as `NowhereClient`/`HysteriaClient`. The leader clears it when the
    /// handshake settles.
    private let inFlightDial = Mutex<Task<SudokuMuxClient, Error>?>(nil)

    // The base `Extra` is a `Bool` `closed` flag, guarded by ``state``.

    init(configuration: ProxyConfiguration, directDialHost: String) {
        self.configuration = configuration
        self.directDialHost = directDialHost
        pool.startIdleEviction(Self.poolPolicy)
    }

    func reclaim() { closeAll() }

    // MARK: - Acquire

    /// Opens a stream on the pooled session, dialing one if needed. A dial failure on a
    /// reused session usually means the kernel killed the socket while it sat idle, so the
    /// dial is retried once on a fresh session.
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

    /// Restarts the idle clock at stream end, so a freed session is kept warm for the full
    /// idle timeout (not evicted right after a long transfer).
    func noteStreamEnded(_ multiplexer: SudokuMuxClient) {
        pool.state.withLock { st in
            if st.lastActivity[ObjectIdentifier(multiplexer)] != nil {
                st.lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
            }
        }
    }

    // MARK: - Teardown

    /// Sets `closed` to reject new acquires, then defers to the pool engine.
    func closeAll() {
        pool.state.withLock { $0.extra = true }
        pool.closeAll()
    }

    // MARK: - Private

    private func acquireMultiplexer() async throws -> SudokuMuxClient {
        while true {
            if let existing = try reusableMultiplexer() {
                return existing
            }

            // Coalesce concurrent cold starts: the first caller becomes the dial leader; the
            // rest await that same handshake `Task` and receive the same warm session.
            let (dial, isLeader) = inFlightDial.withLock { slot -> (Task<SudokuMuxClient, Error>, Bool) in
                if let existing = slot {
                    return (existing, false)
                }
                let dial = Task { [self] in try await dialMultiplexer() }
                slot = dial
                return (dial, true)
            }

            if isLeader {
                // The leader owns the slot's lifetime: clear it once the dial settles so a later
                // cold start can lead a fresh handshake.
                defer { inFlightDial.withLock { $0 = nil } }
                return try await dial.value
            }

            do {
                return try await dial.value
            } catch {
                // The leader's dial failed; loop to re-check the pool and, if still empty, lead
                // a fresh handshake ourselves (matching the former re-poll-then-claim behaviour).
                continue
            }
        }
    }

    /// Returns the pooled session, pruning corpses that closed before `onClose` was armed
    /// (age-based idle eviction is the base's sweep).
    private func reusableMultiplexer() throws -> SudokuMuxClient? {
        try pool.state.withLock { st in
            if st.extra { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
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

    /// Dials a fresh session on its own factory; the session owns the factory and tears it
    /// down on close.
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
        // close() re-enters removeMultiplexer via onClose, so it must run off-lock.
        let wasClosed: Bool = pool.state.withLock { st in
            if st.extra { return true }
            st.multiplexers[Self.bucket, default: []].append(multiplexer)
            st.lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
            return false
        }
        if wasClosed {
            multiplexer.close(error: nil)
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
        }
        logger.debug("[SudokuMultiplexerPool] new session \(configuration.serverAddress):\(configuration.serverPort)")
        return multiplexer
    }
}
