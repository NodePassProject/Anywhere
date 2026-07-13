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
nonisolated final class SudokuMultiplexerRegistry {

    static let shared = SudokuMultiplexerRegistry()

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

extension SudokuMultiplexerRegistry: TransportPool {
    func reclaim() { closeAll() }
}

// MARK: - SudokuMultiplexerPool

/// Warm pool per `(server, port, direct-dial host, outbound settings)`. One Sudoku session
/// carries any number of streams, so the pool holds at most one live session and coalesces
/// cold-start bursts behind a single KIP handshake.
nonisolated final class SudokuMultiplexerPool: MultiplexerPool<SudokuMuxClient> {

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

    /// Guards `dialing`; burst callers wait here so they share one handshake.
    private let dialCondition = NSCondition()
    private var dialing = false

    /// Guarded by ``lock``.
    private var closed = false

    init(configuration: ProxyConfiguration, directDialHost: String) {
        self.configuration = configuration
        self.directDialHost = directDialHost
        super.init()
        startIdleEviction(Self.poolPolicy)
    }

    // MARK: - Acquire

    /// Opens a stream on the pooled session, dialing one if needed. A dial failure on a
    /// reused session usually means the kernel killed the socket while it sat idle, so the
    /// dial is retried once on a fresh session.
    func dialTCP(host: String, port: UInt16) throws -> (SudokuMuxClient, SudokuMuxStream) {
        let multiplexer = try acquireMultiplexer()
        do {
            return (multiplexer, try multiplexer.dialTCP(host: host, port: port))
        } catch {
            multiplexer.close(error: error)
            let retry = try acquireMultiplexer()
            return (retry, try retry.dialTCP(host: host, port: port))
        }
    }

    /// Restarts the idle clock at stream end, so a freed session is kept warm for the full
    /// idle timeout (not evicted right after a long transfer).
    func noteStreamEnded(_ multiplexer: SudokuMuxClient) {
        lock.lock()
        if lastActivity[ObjectIdentifier(multiplexer)] != nil {
            lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
        }
        lock.unlock()
    }

    // MARK: - Teardown

    /// Sets `closed` to reject new acquires, then defers to the base.
    override func closeAll() {
        lock.lock()
        closed = true
        lock.unlock()
        // Wake dial-waiters so they observe `closed` instead of blocking forever.
        dialCondition.lock()
        dialCondition.broadcast()
        dialCondition.unlock()
        super.closeAll()
    }

    // MARK: - Private

    private func acquireMultiplexer() throws -> SudokuMuxClient {
        while true {
            if let existing = try reusableMultiplexer() {
                return existing
            }
            dialCondition.lock()
            if dialing {
                // Another caller is handshaking; re-check the pool once it publishes.
                dialCondition.wait()
                dialCondition.unlock()
                continue
            }
            dialing = true
            dialCondition.unlock()

            defer {
                dialCondition.lock()
                dialing = false
                dialCondition.broadcast()
                dialCondition.unlock()
            }
            return try dialMultiplexer()
        }
    }

    /// Returns the pooled session, pruning corpses that closed before `onClose` was armed
    /// (age-based idle eviction is the base's sweep).
    private func reusableMultiplexer() throws -> SudokuMuxClient? {
        lock.lock()
        defer { lock.unlock() }
        if closed { throw SudokuNativeError.closed }
        multiplexers[Self.bucket]?.removeAll { multiplexer in
            guard multiplexer.isClosed else { return false }
            lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
            return true
        }
        guard let existing = multiplexers[Self.bucket]?.first else { return nil }
        lastActivity[ObjectIdentifier(existing)] = MonotonicClock.now
        return existing
    }

    /// Dials a fresh session on its own factory; the session owns the factory and tears it
    /// down on close.
    private func dialMultiplexer() throws -> SudokuMuxClient {
        let factory = SudokuConnectionFactory(
            configuration: configuration,
            initialTunnel: nil,
            directDialHost: directDialHost
        )
        let multiplexer: SudokuMuxClient
        do {
            let client = try SudokuNativeClient(configuration: configuration, factory: factory)
            multiplexer = try client.openMux(ownsFactory: true)
        } catch {
            factory.closeAll()
            throw error
        }
        multiplexer.onClose = { [weak self, weak multiplexer] in
            guard let self, let multiplexer else { return }
            self.removeMultiplexer(multiplexer, key: Self.bucket)
        }
        lock.lock()
        if closed {
            lock.unlock()
            multiplexer.close(error: nil)
            throw SudokuNativeError.closed
        }
        multiplexers[Self.bucket, default: []].append(multiplexer)
        lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
        lock.unlock()
        logger.debug("[SudokuMultiplexerPool] new session \(configuration.serverAddress):\(configuration.serverPort)")
        return multiplexer
    }
}
