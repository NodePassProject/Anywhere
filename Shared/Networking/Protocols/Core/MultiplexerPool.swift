//
//  MultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 4/14/26.
//

import Foundation
import Synchronization

// MARK: - MultiplexerPolicy

nonisolated struct MultiplexerPolicy {
    var idleTimeout: TimeInterval
    var idleCheckInterval: TimeInterval
    var minIdleKeep: Int
    /// Per-key mux caps; 0 = unlimited.
    var softCapPerKey: Int
    var hardCapPerKey: Int

    init(
        idleTimeout: TimeInterval,
        idleCheckInterval: TimeInterval,
        minIdleKeep: Int = 0,
        softCapPerKey: Int = 0,
        hardCapPerKey: Int = 0
    ) {
        self.idleTimeout = idleTimeout
        self.idleCheckInterval = idleCheckInterval
        self.minIdleKeep = minIdleKeep
        self.softCapPerKey = softCapPerKey
        self.hardCapPerKey = hardCapPerKey
    }
}

// MARK: - MultiplexerPool

/// Pooled-multiplexer managers keyed by `host:port:sni`, owning shared storage, idle
/// eviction, and reclaim; subclasses add their own `acquire`.
nonisolated class MultiplexerPool<S: Multiplexer> {

    /// Critical-section gate guarding `multiplexers`, `lastActivity`, `policy`, `idleTask`, and
    /// each subclass's own pool state. A `Mutex<Void>` (not `Mutex<State>`) because the guarded
    /// fields are shared across the class hierarchy and one subclass drops the gate mid-acquire
    /// to close a victim off-lock.
    let lock = Mutex<Void>(())

    var multiplexers: [String: [S]] = [:]

    /// `MonotonicClock.now` at last acquire/reuse, for idle eviction. Subclasses stamp it
    /// under ``lock`` on every acquire/reuse.
    var lastActivity: [ObjectIdentifier: TimeInterval] = [:]

    private var idleTask: Task<Void, Never>?
    private(set) var policy: MultiplexerPolicy?

    init() {}

    /// A dropped idle-eviction loop keeps sweeping forever; always cancel.
    deinit {
        idleTask?.cancel()
    }

    static func makeKey(host: String, port: UInt16, sni: String) -> String {
        "\(host):\(port):\(sni)"
    }

    // MARK: - Idle eviction

    /// Arms the shared idle-eviction sweep. Call once from the subclass init; idempotent.
    func startIdleEviction(_ policy: MultiplexerPolicy) {
        lock.withLock { _ in
            self.policy = policy
            idleTask?.cancel()
            idleTask = Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(for: .seconds(policy.idleCheckInterval))
                    guard !Task.isCancelled, let self else { return }
                    self.runIdleEviction()
                }
            }
        }
    }

    private func runIdleEviction() {
        let now = MonotonicClock.now

        // Decide and remove under one lock hold so a concurrent acquire can't reserve a mux
        // we're about to close; close() then runs off-lock.
        let toClose: [S] = lock.withLock { _ -> [S] in
            guard let policy else { return [] }
            var toClose: [S] = []
            for key in Array(multiplexers.keys) {
                guard let muxes = multiplexers[key] else { continue }
                var idle = muxes.filter { $0.activeStreamCount == 0 && !$0.isClosed }
                if policy.minIdleKeep > 0 {
                    // Keep the freshest `minIdleKeep` warm.
                    idle.sort { (lastActivity[ObjectIdentifier($0)] ?? 0) > (lastActivity[ObjectIdentifier($1)] ?? 0) }
                }
                for (index, mux) in idle.enumerated() {
                    if index < policy.minIdleKeep {
                        lastActivity[ObjectIdentifier(mux)] = now
                        continue
                    }
                    let age = now - (lastActivity[ObjectIdentifier(mux)] ?? now)
                    if age > policy.idleTimeout {
                        multiplexers[key]?.removeAll { $0 === mux }
                        lastActivity.removeValue(forKey: ObjectIdentifier(mux))
                        toClose.append(mux)
                    }
                }
                if multiplexers[key]?.isEmpty == true { multiplexers.removeValue(forKey: key) }
            }
            return toClose
        }

        for mux in toClose { mux.close(error: nil) }
    }

    // MARK: - Removal / teardown

    func removeMultiplexer(_ multiplexer: S, key: String) {
        lock.withLock { _ in
            multiplexers[key]?.removeAll { $0 === multiplexer }
            if multiplexers[key]?.isEmpty == true {
                multiplexers.removeValue(forKey: key)
            }
            lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
        }
    }

    /// Closes every pooled multiplexer. Leaves the idle sweep running so reused singletons
    /// keep sweeping; per-config pools cancel it in `deinit` when dropped.
    func closeAll() {
        let all: [S] = lock.withLock { _ in
            let all = multiplexers.values.flatMap { $0 }
            multiplexers.removeAll()
            lastActivity.removeAll()
            return all
        }

        for multiplexer in all {
            multiplexer.close(error: nil)
        }
    }
}

extension MultiplexerPool: TransportPool {
    func reclaim() { closeAll() }
}
