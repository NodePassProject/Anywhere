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

nonisolated class MultiplexerPool<S: Multiplexer, Extra> {
    
    struct PoolState {
        var multiplexers: [String: [S]] = [:]

        /// `MonotonicClock.now` at last acquire/reuse, for idle eviction. Subclasses stamp it
        /// on every acquire/reuse.
        var lastActivity: [ObjectIdentifier: TimeInterval] = [:]

        var idleTask: Task<Void, Never>?
        var policy: MultiplexerPolicy?

        /// Subclass-owned pool state
        var extra: Extra
    }
    
    let state: Mutex<PoolState>

    init(extra: Extra) {
        state = Mutex(PoolState(extra: extra))
    }

    /// A dropped idle-eviction loop keeps sweeping forever; always cancel.
    deinit {
        state.withLock { $0.idleTask?.cancel() }
    }

    static func makeKey(host: String, port: UInt16, sni: String) -> String {
        "\(host):\(port):\(sni)"
    }

    // MARK: - Idle eviction

    /// Arms the shared idle-eviction sweep. Call once from the subclass init; idempotent.
    func startIdleEviction(_ policy: MultiplexerPolicy) {
        state.withLock { st in
            st.policy = policy
            st.idleTask?.cancel()
            st.idleTask = Task { [weak self] in
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
        let toClose: [S] = state.withLock { st -> [S] in
            guard let policy = st.policy else { return [] }
            var toClose: [S] = []
            for key in Array(st.multiplexers.keys) {
                guard let muxes = st.multiplexers[key] else { continue }
                var idle = muxes.filter { $0.activeStreamCount == 0 && !$0.isClosed }
                if policy.minIdleKeep > 0 {
                    // Keep the freshest `minIdleKeep` warm.
                    idle.sort { (st.lastActivity[ObjectIdentifier($0)] ?? 0) > (st.lastActivity[ObjectIdentifier($1)] ?? 0) }
                }
                for (index, mux) in idle.enumerated() {
                    if index < policy.minIdleKeep {
                        st.lastActivity[ObjectIdentifier(mux)] = now
                        continue
                    }
                    let age = now - (st.lastActivity[ObjectIdentifier(mux)] ?? now)
                    if age > policy.idleTimeout {
                        st.multiplexers[key]?.removeAll { $0 === mux }
                        st.lastActivity.removeValue(forKey: ObjectIdentifier(mux))
                        toClose.append(mux)
                    }
                }
                if st.multiplexers[key]?.isEmpty == true { st.multiplexers.removeValue(forKey: key) }
            }
            return toClose
        }

        for mux in toClose { mux.close(error: nil) }
    }

    // MARK: - Removal / teardown

    func removeMultiplexer(_ multiplexer: S, key: String) {
        state.withLock { st in
            st.multiplexers[key]?.removeAll { $0 === multiplexer }
            if st.multiplexers[key]?.isEmpty == true {
                st.multiplexers.removeValue(forKey: key)
            }
            st.lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
        }
    }

    /// Closes every pooled multiplexer. Leaves the idle sweep running so reused singletons
    /// keep sweeping; per-config pools cancel it in `deinit` when dropped.
    func closeAll() {
        let all: [S] = state.withLock { st in
            let all = st.multiplexers.values.flatMap { $0 }
            st.multiplexers.removeAll()
            st.lastActivity.removeAll()
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
