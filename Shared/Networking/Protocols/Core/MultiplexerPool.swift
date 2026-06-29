//
//  MultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 4/14/26.
//

import Foundation

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

    /// Guards `multiplexers`, `lastActivity`, and `idleTimer`.
    let lock = UnfairLock()

    var multiplexers: [String: [S]] = [:]

    /// `MonotonicClock.now` at last acquire/reuse, for idle eviction. Subclasses stamp it
    /// under ``lock`` on every acquire/reuse.
    var lastActivity: [ObjectIdentifier: TimeInterval] = [:]

    private let evictionQueue = DispatchQueue(label: AWCore.Identifier.multiplexerEvictionQueue)
    private var idleTimer: DispatchSourceTimer?
    private(set) var policy: MultiplexerPolicy?

    init() {}

    /// A dropped-but-uncancelled `DispatchSourceTimer` is retained by libdispatch and fires
    /// forever; always cancel.
    deinit {
        idleTimer?.cancel()
    }

    static func makeKey(host: String, port: UInt16, sni: String) -> String {
        "\(host):\(port):\(sni)"
    }

    // MARK: - Idle eviction

    /// Arms the shared idle-eviction sweep. Call once from the subclass init; idempotent.
    func startIdleEviction(_ policy: MultiplexerPolicy) {
        let timer = DispatchSource.makeTimerSource(queue: evictionQueue)
        timer.schedule(
            deadline: .now() + policy.idleCheckInterval,
            repeating: policy.idleCheckInterval,
            leeway: .milliseconds(Int(policy.idleCheckInterval * 100))   // ~10%
        )
        timer.setEventHandler { [weak self] in self?.runIdleEviction() }
        lock.lock()
        self.policy = policy
        idleTimer?.cancel()
        idleTimer = timer
        lock.unlock()
        timer.resume()
    }

    private func runIdleEviction() {
        let now = MonotonicClock.now
        var toClose: [S] = []

        // Decide and remove under one lock hold so a concurrent acquire can't reserve a mux
        // we're about to close; close() then runs off-lock.
        lock.lock()
        guard let policy else { lock.unlock(); return }
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
        lock.unlock()

        for mux in toClose { mux.close(error: nil) }
    }

    // MARK: - Removal / teardown

    func removeMultiplexer(_ multiplexer: S, key: String) {
        lock.lock()
        multiplexers[key]?.removeAll { $0 === multiplexer }
        if multiplexers[key]?.isEmpty == true {
            multiplexers.removeValue(forKey: key)
        }
        lastActivity.removeValue(forKey: ObjectIdentifier(multiplexer))
        lock.unlock()
    }

    /// Closes every pooled multiplexer. Leaves the idle timer running so reused singletons
    /// keep sweeping; per-config pools cancel it in `deinit` when dropped.
    func closeAll() {
        lock.lock()
        let all = multiplexers.values.flatMap { $0 }
        multiplexers.removeAll()
        lastActivity.removeAll()
        lock.unlock()

        for multiplexer in all {
            multiplexer.close(error: nil)
        }
    }
}

extension MultiplexerPool: TransportPool {
    func reclaim() { closeAll() }
}
