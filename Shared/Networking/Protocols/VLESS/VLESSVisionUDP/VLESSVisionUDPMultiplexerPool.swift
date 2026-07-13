//
//  VLESSVisionUDPMultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

/// Warm pool of Vision-UDP mux connections for one tunnel, owned by ``TunnelStack`` on
/// ``TunnelStack/udpQueue`` and torn down there on wake/path-change/stop.
///
/// Deliberately standalone rather than a ``MultiplexerPool`` subclass: each
/// ``VLESSVisionUDPMultiplexer`` runs its own idle timer, and an XUDP (globalID) mux pins a
/// single flow for its lifetime — neither fits the base's pool-driven idle sweep and per-key
/// bucketing. The `multiplexers` collection is guarded by a `Mutex`, but each mux's own state
/// stays confined to `flowQueue`, so `acquireStream` must be called on `flowQueue`.
nonisolated final class VLESSVisionUDPMultiplexerPool {
    let configuration: ProxyConfiguration
    let flowQueue: DispatchQueue
    private let multiplexers = Mutex<[VLESSVisionUDPMultiplexer]>([])

    init(configuration: ProxyConfiguration, flowQueue: DispatchQueue) {
        self.configuration = configuration
        self.flowQueue = flowQueue
    }

    /// Reuses a mux with spare capacity or dials a fresh one, then opens a stream. Must be
    /// called on `flowQueue`.
    func acquireStream(
        network: VLESSVisionUDPNetwork,
        host: String,
        port: UInt16,
        globalID: Data?,
        completion: @escaping (Result<VLESSVisionUDPStream, Error>) -> Void
    ) {
        let multiplexer: VLESSVisionUDPMultiplexer = multiplexers.withLock { multiplexers in
            multiplexers.removeAll { $0.isClosed }

            if let reusable = multiplexers.first(where: { !$0.isFull }) {
                return reusable
            }

            let created = VLESSVisionUDPMultiplexer(configuration: configuration, flowQueue: flowQueue)
            // Self-eviction: a mux that idle-times-out or fails removes itself here instead of
            // lingering until the next acquire. `onClose` fires on flowQueue, off this lock.
            created.onClose = { [weak self, weak created] in
                guard let self, let created else { return }
                self.multiplexers.withLock { $0.removeAll { $0 === created } }
            }
            multiplexers.append(created)
            return created
        }

        multiplexer.openStream(network: network, host: host, port: port, globalID: globalID, completion: completion)
    }

    func closeAll() {
        // Snapshot and clear under the lock, then close off-lock: each close() re-enters the
        // lock via `onClose`, which would deadlock the non-reentrant Mutex if held here.
        let all = multiplexers.withLock { multiplexers -> [VLESSVisionUDPMultiplexer] in
            let snapshot = multiplexers
            multiplexers.removeAll()
            return snapshot
        }
        for multiplexer in all {
            multiplexer.close()
        }
    }
}
