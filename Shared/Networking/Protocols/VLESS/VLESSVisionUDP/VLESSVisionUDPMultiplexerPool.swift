//
//  VLESSVisionUDPMultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated final class VLESSVisionUDPMultiplexerPool {
    let configuration: ProxyConfiguration
    private let multiplexers = Mutex<[VLESSVisionUDPMultiplexer]>([])

    init(configuration: ProxyConfiguration) {
        self.configuration = configuration
    }

    /// Reuses a mux with spare capacity or dials a fresh one, then opens a stream.
    func acquireStream(
        network: VLESSVisionUDPNetwork,
        host: String,
        port: UInt16,
        globalID: Data?
    ) async throws -> VLESSVisionUDPStream {
        let multiplexer: VLESSVisionUDPMultiplexer = multiplexers.withLock { multiplexers in
            multiplexers.removeAll { $0.isClosed }

            if let reusable = multiplexers.first(where: { !$0.isFull }) {
                return reusable
            }

            let created = VLESSVisionUDPMultiplexer(configuration: configuration)
            // Self-eviction: a mux that idle-times-out or fails removes itself here instead of
            // lingering until the next acquire. `onClose` fires off this lock.
            created.onClose = { [weak self, weak created] in
                guard let self, let created else { return }
                self.multiplexers.withLock { $0.removeAll { $0 === created } }
            }
            multiplexers.append(created)
            return created
        }

        return try await multiplexer.openStream(network: network, host: host, port: port, globalID: globalID)
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
