//
//  MITMHTTP2FlowController.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Synchronization

nonisolated final class MITMHTTP2FlowController: Sendable {

    /// Largest legal flow-control window (RFC 9113 §6.9.1, 2^31 - 1); credits clamp here.
    static let maxWindow = 0x7FFF_FFFF

    private struct Windows {
        /// Connection-level window for client-bound DATA; changed *only* by WINDOW_UPDATE —
        /// SETTINGS_INITIAL_WINDOW_SIZE does not affect the connection window (RFC 9113 §6.9.2).
        var connection = 65_535
        /// Client's latest SETTINGS_INITIAL_WINDOW_SIZE; seeds per-stream windows of
        /// MITM-synthesized client-bound streams.
        var clientInitialStream = 65_535
        /// Upstream mirror of ``connection`` for server-bound DATA.
        var serverConnection = 65_535
        /// Upstream mirror of ``clientInitialStream`` for server-bound request bodies.
        var serverInitialStream = 65_535
    }

    private let windows = Mutex(Windows())

    var connectionWindow: Int { windows.withLock { $0.connection } }
    var clientInitialStreamWindow: Int { windows.withLock { $0.clientInitialStream } }
    var serverConnectionWindow: Int { windows.withLock { $0.serverConnection } }
    var serverInitialStreamWindow: Int { windows.withLock { $0.serverInitialStream } }

    /// Debits the connection window; may go negative, gating synth emission.
    func debitConnection(_ n: Int) {
        windows.withLock { $0.connection -= n }
    }

    /// Credits the connection window by a client stream-0 WINDOW_UPDATE, clamped to ``maxWindow``.
    func creditConnection(_ increment: Int) {
        windows.withLock { $0.connection = min(Self.maxWindow, $0.connection &+ increment) }
    }

    /// Debits the upstream connection window; may go negative, gating paced request emission.
    func debitServerConnection(_ n: Int) {
        windows.withLock { $0.serverConnection -= n }
    }

    /// Credits the upstream connection window by a server stream-0 WINDOW_UPDATE, clamped to ``maxWindow``.
    func creditServerConnection(_ increment: Int) {
        windows.withLock { $0.serverConnection = min(Self.maxWindow, $0.serverConnection &+ increment) }
    }

    /// Records a new client SETTINGS_INITIAL_WINDOW_SIZE and returns the (possibly negative)
    /// delta for retroactive adjustment of open synth stream windows (RFC 9113 §6.9.2).
    func updateInitialStreamWindow(_ newValue: Int) -> Int {
        windows.withLock { w in
            // RFC 9113 §6.5.2: values above 2^31-1 are a FLOW_CONTROL_ERROR; clamp our model too.
            let clamped = min(newValue, Self.maxWindow)
            let delta = clamped - w.clientInitialStream
            w.clientInitialStream = clamped
            return delta
        }
    }

    /// Upstream mirror of ``updateInitialStreamWindow`` for paced-request stream windows.
    func updateServerInitialStreamWindow(_ newValue: Int) -> Int {
        windows.withLock { w in
            let clamped = min(newValue, Self.maxWindow)
            let delta = clamped - w.serverInitialStream
            w.serverInitialStream = clamped
            return delta
        }
    }
}
