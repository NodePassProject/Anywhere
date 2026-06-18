//
//  MITMHTTP2FlowController.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Foundation

/// Tracks peer connection-level receive windows so MITM-emitted DATA (synth and
/// buffered-rewrite bodies) is paced instead of overflowing into a FLOW_CONTROL_ERROR.
/// No internal sync — confined to the serial lwIP queue. Windows are signed (RFC 9113
/// §6.9.2 allows negative); negative gates synth emission until credited positive.
final class MITMHTTP2FlowController {

    /// Largest legal flow-control window (RFC 9113 §6.9.1, 2^31 - 1); credits clamp here.
    static let maxWindow = 0x7FFF_FFFF

    /// Connection-level window for client-bound DATA; changed *only* by WINDOW_UPDATE —
    /// SETTINGS_INITIAL_WINDOW_SIZE does not affect the connection window (RFC 9113 §6.9.2).
    private(set) var connectionWindow: Int = 65_535

    /// Client's latest SETTINGS_INITIAL_WINDOW_SIZE; seeds per-stream windows of
    /// MITM-synthesized client-bound streams.
    private(set) var clientInitialStreamWindow: Int = 65_535

    /// Upstream mirror of ``connectionWindow`` for server-bound DATA.
    private(set) var serverConnectionWindow: Int = 65_535

    /// Upstream mirror of ``clientInitialStreamWindow`` for server-bound request bodies.
    private(set) var serverInitialStreamWindow: Int = 65_535

    /// Debits the connection window; may go negative, gating synth emission.
    func debitConnection(_ n: Int) {
        connectionWindow -= n
    }

    /// Credits the connection window by a client stream-0 WINDOW_UPDATE, clamped to ``maxWindow``.
    func creditConnection(_ increment: Int) {
        connectionWindow = min(Self.maxWindow, connectionWindow &+ increment)
    }

    /// Debits the upstream connection window; may go negative, gating paced request emission.
    func debitServerConnection(_ n: Int) {
        serverConnectionWindow -= n
    }

    /// Credits the upstream connection window by a server stream-0 WINDOW_UPDATE, clamped to ``maxWindow``.
    func creditServerConnection(_ increment: Int) {
        serverConnectionWindow = min(Self.maxWindow, serverConnectionWindow &+ increment)
    }

    /// Records a new client SETTINGS_INITIAL_WINDOW_SIZE and returns the (possibly negative)
    /// delta for retroactive adjustment of open synth stream windows (RFC 9113 §6.9.2).
    func updateInitialStreamWindow(_ newValue: Int) -> Int {
        // RFC 9113 §6.5.2: values above 2^31-1 are a FLOW_CONTROL_ERROR; clamp our model too.
        let clamped = min(newValue, Self.maxWindow)
        let delta = clamped - clientInitialStreamWindow
        clientInitialStreamWindow = clamped
        return delta
    }

    /// Upstream mirror of ``updateInitialStreamWindow`` for paced-request stream windows.
    func updateServerInitialStreamWindow(_ newValue: Int) -> Int {
        let clamped = min(newValue, Self.maxWindow)
        let delta = clamped - serverInitialStreamWindow
        serverInitialStreamWindow = clamped
        return delta
    }
}
