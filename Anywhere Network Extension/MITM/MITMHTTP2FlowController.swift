//
//  MITMHTTP2FlowController.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Foundation

/// Tracks the peer receive windows the MITM must respect when it emits DATA the
/// real sender didn't produce (synth and buffered-rewrite bodies), pacing instead
/// of overflowing into a FLOW_CONTROL_ERROR. Only connection-level windows and
/// cross-leg debt live here; per-stream windows live on the connection.
///
/// Shared by a session's two h2 legs on the serial lwIP queue — no internal
/// synchronization. Windows are signed (RFC 9113 §6.9.2 allows going negative);
/// negative just gates synth emission until credited positive again.
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

    /// Bytes the MITM injected toward the client that the upstream did not send;
    /// relaying the client's WINDOW_UPDATEs verbatim would over-grant the upstream's
    /// send window, so this is withheld first.
    private(set) var synthConnectionDebt: Int = 0

    /// Request-direction mirror: bytes credited directly to the client while
    /// buffering a request, withheld from the upstream's later credits so the
    /// client isn't credited twice.
    private(set) var clientRequestConnectionDebt: Int = 0

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

    /// Records synth debt (post-establishment only — a pre-establishment one-shot
    /// never dials, so nothing to over-grant).
    func addSynthDebt(_ n: Int) {
        synthConnectionDebt += n
    }

    func addClientRequestDebt(_ n: Int) {
        clientRequestConnectionDebt += n
    }

    /// Withholds the debt portion from an upstream→client WINDOW_UPDATE; `0` means
    /// drop the frame (a zero-increment WINDOW_UPDATE is a PROTOCOL_ERROR, RFC 9113 §6.9.1).
    func withholdClientRequestDebt(from increment: Int) -> Int {
        let withheld = min(increment, clientRequestConnectionDebt)
        clientRequestConnectionDebt -= withheld
        return increment - withheld
    }

    /// Withholds the synth-debt portion from a client→upstream WINDOW_UPDATE;
    /// `0` means drop the frame.
    func withholdSynthDebt(from increment: Int) -> Int {
        let withheld = min(increment, synthConnectionDebt)
        synthConnectionDebt -= withheld
        return increment - withheld
    }

    /// Records a new client SETTINGS_INITIAL_WINDOW_SIZE and returns the (possibly
    /// negative) delta for retroactive adjustment of open synth stream windows (RFC 9113 §6.9.2).
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
