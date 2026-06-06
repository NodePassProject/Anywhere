//
//  MITMHTTP2FlowController.swift
//  Anywhere
//
//  Created by NodePassProject on 6/2/26.
//

import Foundation

/// Tracks the peer HTTP/2 receive windows the MITM must respect when it emits
/// DATA the real sender didn't produce frame-for-frame, so it can pace that DATA
/// to the window instead of truncating it or overflowing into a
/// FLOW_CONTROL_ERROR. Two symmetric directions:
///
/// - **Client-bound**: the inbound leg observes the client's flow-control
///   signals (SETTINGS_INITIAL_WINDOW_SIZE, WINDOW_UPDATE) and paces synth
///   (`Anywhere.respond`) and buffered-rewrite RESPONSE bodies toward the
///   client; the outbound leg debits the shared client window for the real
///   server→client DATA it forwards.
/// - **Server-bound**: the outbound leg observes the server's flow-control
///   signals and paces buffered-rewrite REQUEST bodies toward the server; the
///   inbound leg debits the shared server window for the real client→server DATA
///   it forwards.
///
/// Shared by a session's two h2 legs, both running on the session's single
/// serial lwIP queue, so this needs no internal synchronization.
///
/// Only the **connection-level** windows and the cross-leg debt bookkeeping live
/// here (they are shared across legs/streams); per-stream windows live on the
/// ``MITMHTTP2Connection`` next to the buffered bodies they gate, mirroring the
/// RFC's stream-vs-connection split.
///
/// All windows are signed: a stream window legitimately goes negative when the
/// client lowers SETTINGS_INITIAL_WINDOW_SIZE while a stream is open (RFC 9113
/// §6.9.2), and the connection window goes negative whenever forwarded real
/// DATA outruns the WINDOW_UPDATEs we have observed so far — both cases simply
/// gate synth emission until a WINDOW_UPDATE brings the window positive again.
final class MITMHTTP2FlowController {

    /// The largest value a flow-control window may hold (RFC 9113 §6.9.1,
    /// 2^31 - 1). We clamp on credit so we never model an impossible window.
    static let maxWindow = 0x7FFF_FFFF

    /// Available connection-level window for client-bound DATA. RFC 9113
    /// §6.9.2: starts at 65,535 for every connection and is changed *only* by
    /// WINDOW_UPDATE — SETTINGS_INITIAL_WINDOW_SIZE does not affect it. Debited
    /// by every client-bound DATA byte from both legs (real forwarded +
    /// synthesized) and credited by the client's stream-0 WINDOW_UPDATEs, so it
    /// mirrors the client's own remaining connection window (held slightly
    /// conservative — we credit only when we observe the WINDOW_UPDATE).
    private(set) var connectionWindow: Int = 65_535

    /// The client's most recently advertised SETTINGS_INITIAL_WINDOW_SIZE
    /// (RFC 9113 §6.5.2, identifier 0x4). Initializes the per-stream window of
    /// each stream the MITM synthesizes toward the client. Default 65,535.
    private(set) var clientInitialStreamWindow: Int = 65_535

    /// Upstream (server) mirror of ``connectionWindow``: the available
    /// connection-level window for **server-bound** DATA the MITM sends (relayed
    /// request DATA plus paced buffered-rewrite request bodies). Starts at 65,535
    /// (RFC 9113 §6.9.2), debited by every server-bound DATA byte and credited by
    /// the server's stream-0 WINDOW_UPDATEs (observed on the outbound leg). Held
    /// slightly conservative — credited only when we observe the WINDOW_UPDATE —
    /// so a MITM-buffered request body can be paced against it instead of being
    /// dumped past the server's window into a FLOW_CONTROL_ERROR.
    private(set) var serverConnectionWindow: Int = 65_535

    /// Upstream mirror of ``clientInitialStreamWindow``: the server's most
    /// recently advertised SETTINGS_INITIAL_WINDOW_SIZE (observed on the outbound
    /// leg). Initializes the per-stream window of each request body the MITM
    /// paces toward the server. Default 65,535 until the server's SETTINGS says
    /// otherwise — the spec default a sender may use until it processes a
    /// reducing SETTINGS, after which the per-stream window simply goes negative
    /// and pacing waits for WINDOW_UPDATE (§6.9.2).
    private(set) var serverInitialStreamWindow: Int = 65_535

    /// Connection-level bytes the MITM has put toward the client that the
    /// upstream did **not** itself send on the wire, and that have not yet been
    /// withheld from a forwarded client→upstream connection WINDOW_UPDATE. Two
    /// sources feed it: synth DATA (request-phase `Anywhere.respond`) the
    /// upstream never sent at all, and the body the MITM emits toward the client
    /// after **buffering** a response for a rewrite rule (the upstream sent the
    /// original, possibly-compressed bytes; the client sees and credits the
    /// rewritten identity body — a different byte count it must not relay back
    /// to the upstream as-is). The client replenishes its connection window for
    /// everything it consumes, so forwarding those WINDOW_UPDATEs verbatim would
    /// over-grant the upstream's send window. ``withholdSynthDebt(from:)``
    /// subtracts this so the upstream is credited only for bytes it actually
    /// sent (the buffered stream's sender was instead credited directly while
    /// the body was held — see ``MITMHTTP2Connection.creditBufferedDataToSender``).
    private(set) var synthConnectionDebt: Int = 0

    /// The request-direction mirror of ``synthConnectionDebt``: connection-level
    /// bytes the MITM credited to the **client** directly while buffering a
    /// request for a rewrite rule (the client would otherwise stall at its
    /// initial window, since the upstream hasn't seen the held body and so
    /// sends no WINDOW_UPDATE to relay back). The upstream later credits the
    /// rewritten request it receives, and the outbound leg relays those
    /// upstream→client WINDOW_UPDATEs; ``withholdClientRequestDebt(from:)``
    /// subtracts this there so the client is not credited twice for the same
    /// logical bytes.
    private(set) var clientRequestConnectionDebt: Int = 0

    /// Debits the connection window by `n` client-bound DATA bytes (real or
    /// synth). May drive the window negative; that just gates synth emission.
    func debitConnection(_ n: Int) {
        connectionWindow -= n
    }

    /// Credits the connection window by a client stream-0 WINDOW_UPDATE
    /// increment, clamped to ``maxWindow``.
    func creditConnection(_ increment: Int) {
        connectionWindow = min(Self.maxWindow, connectionWindow &+ increment)
    }

    /// Debits the upstream connection window by `n` server-bound DATA bytes
    /// (relayed request DATA or a paced request body). May drive the window
    /// negative; that just gates paced request emission until a server
    /// WINDOW_UPDATE replenishes it.
    func debitServerConnection(_ n: Int) {
        serverConnectionWindow -= n
    }

    /// Credits the upstream connection window by a server stream-0 WINDOW_UPDATE
    /// increment, clamped to ``maxWindow``.
    func creditServerConnection(_ increment: Int) {
        serverConnectionWindow = min(Self.maxWindow, serverConnectionWindow &+ increment)
    }

    /// Records `n` client-bound connection-level DATA bytes for later
    /// compensation against the client→upstream WINDOW_UPDATE relay — synth
    /// DATA (post-establishment only; a pre-establishment one-shot never dials,
    /// so there is nothing to over-grant) or a buffered response body emitted
    /// to the client.
    func addSynthDebt(_ n: Int) {
        synthConnectionDebt += n
    }

    /// Records `n` connection-level bytes credited to the client while buffering
    /// a request, for later compensation against the upstream→client
    /// WINDOW_UPDATE relay (see ``clientRequestConnectionDebt``).
    func addClientRequestDebt(_ n: Int) {
        clientRequestConnectionDebt += n
    }

    /// Given an upstream connection-level WINDOW_UPDATE increment about to be
    /// relayed to the client, withholds the portion attributable to request
    /// bytes the MITM already credited the client for directly while buffering.
    /// Returns the increment to actually forward; `0` means **drop** the frame
    /// (a zero-increment WINDOW_UPDATE is a PROTOCOL_ERROR, RFC 9113 §6.9.1).
    func withholdClientRequestDebt(from increment: Int) -> Int {
        let withheld = min(increment, clientRequestConnectionDebt)
        clientRequestConnectionDebt -= withheld
        return increment - withheld
    }

    /// Given a client connection-level WINDOW_UPDATE increment about to be
    /// forwarded upstream, withholds the portion attributable to synth bytes
    /// the MITM injected. Returns the increment to actually forward; a result
    /// of `0` means the caller must **drop** the frame, since a zero-increment
    /// WINDOW_UPDATE is a PROTOCOL_ERROR (RFC 9113 §6.9.1).
    func withholdSynthDebt(from increment: Int) -> Int {
        let withheld = min(increment, synthConnectionDebt)
        synthConnectionDebt -= withheld
        return increment - withheld
    }

    /// Records a new client SETTINGS_INITIAL_WINDOW_SIZE and returns the delta
    /// `(new - old)` the caller must apply to every open synth stream window
    /// (RFC 9113 §6.9.2 retroactive adjustment). The delta may be negative.
    func updateInitialStreamWindow(_ newValue: Int) -> Int {
        // RFC 9113 §6.5.2: a SETTINGS_INITIAL_WINDOW_SIZE above 2^31-1 is a
        // FLOW_CONTROL_ERROR. The SETTINGS frame is forwarded verbatim, so the
        // real peer rejects an illegal value; clamp our own model too so synth
        // pacing never tracks an impossible window.
        let clamped = min(newValue, Self.maxWindow)
        let delta = clamped - clientInitialStreamWindow
        clientInitialStreamWindow = clamped
        return delta
    }

    /// Upstream mirror of ``updateInitialStreamWindow``: records a new server
    /// SETTINGS_INITIAL_WINDOW_SIZE and returns the delta `(new - old)` the
    /// caller applies to every open paced-request stream window (RFC 9113
    /// §6.9.2 retroactive adjustment). The delta may be negative.
    func updateServerInitialStreamWindow(_ newValue: Int) -> Int {
        let clamped = min(newValue, Self.maxWindow)
        let delta = clamped - serverInitialStreamWindow
        serverInitialStreamWindow = clamped
        return delta
    }
}
