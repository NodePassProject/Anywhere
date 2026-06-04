//
//  MITMMessageRewriter.swift
//  Anywhere
//
//  Created by NodePassProject on 6/4/26.
//

import Foundation

/// A per-direction MITM message rewriter. ``MITMHTTP1Stream`` (HTTP/1.1) and
/// ``MITMHTTP2Connection`` (HTTP/2) both conform, so ``MITMSession`` can shuttle
/// decrypted plaintext without branching on the negotiated protocol at every
/// step of its pumps. One instance handles one direction; the HTTP/2 connection
/// supersedes the always-present HTTP/1 stream for a direction once `h2` is
/// negotiated (``MITMSession`` selects via its `inbound` / `outbound`
/// accessors).
///
/// The contract is intentionally narrow — only what the session's pumps touch.
/// Both drains and ``resolvedUpstream`` live on the protocol even though each is
/// exercised on one direction only (client-bound synth + the resolved upstream
/// are read inbound; server-bound flow-control credit is drained outbound); the
/// unused side is a cheap, side-effect-free no-op so a single protocol serves
/// both directions.
protocol MITMMessageRewriter: AnyObject {

    /// Feeds decrypted plaintext from this direction's source leg. `completion`
    /// delivers the rewritten bytes for the destination leg and is invoked
    /// exactly once — inline when no script ran, or later on the lwIP queue from
    /// a parked script's resume.
    func feed(_ data: Data, completion: @escaping (Data) -> Void)

    /// Client-bound bytes this rewriter synthesized (a 302 / reject rewrite or a
    /// request-phase `Anywhere.respond`) and is holding for the inner leg.
    /// Drained right after each ``feed(_:completion:)``.
    func drainPendingClientBytes() -> Data

    /// Upstream-bound flow-control credit issued for a buffered body, so the
    /// server keeps sending while the body is held. HTTP/1 has no windowing and
    /// returns empty.
    func drainPendingServerBytes() -> Data

    /// The upstream a transparent rewrite resolved for the first request, or nil
    /// when none applied (the session falls back to the original destination).
    var resolvedUpstream: (host: String, port: UInt16?)? { get }
}
