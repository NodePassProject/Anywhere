//
//  MITMMessageRewriter.swift
//  Anywhere
//
//  Created by NodePassProject on 6/4/26.
//

import Foundation

/// A per-direction MITM message rewriter; HTTP/1.1 and HTTP/2 both conform so the
/// session pumps plaintext without branching on the negotiated protocol.
protocol MITMMessageRewriter: AnyObject {

    /// Feeds decrypted plaintext. `completion` is invoked exactly once — inline when
    /// no script ran, or later on the lwIP queue when a parked script resumes.
    func feed(_ data: Data, completion: @escaping (Data) -> Void)

    /// Client-bound bytes the rewriter synthesized and is holding for the inner leg; drained after each feed.
    func drainPendingClientBytes() -> Data

    /// Upstream-bound flow-control credit issued for a buffered body; empty for HTTP/1 (no windowing).
    func drainPendingServerBytes() -> Data

    /// The upstream a transparent rewrite resolved for the first request, or nil when none applied.
    var resolvedUpstream: (host: String, port: UInt16?)? { get }
}
