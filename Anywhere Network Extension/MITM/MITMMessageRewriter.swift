//
//  MITMMessageRewriter.swift
//  Anywhere
//
//  Created by NodePassProject on 6/4/26.
//

import Foundation

/// HTTP/1.1 and HTTP/2 both conform so the session pumps plaintext without branching on protocol.
protocol MITMMessageRewriter: AnyObject {

    /// Feeds decrypted plaintext, returning the rewritten bytes. Suspends across a parked script hop;
    /// the implementation is lwIP-queue-confined, so callers await on their own executor.
    func feed(_ data: Data) async -> Data

    /// Client-bound bytes the rewriter synthesized and is holding for the inner leg; drained after each feed.
    func drainPendingClientBytes() -> Data

    /// Upstream-bound flow-control credit issued for a buffered body; empty for HTTP/1 (no windowing).
    func drainPendingServerBytes() -> Data

    /// The upstream a transparent rewrite resolved for the first request, or nil when none applied.
    var resolvedUpstream: (host: String, port: UInt16?)? { get }
}
