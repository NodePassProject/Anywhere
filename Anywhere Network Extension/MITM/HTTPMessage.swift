//
//  HTTPMessage.swift
//  Anywhere
//
//  Created by NodePassProject on 6/4/26.
//

import Foundation

/// The protocol-agnostic in-flight HTTP message the MITM rewrite path is built
/// around: the HTTP/1.1 and HTTP/2 rewriters parse the wire into it, the script
/// engine hands it to `function process(ctx)`, and the rewriters re-emit from
/// it. Keeping it independent of either wire format is what lets a single
/// rule / script pipeline serve both protocols.
///
/// Only `body` is read back from a script: scripts replace it or mutate it in
/// place (`ctx.body` is a Uint8Array backed by Swift-owned memory, so
/// element-wise writes propagate without a return value).
///
/// `method`, `url`, `status`, and `headers` are **read-only** (like `phase`):
/// a script may read them but assigning them is a no-op on readback. URL and
/// header edits have dedicated rule operations — `rewrite` and `header-add` /
/// `header-delete` / `header-replace` — so the script surface deliberately
/// doesn't duplicate them. This also lets the HTTP/2 path open a request stream
/// in stream-ID order without waiting on the script (see ``MITMHTTP2Connection``'s
/// early-open path) and makes request-line / header / URL injection from a rule
/// set structurally impossible.
///
/// `method` and `url` are populated on both request and response phases
/// (response carries the originating request's values, looked up via
/// ``MITMRequestLog``). `status` is populated on response only.
struct HTTPMessage {
    let phase: MITMPhase
    var method: String?
    var url: String?
    var status: Int?
    var headers: [(name: String, value: String)]
    var body: Data
    let ruleSetID: UUID?
}
