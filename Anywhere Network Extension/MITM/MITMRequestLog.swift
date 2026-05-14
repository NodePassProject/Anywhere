//
//  MITMRequestLog.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/14/26.
//

import Foundation

/// Per-``MITMSession`` cache of in-flight request method+URL so that
/// the response-phase script can populate `ctx.method` / `ctx.url` with
/// the originating request's values. Owned by the session, shared
/// across both HTTP/1 streams and the HTTP/2 rewriter.
///
/// Two independent stores live here because HTTP/1 and HTTP/2 use
/// different correlation keys. HTTP/1 has no per-request identifier on
/// the wire, so we rely on the order-of-arrival contract of the spec
/// (responses match requests in order) and use a FIFO. HTTP/2 streams
/// are correlated by stream ID, which is unique within a connection.
///
/// Not thread-safe. ``MITMSession`` serializes all access on its lwIP
/// queue.
final class MITMRequestLog {

    struct Record {
        let method: String?
        let url: String?
    }

    /// HTTP/1 pipeline. Request-stream pushes on each request head;
    /// response-stream pops on each response head. Concurrent
    /// requests on a single HTTP/1 connection are vanishingly rare in
    /// modern HTTPS, but a queue still keeps the mapping correct if a
    /// client does happen to pipeline.
    private var http1Queue: [Record] = []

    /// HTTP/2 stream → record map. Set by the inbound (request) leg on
    /// HEADERS, cleared by the outbound (response) leg on the matching
    /// HEADERS. A stream that closes without a response (RST_STREAM)
    /// leaves a stale entry — bounded by the connection lifetime, so
    /// not worth GC'ing here.
    private var http2Streams: [UInt32: Record] = [:]

    init() {}

    // MARK: - HTTP/1

    func recordHTTP1(method: String?, url: String?) {
        http1Queue.append(Record(method: method, url: url))
    }

    /// Returns the oldest unmatched request record and removes it,
    /// or nil when the queue is empty. Used at response-head time.
    func popHTTP1() -> Record? {
        guard !http1Queue.isEmpty else { return nil }
        return http1Queue.removeFirst()
    }

    /// Returns the oldest unmatched request record without removing
    /// it. Used by interim 1xx response heads (100 Continue, 103
    /// Early Hints) that need the originating request context for
    /// script ctx but mustn't consume the queue — the final response
    /// follows and is the one that should pop.
    func peekHTTP1() -> Record? {
        http1Queue.first
    }

    // MARK: - HTTP/2

    func recordHTTP2(streamID: UInt32, method: String?, url: String?) {
        http2Streams[streamID] = Record(method: method, url: url)
    }

    /// Returns and clears the record for ``streamID``, or nil when no
    /// request was logged for it.
    func popHTTP2(streamID: UInt32) -> Record? {
        http2Streams.removeValue(forKey: streamID)
    }

    /// Returns the record for ``streamID`` without removing it. Used
    /// by interim 1xx response HEADERS that need ``ctx.method`` /
    /// ``ctx.url`` for script context but mustn't consume the record —
    /// the matching final response follows on the same stream and is
    /// the one that should pop.
    func peekHTTP2(streamID: UInt32) -> Record? {
        http2Streams[streamID]
    }
}
