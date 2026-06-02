//
//  MITMRequestLog.swift
//  Anywhere
//
//  Created by NodePassProject on 5/14/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

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
        /// Bytes (a serialized response head + optional body) that the
        /// request stream synthesized via ``Anywhere.respond`` for a
        /// PIPELINED follow-on request while this record was the
        /// newest in-flight entry. They must be written to the client
        /// *after* the upstream response that matches this record so
        /// the client's pipeline-order assumption holds (RFC 9112
        /// §9.3.2: responses come back in the same order as requests).
        /// Drained by the response stream when the matching response
        /// body finishes streaming. See
        /// ``MITMRequestLog/attachSynthAfterLastHTTP1`` for the push
        /// side.
        var synthAfter: Data = Data()
    }

    /// HTTP/1 pipeline. Request-stream pushes on each request head;
    /// response-stream pops on each response head. Concurrent
    /// requests on a single HTTP/1 connection are vanishingly rare in
    /// modern HTTPS, but a queue still keeps the mapping correct if a
    /// client does happen to pipeline.
    private var http1Queue: [Record] = []

    /// HTTP/2 stream → record map. Set by the inbound (request) leg on
    /// HEADERS, cleared by the outbound (response) leg on the matching
    /// HEADERS. A stream that closes without a response (RST_STREAM) would
    /// leave a stale entry, so ``recordHTTP2`` caps the map at
    /// ``maxHTTP2Streams`` and evicts the oldest (lowest, monotonic) stream
    /// ID when full — otherwise a peer opening many unanswered streams
    /// (e.g. an HTTP/2 rapid-reset pattern) could grow it without bound for
    /// the connection's lifetime.
    private var http2Streams: [UInt32: Record] = [:]

    /// Upper bound on ``http2Streams``. Well above the spec-default
    /// SETTINGS_MAX_CONCURRENT_STREAMS (100) so a saturated connection
    /// doesn't evict records for streams still awaiting a response. Records
    /// are tiny (two optional strings), so the cap costs a few tens of KiB.
    private static let maxHTTP2Streams = 512

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

    /// True when no HTTP/1 requests are awaiting a response. The
    /// request stream uses this to decide whether a freshly
    /// synthesized response can go straight to the client (queue
    /// empty: no pipelined predecessor, emit now) or must be deferred
    /// behind an in-flight response (queue non-empty: attach to the
    /// newest record via ``attachSynthAfterLastHTTP1``).
    var isHTTP1QueueEmpty: Bool {
        http1Queue.isEmpty
    }

    /// Hard cap on per-record ``synthAfter`` accumulation. A chatty
    /// request script that fires ``Anywhere.respond`` against every
    /// pipelined request while one slow upstream response is still
    /// streaming would otherwise pile responses into a single record's
    /// ``synthAfter``, eating the Network Extension's memory budget.
    /// Past the cap, additional synth bytes are dropped with a warning
    /// rather than queued; the affected requests get no response on
    /// the wire, but every previously-queued synth still flushes
    /// cleanly when the head-of-queue response completes.
    private static let maxSynthAfterBytes: Int = 1 * 1024 * 1024

    /// Appends ``bytes`` to the ``synthAfter`` buffer on the most
    /// recently pushed HTTP/1 request record. Used when a request
    /// short-circuits via ``Anywhere.respond`` while earlier
    /// pipelined requests are still waiting on upstream responses —
    /// the synthesized bytes are held until the response stream
    /// finishes emitting that earlier request's response, preserving
    /// pipeline order. No-op when the queue is empty (callers in that
    /// case emit immediately via ``pendingClientBytes`` instead).
    func attachSynthAfterLastHTTP1(_ bytes: Data) {
        guard !http1Queue.isEmpty else { return }
        let idx = http1Queue.count - 1
        let projected = http1Queue[idx].synthAfter.count + bytes.count
        if projected > Self.maxSynthAfterBytes {
            // Drop with a warning rather than crashing the NE. The
            // session that owns this log is already at risk of
            // running out of memory; a partial pipeline result is
            // strictly better than an OOM kill that takes down
            // every other tunneled session.
            logger.warning("[MITM] synthAfter buffer would reach \(projected) B, over cap \(Self.maxSynthAfterBytes) B; dropping \(bytes.count) B of pipelined synth response")
            return
        }
        http1Queue[idx].synthAfter.append(bytes)
    }

    // MARK: - HTTP/2

    func recordHTTP2(streamID: UInt32, method: String?, url: String?) {
        if http2Streams[streamID] == nil, http2Streams.count >= Self.maxHTTP2Streams,
           let oldest = http2Streams.keys.min() {
            // Evict the oldest tracked stream rather than grow unbounded.
            // Losing its record only degrades a later response's script
            // ctx.method/ctx.url to nil — never a crash.
            http2Streams.removeValue(forKey: oldest)
        }
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
