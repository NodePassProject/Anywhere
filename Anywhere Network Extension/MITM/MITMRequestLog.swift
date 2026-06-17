//
//  MITMRequestLog.swift
//  Anywhere
//
//  Created by NodePassProject on 5/14/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITMRequestLog")

/// Per-session cache of in-flight request method+URL for response-phase script context;
/// HTTP/1 uses a FIFO, HTTP/2 a stream-ID map. Not thread-safe — serialized on the lwIP queue.
final class MITMRequestLog {

    struct Record {
        let method: String?
        let url: String?
        /// Synthesized response bytes queued behind this record's upstream response to preserve pipeline order (RFC 9112 §9.3.2).
        var synthAfter: Data = Data()
    }

    /// HTTP/1 FIFO; keeps request/response correlation correct if a client pipelines.
    private var http1Queue: [Record] = []

    /// Cap against push/pop imbalance; eviction only degrades ctx.method/ctx.url.
    private static let maxHTTP1Queue = 256

    /// HTTP/2 stream → record map; RST_STREAM without a response leaves stale entries, so it's capped with oldest-ID eviction.
    private var http2Streams: [UInt32: Record] = [:]

    /// Well above the spec-default SETTINGS_MAX_CONCURRENT_STREAMS (100) so live streams aren't evicted.
    private static let maxHTTP2Streams = 512

    init() {}

    // MARK: - HTTP/1

    func recordHTTP1(method: String?, url: String?) {
        if http1Queue.count >= Self.maxHTTP1Queue {
            http1Queue.removeFirst()
        }
        http1Queue.append(Record(method: method, url: url))
    }

    func popHTTP1() -> Record? {
        guard !http1Queue.isEmpty else { return nil }
        return http1Queue.removeFirst()
    }

    /// Peek for interim 1xx responses, which must not advance the queue; the final response pops.
    func peekHTTP1() -> Record? {
        http1Queue.first
    }

    /// Whether a synthesized response can be emitted immediately or must defer behind an in-flight response.
    var isHTTP1QueueEmpty: Bool {
        http1Queue.isEmpty
    }

    /// Number of HTTP/1 requests recorded (emitted upstream) but not yet matched to a response head.
    /// The session reads this to decide whether an h1 upstream leg has outstanding responses before
    /// closing it to reconnect to a different transparent-rewrite target.
    var http1InFlightCount: Int {
        http1Queue.count
    }

    /// Cap on per-record synthAfter so pipelined `Anywhere.respond` bursts can't
    /// exhaust memory; excess bytes are dropped with a warning.
    private static let maxSynthAfterBytes: Int = 1 * 1024 * 1024

    /// Queues bytes behind the newest in-flight record; no-op when the queue is empty (caller emits immediately).
    func attachSynthAfterLastHTTP1(_ bytes: Data) {
        guard !http1Queue.isEmpty else { return }
        let idx = http1Queue.count - 1
        let projected = http1Queue[idx].synthAfter.count + bytes.count
        if projected > Self.maxSynthAfterBytes {
            logger.warning("synthAfter buffer would reach \(projected) B, over cap \(Self.maxSynthAfterBytes) B; dropping \(bytes.count) B of pipelined synth response")
            return
        }
        http1Queue[idx].synthAfter.append(bytes)
    }

    // MARK: - HTTP/2

    func recordHTTP2(streamID: UInt32, method: String?, url: String?) {
        if http2Streams[streamID] == nil, http2Streams.count >= Self.maxHTTP2Streams,
           let oldest = http2Streams.keys.min() {
            http2Streams.removeValue(forKey: oldest)
        }
        http2Streams[streamID] = Record(method: method, url: url)
    }

    func popHTTP2(streamID: UInt32) -> Record? {
        http2Streams.removeValue(forKey: streamID)
    }

    /// Peek for interim 1xx HEADERS, which must not consume the record; the final response pops.
    func peekHTTP2(streamID: UInt32) -> Record? {
        http2Streams[streamID]
    }
}
