//
//  MITMRequestLog.swift
//  Anywhere
//
//  Created by NodePassProject on 5/14/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMRequestLog")

nonisolated final class MITMRequestLog: Sendable {

    struct Record {
        let method: String?
        let url: String?
        let originalUrl: String?
        /// Synthesized response bytes queued behind this record's upstream response to preserve pipeline order (RFC 9112 §9.3.2).
        var synthAfter: Data = Data()
    }

    private struct State {
        /// HTTP/1 FIFO; keeps request/response correlation correct if a client pipelines.
        var http1Queue: [Record] = []
        /// HTTP/2 stream → record map; RST_STREAM without a response leaves stale entries, so it's capped with oldest-ID eviction.
        var http2Streams: [UInt32: Record] = [:]
    }
    private let state = Mutex(State())

    /// Cap against push/pop imbalance; eviction only degrades ctx.method/ctx.url.
    private static let maxHTTP1Queue = 256

    /// Well above the spec-default SETTINGS_MAX_CONCURRENT_STREAMS (100) so live streams aren't evicted.
    private static let maxHTTP2Streams = 512

    /// Cap on per-record synthAfter so pipelined `Anywhere.respond` bursts can't
    /// exhaust memory; excess bytes are dropped with a warning.
    private static let maxSynthAfterBytes: Int = 1 * 1024 * 1024

    init() {}

    // MARK: - HTTP/1

    func recordHTTP1(method: String?, url: String?, originalUrl: String?) {
        state.withLock { s in
            if s.http1Queue.count >= Self.maxHTTP1Queue {
                s.http1Queue.removeFirst()
            }
            s.http1Queue.append(Record(method: method, url: url, originalUrl: originalUrl))
        }
    }

    func popHTTP1() -> Record? {
        state.withLock { s in
            guard !s.http1Queue.isEmpty else { return nil }
            return s.http1Queue.removeFirst()
        }
    }

    /// Peek for interim 1xx responses, which must not advance the queue; the final response pops.
    func peekHTTP1() -> Record? {
        state.withLock { $0.http1Queue.first }
    }

    /// Whether a synthesized response can be emitted immediately or must defer behind an in-flight response.
    var isHTTP1QueueEmpty: Bool {
        state.withLock { $0.http1Queue.isEmpty }
    }

    /// Outstanding h1 responses; checked before closing an upstream leg to reconnect to a different rewrite target.
    var http1InFlightCount: Int {
        state.withLock { $0.http1Queue.count }
    }

    /// Queues bytes behind the newest in-flight record; no-op when the queue is empty (caller emits immediately).
    func attachSynthAfterLastHTTP1(_ bytes: Data) {
        state.withLock { s in
            guard !s.http1Queue.isEmpty else { return }
            let index = s.http1Queue.count - 1
            let projected = s.http1Queue[index].synthAfter.count + bytes.count
            if projected > Self.maxSynthAfterBytes {
                logger.warning("synthAfter buffer would reach \(projected) B, over cap \(Self.maxSynthAfterBytes) B; dropping \(bytes.count) B of pipelined synth response")
                return
            }
            s.http1Queue[index].synthAfter.append(bytes)
        }
    }

    // MARK: - HTTP/2

    func recordHTTP2(streamID: UInt32, method: String?, url: String?, originalUrl: String?) {
        state.withLock { s in
            if s.http2Streams[streamID] == nil, s.http2Streams.count >= Self.maxHTTP2Streams,
               let oldest = s.http2Streams.keys.min() {
                s.http2Streams.removeValue(forKey: oldest)
            }
            s.http2Streams[streamID] = Record(method: method, url: url, originalUrl: originalUrl)
        }
    }

    func popHTTP2(streamID: UInt32) -> Record? {
        state.withLock { $0.http2Streams.removeValue(forKey: streamID) }
    }

    /// Peek for interim 1xx HEADERS, which must not consume the record; the final response pops.
    func peekHTTP2(streamID: UInt32) -> Record? {
        state.withLock { $0.http2Streams[streamID] }
    }
}
