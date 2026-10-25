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
        let originalURL: String?
        var synthesizedAfter: Data = Data()
    }

    private struct State {
        var http1Queue: [Record] = []
        var isHTTP1ResponseOpen = false
        var http1OpenResponseSynthesizedAfter = Data()
        var http2Streams: [UInt32: Record] = [:]
    }
    private let state = Mutex(State())

    private static let maxHTTP1Queue = 256
    private static let maxHTTP2Streams = 512
    private static let maxSynthesizedAfterBytes: Int = 1 * 1024 * 1024

    init() {}

    // MARK: - HTTP/1

    func recordHTTP1(method: String?, url: String?, originalURL: String?) {
        state.withLock { state in
            if state.http1Queue.count >= Self.maxHTTP1Queue {
                state.http1Queue.removeFirst()
            }
            state.http1Queue.append(Record(method: method, url: url, originalURL: originalURL))
        }
    }

    func popHTTP1() -> Record? {
        state.withLock { state in
            guard !state.http1Queue.isEmpty else { return nil }
            state.isHTTP1ResponseOpen = true
            return state.http1Queue.removeFirst()
        }
    }

    func closeHTTP1Response() -> Data {
        state.withLock { state in
            state.isHTTP1ResponseOpen = false
            let bytes = state.http1OpenResponseSynthesizedAfter
            state.http1OpenResponseSynthesizedAfter = Data()
            return bytes
        }
    }

    func peekHTTP1() -> Record? {
        state.withLock { $0.http1Queue.first }
    }

    var isHTTP1QueueEmpty: Bool {
        state.withLock { $0.http1Queue.isEmpty && !$0.isHTTP1ResponseOpen }
    }

    var http1InFlightCount: Int {
        state.withLock { $0.http1Queue.count }
    }

    func attachSynthesizedAfterLastHTTP1(_ bytes: Data) {
        state.withLock { state in
            guard !state.http1Queue.isEmpty else {
                guard state.isHTTP1ResponseOpen else { return }
                let projected = state.http1OpenResponseSynthesizedAfter.count + bytes.count
                if projected > Self.maxSynthesizedAfterBytes {
                    logger.warning("[MITM] Synthesized response buffer full")
                    return
                }
                state.http1OpenResponseSynthesizedAfter.append(bytes)
                return
            }
            let index = state.http1Queue.count - 1
            let projected = state.http1Queue[index].synthesizedAfter.count + bytes.count
            if projected > Self.maxSynthesizedAfterBytes {
                logger.warning("[MITM] Synthesized response buffer full")
                return
            }
            state.http1Queue[index].synthesizedAfter.append(bytes)
        }
    }

    // MARK: - HTTP/2

    func recordHTTP2(streamID: UInt32, method: String?, url: String?, originalURL: String?) {
        state.withLock { state in
            if state.http2Streams[streamID] == nil, state.http2Streams.count >= Self.maxHTTP2Streams,
               let oldest = state.http2Streams.keys.min() {
                state.http2Streams.removeValue(forKey: oldest)
            }
            state.http2Streams[streamID] = Record(method: method, url: url, originalURL: originalURL)
        }
    }

    func popHTTP2(streamID: UInt32) -> Record? {
        state.withLock { $0.http2Streams.removeValue(forKey: streamID) }
    }

    func peekHTTP2(streamID: UInt32) -> Record? {
        state.withLock { $0.http2Streams[streamID] }
    }
}
