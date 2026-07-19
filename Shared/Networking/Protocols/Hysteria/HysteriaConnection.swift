//
//  HysteriaConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "HysteriaConnection")

actor HysteriaConnection {

    private let session: HysteriaSession
    private let destination: String

    /// Readiness mirror, so the nonisolated `isConnected`/send-guard read it without hopping.
    private nonisolated let _isReady = Atomic<Bool>(false)
    /// Assigned once in `open()`, read from the send/receive/cancel paths.
    private nonisolated let _streamID = Atomic<Int64>(-1)

    /// Inbound stream bytes from the demux. The producer (`yield`/`finish`) is `Sendable` and driven
    /// on the ngtcp2 queue via `feedStreamData`; a single consumer pulls via `open()` (header) then
    /// `receiveRaw()` (data), never concurrently.
    private let rawInbox = AsyncInbox<Data>()
    /// Post-header bytes left over from `open()`'s parse, handed to the app first by `receiveRaw()`.
    private var pendingData = Data()

    /// Guards `teardown()` so the stream is shut down and released exactly once.
    private var closed = false

    init(session: HysteriaSession, destination: String) {
        self.session = session
        self.destination = destination
    }

    nonisolated var isConnected: Bool { _isReady.load(ordering: .relaxed) }
    nonisolated var outerTLSVersion: TLSVersion? { .tls13 }

    private var streamID: Int64 {
        get { _streamID.load(ordering: .relaxed) }
        set { _streamID.store(newValue, ordering: .relaxed) }
    }

    // MARK: - Open (called by ProxyClient after the session is ready)

    func open() async throws {
        let sid = try await session.openTCPStream(for: self)
        streamID = sid
        let frame = HysteriaProtocol.encodeTCPRequest(address: destination)
        try await session.writeStream(sid, data: frame)

        // Read inbound bytes until the Hysteria TCP response header parses (or the stream ends/fails).
        var buffer = Data()
        while true {
            guard let chunk = try await nextChunk() else {
                throw AnywhereError.proxy(.hysteria, .connectionClosed(detail: "Stream closed before response"))
            }
            buffer.append(chunk)
            guard let parsed = HysteriaProtocol.parseTCPResponse(from: buffer) else { continue }
            // Credit the consumed header now (small, bounded); post-header bytes are credited
            // lazily in `receiveRaw` as the app consumes them.
            if parsed.consumed > 0 { session.extendStreamOffset(sid, count: parsed.consumed) }
            guard parsed.status == HysteriaProtocol.tcpResponseStatusOK else {
                throw AnywhereError.proxy(.hysteria, .tunnelRejected(detail: parsed.message))
            }
            buffer.removeFirst(parsed.consumed)
            pendingData = buffer
            _isReady.store(true, ordering: .relaxed)
            return
        }
    }

    // MARK: - Demux feed (nonisolated; driven on the ngtcp2 queue)

    /// New inbound bytes / FIN from the session's demux loop. `data` is a zero-copy view into
    /// ngtcp2's buffer — detach with `Data(...)` before buffering it.
    nonisolated func feedStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty { rawInbox.yield(Data(data)) }
        if fin { rawInbox.finish() }
    }

    /// QUIC stream termination (RESET_STREAM or stream_close). Idempotent — finishing an
    /// already-finished stream is a no-op, so both callbacks firing is harmless.
    nonisolated func handleStreamTermination(error: Error?) {
        if let error { rawInbox.finish(throwing: error) } else { rawInbox.finish() }
    }

    nonisolated func handleSessionError(_ error: Error) {
        _isReady.store(false, ordering: .relaxed)
        if case AnywhereError.quic(.closed(graceful: true)) = error {
            rawInbox.finish()
        } else {
            rawInbox.finish(throwing: error)
        }
    }

    // MARK: - ProxyConnection overrides

    func sendRaw(_ data: Data) async throws {
        guard _isReady.load(ordering: .relaxed) else {
            throw AnywhereError.proxy(.hysteria, .streamClosed)
        }
        try await session.writeStream(streamID, data: data)
    }

    func receiveRaw() async throws -> Data? {
        if !pendingData.isEmpty {
            let out = pendingData
            pendingData = Data()
            session.extendStreamOffset(streamID, count: out.count)
            return out
        }
        guard let chunk = try await nextChunk() else { return nil }
        if !chunk.isEmpty {
            // Return stream flow-control credit only now the app has taken the bytes.
            session.extendStreamOffset(streamID, count: chunk.count)
        }
        return chunk
    }

    /// Single-consumer pull over `rawInbox`. Drains the whole backlog per call and hands the
    /// app one merged chunk — one wake-up and one flow-control credit per burst, and bigger
    /// chunks for the downstream relay, instead of a full cycle per QUIC stream frame.
    private func nextChunk() async throws -> Data? {
        guard let batch = try await rawInbox.nextBatch() else { return nil }
        guard batch.count > 1 else { return batch.first }
        var merged = batch[0]
        merged.reserveCapacity(batch.reduce(0) { $0 + $1.count })
        for chunk in batch.dropFirst() { merged.append(chunk) }
        return merged
    }

    nonisolated func cancel() {
        _isReady.store(false, ordering: .relaxed)
        rawInbox.finish()
        Task { await self.teardown() }
    }

    private func teardown() {
        guard !closed else { return }
        closed = true
        let sid = _streamID.load(ordering: .relaxed)
        if sid >= 0 {
            session.shutdownStream(sid)
            session.releaseTCPStream(sid)
        }
    }
}

extension HysteriaConnection: ProxyConnection {}
