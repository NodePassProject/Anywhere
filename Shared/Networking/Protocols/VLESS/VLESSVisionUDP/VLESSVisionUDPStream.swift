//
//  VLESSVisionUDPStream.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "VLESSVisionUDPStream")

actor VLESSVisionUDPStream {
    nonisolated let sessionID: UInt16
    nonisolated let network: VLESSVisionUDPNetwork
    nonisolated let targetHost: String
    nonisolated let targetPort: UInt16
    private weak var multiplexer: VLESSVisionUDPMultiplexer?
    private nonisolated let globalID: Data?

    /// `firstFrameSent` is observed inside each chained send, so the first send builds the New
    /// frame and — on failure — rolls back before the next chained send runs.
    private var firstFrameSent: Bool
    /// Tail of this stream's send chain.
    private var sendTail: Task<Void, Error>?

    /// Closed once via EOF (clean End / cancel) or failure. Atomic because `deliverData`/
    /// `deliverClose` run from the mux's read loop while `send`/`close` run from the flow.
    private nonisolated let _closed = Atomic<Bool>(false)
    nonisolated var closed: Bool { _closed.load(ordering: .relaxed) }

    /// Inbound datagrams; EOF signals a clean End/close, a thrown error a transport failure.
    /// Single consumer; `Sendable` producer via `yield`/`finish`.
    private let inbox = AsyncInbox<Data>()

    init(
        sessionID: UInt16,
        network: VLESSVisionUDPNetwork,
        targetHost: String,
        targetPort: UInt16,
        globalID: Data? = nil,
        multiplexer: VLESSVisionUDPMultiplexer
    ) {
        self.sessionID = sessionID
        self.network = network
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.globalID = globalID
        self.firstFrameSent = globalID == nil
        self.multiplexer = multiplexer
    }

    // MARK: - Send

    func send(data: Data) async throws {
        guard !closed else {
            throw ProxyError.connectionFailed("Mux stream closed")
        }
        guard let multiplexer else {
            throw ProxyError.connectionFailed("Mux multiplexer deallocated")
        }
        let previous = sendTail
        let task = Task<Void, Error> { [weak self] in
            _ = try? await previous?.value
            guard let self else { throw ProxyError.connectionFailed("Mux stream closed") }
            try await self.buildAndSend(data: data, multiplexer: multiplexer)
        }
        sendTail = task
        try await task.value
    }

    /// Runs serialized on the send chain: exactly one send observes `firstFrameSent == false` and
    /// builds the SessionStatusNew frame, rolling back on a write failure so a retry re-sends it.
    private func buildAndSend(data: Data, multiplexer: VLESSVisionUDPMultiplexer) async throws {
        let isFirstFrame = !firstFrameSent
        if isFirstFrame {
            firstFrameSent = true
        }

        var metadata = VLESSVisionUDPFrameMetadata(
            sessionID: sessionID,
            status: isFirstFrame ? .new : .keep,
            option: .data,
            globalID: (isFirstFrame && network == .udp) ? globalID : nil
        )
        if network == .udp {
            metadata.network = network
            metadata.targetHost = targetHost
            metadata.targetPort = targetPort
        }

        let frame = VLESSVisionUDPFrame.encode(metadata: metadata, payload: data)
        do {
            try await multiplexer.writeFrame(frame)
        } catch {
            if isFirstFrame {
                firstFrameSent = false
            }
            throw error
        }
    }

    // MARK: - Receive (driven by the owning flow)

    func receive() async throws -> Data? {
        try await inbox.next()
    }

    // MARK: - Close

    nonisolated func close() {
        guard !_closed.exchange(true, ordering: .relaxed) else { return }
        inbox.finish()
        Task { await self.sendEndAndRemove() }
    }

    private func sendEndAndRemove() async {
        guard let multiplexer else { return }
        let metadata = VLESSVisionUDPFrameMetadata(
            sessionID: sessionID,
            status: .end,
            option: []
        )
        let frame = VLESSVisionUDPFrame.encode(metadata: metadata, payload: nil)
        // Fire-and-forget the End frame, then drop the stream from the mux.
        try? await multiplexer.writeFrame(frame)
        multiplexer.removeStream(sessionID)
    }

    // MARK: - Called by VLESSVisionUDPMultiplexer (demux, nonisolated)

    nonisolated func deliverData(_ data: Data) {
        guard !closed else { return }
        inbox.yield(data)
    }

    nonisolated func deliverClose(error: Error? = nil) {
        guard !_closed.exchange(true, ordering: .relaxed) else { return }
        if let error {
            inbox.finish(throwing: error)
        } else {
            inbox.finish()
        }
    }
}

extension VLESSVisionUDPStream: MultiplexerStreamSink {}
