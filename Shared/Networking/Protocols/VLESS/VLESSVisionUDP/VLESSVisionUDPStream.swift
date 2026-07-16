//
//  VLESSVisionUDPStream.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "VLESSVisionUDPStream")

nonisolated class VLESSVisionUDPStream: MultiplexerStreamSink {
    let sessionID: UInt16
    let network: VLESSVisionUDPNetwork
    let targetHost: String
    let targetPort: UInt16
    weak var multiplexer: VLESSVisionUDPMultiplexer?
    private let globalID: Data?

    /// Serializes this stream's sends so the SessionStatusNew frame (first send) always
    /// lands — and completes on the wire — before any SessionStatusKeep frame, even when
    /// the flow drives sends from concurrent tasks. `firstFrameSent` is only touched here.
    private let sendMutex = AsyncMutex()
    private var firstFrameSent: Bool

    /// Closed once via EOF (clean End / cancel) or failure. Atomic because `deliverData`/
    /// `deliverClose` run from the mux's read loop while `send`/`close` run from the flow.
    private let _closed = Atomic<Bool>(false)
    var closed: Bool { _closed.load(ordering: .relaxed) }

    /// Inbound datagrams; EOF signals a clean End/close, a thrown error a transport failure.
    /// Replaces the old `dataHandler`/`closeHandler` callbacks.
    let inbox = AsyncByteChannel()

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

    func send(data: Data) async throws {
        guard !closed else {
            throw ProxyError.connectionFailed("Mux stream closed")
        }
        guard let multiplexer else {
            throw ProxyError.connectionFailed("Mux multiplexer deallocated")
        }

        try await sendMutex.withLock {
            // Serialized: exactly one send observes `firstFrameSent == false` and builds the
            // SessionStatusNew frame; it holds the mutex across the write so the New frame
            // reaches the wire before the next send's Keep frame.
            let isFirstFrame = !self.firstFrameSent
            if isFirstFrame {
                self.firstFrameSent = true
            }

            var metadata = VLESSVisionUDPFrameMetadata(
                sessionID: self.sessionID,
                status: isFirstFrame ? .new : .keep,
                option: .data,
                globalID: (isFirstFrame && self.network == .udp) ? self.globalID : nil
            )
            if self.network == .udp {
                metadata.network = self.network
                metadata.targetHost = self.targetHost
                metadata.targetPort = self.targetPort
            }

            let frame = VLESSVisionUDPFrame.encode(metadata: metadata, payload: data)
            do {
                try await multiplexer.writeFrame(frame)
            } catch {
                if isFirstFrame {
                    // Allow retry: first frame never committed, so roll back.
                    self.firstFrameSent = false
                }
                throw error
            }
        }
    }

    func close() {
        guard !_closed.exchange(true, ordering: .relaxed) else { return }

        if let multiplexer {
            let metadata = VLESSVisionUDPFrameMetadata(
                sessionID: sessionID,
                status: .end,
                option: []
            )
            let frame = VLESSVisionUDPFrame.encode(metadata: metadata, payload: nil)
            let sid = sessionID
            // Fire-and-forget the End frame, then drop the stream from the mux.
            Task {
                try? await multiplexer.writeFrame(frame)
                multiplexer.removeStream(sid)
            }
        }

        inbox.finish()
    }

    // MARK: - Called by VLESSVisionUDPMultiplexer (demux)

    func deliverData(_ data: Data) {
        guard !closed else { return }
        inbox.yield(data)
    }

    func deliverClose(error: Error? = nil) {
        guard !_closed.exchange(true, ordering: .relaxed) else { return }
        if let error {
            inbox.fail(error)
        } else {
            inbox.finish()
        }
    }
}
