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
    
    private var firstFrameSent: Bool
    
    private let sendChain = SerialSender()
    
    private nonisolated let _closed = Atomic<Bool>(false)
    nonisolated var closed: Bool { _closed.load(ordering: .relaxed) }
    
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
            throw AnywhereError.proxy(.vless, .connectionClosed(detail: "Mux stream closed"))
        }
        guard let multiplexer else {
            throw AnywhereError.proxy(.vless, .connectionClosed(detail: "Mux multiplexer deallocated"))
        }
        try await sendChain.run { [weak self] in
            guard let self else { throw AnywhereError.proxy(.vless, .connectionClosed(detail: "Mux stream closed")) }
            try await self.buildAndSend(data: data, multiplexer: multiplexer)
        }
    }
    
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
        sendChain.cancel()
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
        try? await multiplexer.writeFrame(frame)
        multiplexer.removeStream(sessionID)
    }

    // MARK: - Called by VLESSVisionUDPMultiplexer

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
