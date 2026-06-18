//
//  VLESSVisionUDPStream.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "VLESSVisionUDPStream")

nonisolated class VLESSVisionUDPStream: MultiplexerStreamSink {
    let sessionID: UInt16
    let network: VLESSVisionUDPNetwork
    let targetHost: String
    let targetPort: UInt16
    weak var multiplexer: VLESSVisionUDPMultiplexer?
    private let globalID: Data?
    private var firstFrameSent: Bool
    private(set) var closed = false

    var dataHandler: ((Data) -> Void)?

    /// Non-nil error means the underlying mux connection died with a transport
    /// failure; nil means the stream ended cleanly (End frame / normal cancel).
    var closeHandler: ((Error?) -> Void)?

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

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        guard !closed else {
            completion(ProxyError.connectionFailed("Mux stream closed"))
            return
        }

        guard let multiplexer else {
            completion(ProxyError.connectionFailed("Mux multiplexer deallocated"))
            return
        }

        let isFirstFrame = !firstFrameSent
        if isFirstFrame {
            // Flip state before enqueueing the write so back-to-back packets do not
            // race into multiple SessionStatusNew frames.
            firstFrameSent = true
        }

        var metadata = VLESSVisionUDPFrameMetadata(
            sessionID: sessionID,
            status: isFirstFrame ? .new : .keep,
            option: .data,
            globalID: (isFirstFrame && network == .udp) ? globalID : nil
        )
        // For UDP Keep frames, include address
        if network == .udp {
            metadata.network = network
            metadata.targetHost = targetHost
            metadata.targetPort = targetPort
        }

        let frame = VLESSVisionUDPFrame.encode(metadata: metadata, payload: data)
        multiplexer.writeFrame(frame) { [weak self] error in
            if let error, isFirstFrame {
                // Allow retry: first frame never committed, so roll back.
                self?.firstFrameSent = false
                completion(error)
                return
            }
            completion(error)
        }
    }

    /// Closes this stream by sending an End frame.
    func close() {
        guard !closed else { return }
        closed = true

        if let multiplexer {
            let metadata = VLESSVisionUDPFrameMetadata(
                sessionID: sessionID,
                status: .end,
                option: []
            )
            let frame = VLESSVisionUDPFrame.encode(metadata: metadata, payload: nil)
            multiplexer.writeFrame(frame) { _ in }
            multiplexer.removeStream(sessionID)
        }

        closeHandler?(nil)
        dataHandler = nil
        closeHandler = nil
    }

    // MARK: - Called by VLESSVisionUDPMultiplexer (demux)

    func deliverData(_ data: Data) {
        guard !closed else { return }
        dataHandler?(data)
    }

    func deliverClose(error: Error? = nil) {
        guard !closed else { return }
        closed = true
        closeHandler?(error)
        dataHandler = nil
        closeHandler = nil
    }
}
