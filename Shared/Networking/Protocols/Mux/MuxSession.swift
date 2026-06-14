//
//  MuxSession.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MuxSession")

nonisolated class MuxSession {
    let sessionID: UInt16
    let network: MuxNetwork
    let targetHost: String
    let targetPort: UInt16
    weak var client: MuxClient?
    private let globalID: Data?
    private var firstFrameSent: Bool
    private(set) var closed = false

    var dataHandler: ((Data) -> Void)?

    /// Non-nil error means the underlying mux connection died with a transport
    /// failure; nil means the session ended cleanly (End frame / normal cancel).
    var closeHandler: ((Error?) -> Void)?

    init(
        sessionID: UInt16,
        network: MuxNetwork,
        targetHost: String,
        targetPort: UInt16,
        globalID: Data? = nil,
        client: MuxClient
    ) {
        self.sessionID = sessionID
        self.network = network
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.globalID = globalID
        self.firstFrameSent = globalID == nil
        self.client = client
    }

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        guard !closed else {
            completion(ProxyError.connectionFailed("Mux session closed"))
            return
        }

        guard let client else {
            completion(ProxyError.connectionFailed("Mux client deallocated"))
            return
        }

        let isFirstFrame = !firstFrameSent
        if isFirstFrame {
            // Flip state before enqueueing the write so back-to-back packets do not
            // race into multiple SessionStatusNew frames.
            firstFrameSent = true
        }

        var metadata = MuxFrameMetadata(
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

        let frame = MuxFrame.encode(metadata: metadata, payload: data)
        client.writeFrame(frame) { [weak self] error in
            if let error, isFirstFrame {
                // Allow retry: first frame never committed, so roll back.
                self?.firstFrameSent = false
                completion(error)
                return
            }
            completion(error)
        }
    }

    /// Closes this session by sending an End frame.
    func close() {
        guard !closed else { return }
        closed = true

        if let client {
            let metadata = MuxFrameMetadata(
                sessionID: sessionID,
                status: .end,
                option: []
            )
            let frame = MuxFrame.encode(metadata: metadata, payload: nil)
            client.writeFrame(frame) { _ in }
            client.removeSession(sessionID)
        }

        closeHandler?(nil)
        dataHandler = nil
        closeHandler = nil
    }

    // MARK: - Called by MuxClient (demux)

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
