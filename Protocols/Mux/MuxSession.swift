//
//  MuxSession.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "MuxSession")

class MuxSession {
    let sessionID: UInt16
    let network: MuxNetwork
    let targetHost: String
    let targetPort: UInt16
    weak var client: MuxClient?
    private(set) var closed = false

    /// Called by MuxClient when demuxed data arrives for this session.
    var dataHandler: ((Data) -> Void)?

    /// Called by MuxClient when the session is closed (End frame received or connection error).
    var closeHandler: (() -> Void)?

    init(sessionID: UInt16, network: MuxNetwork, targetHost: String, targetPort: UInt16, client: MuxClient) {
        self.sessionID = sessionID
        self.network = network
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.client = client
    }

    /// Sends data through the mux connection as a Keep frame with payload.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        guard !closed else {
            completion(VLESSError.connectionFailed("Mux session closed"))
            return
        }

        guard let client else {
            completion(VLESSError.connectionFailed("Mux client deallocated"))
            return
        }

        var metadata = MuxFrameMetadata(
            sessionID: sessionID,
            status: .keep,
            option: .data
        )
        // For UDP Keep frames, include address (matching Xray-core writer.go)
        if network == .udp {
            metadata.network = network
            metadata.targetHost = targetHost
            metadata.targetPort = targetPort
        }

        let frame = encodeMuxFrame(metadata: metadata, payload: data)
        client.writeFrame(frame, completion: completion)
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
            let frame = encodeMuxFrame(metadata: metadata, payload: nil)
            client.writeFrame(frame) { _ in }
            client.removeSession(sessionID)
        }

        closeHandler?()
    }

    // MARK: - Called by MuxClient (demux)

    /// Delivers demuxed data to this session.
    func deliverData(_ data: Data) {
        guard !closed else { return }
        dataHandler?(data)
    }

    /// Delivers a close event to this session.
    func deliverClose() {
        guard !closed else { return }
        closed = true
        closeHandler?()
    }

    deinit {
        if !closed {
            // Best-effort End frame on dealloc
            client?.removeSession(sessionID)
        }
    }
}
