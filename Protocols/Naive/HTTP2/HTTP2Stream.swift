//
//  HTTP2Stream.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/18/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "HTTP2Stream")

/// A single CONNECT tunnel multiplexed on an ``HTTP2Session``.
///
/// Conforms to ``NaiveTunnel`` so it can be wrapped by ``NaiveProxyConnection``
/// identically to the old single-stream ``HTTP2Connection``.  Each stream has
/// its own flow-control window and padding negotiation, matching NaiveProxy's
/// per-stream `NaivePaddingSocket` architecture.
class HTTP2Stream: NaiveTunnel {

    // MARK: - State

    enum StreamState {
        case idle
        /// CONNECT HEADERS sent, waiting for response.
        case connectSent
        /// 200 received, data can flow.
        case open
        case closed
    }

    // MARK: - Properties

    let streamID: UInt32
    let destination: String

    private weak var session: HTTP2Session?
    private let configuration: NaiveConfiguration

    private var state: StreamState = .idle

    // Per-stream flow control (send side)
    private(set) var sendWindow: Int

    // Per-stream flow control (receive side)
    private var recvConsumed: Int = 0
    private var recvWindowSize: Int = HTTP2FlowControl.naiveInitialWindowSize

    // Receive buffering — data delivered by the session's read loop
    private var receiveQueue: [Data] = []
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var endStreamReceived = false
    private var streamError: Error?

    // CONNECT handshake callback
    private var connectCompletion: ((Error?) -> Void)?

    // Padding (negotiated per-stream via CONNECT response headers)
    private(set) var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType = .none

    var isConnected: Bool { state == .open }

    // MARK: - Init

    init(streamID: UInt32, session: HTTP2Session, configuration: NaiveConfiguration,
         destination: String) {
        self.streamID = streamID
        self.session = session
        self.configuration = configuration
        self.destination = destination
        self.sendWindow = HTTP2FlowControl.defaultInitialWindowSize
    }

    // MARK: - NaiveTunnel

    func openTunnel(completion: @escaping (Error?) -> Void) {
        guard let session else {
            completion(HTTP2Error.notReady)
            return
        }

        session.queue.async { [self] in
            session.ensureReady { [weak self] error in
                guard let self, let session = self.session else { return }
                // ensureReady completion fires on session.queue
                if let error {
                    self.state = .closed
                    completion(error)
                    return
                }

                // Adopt the peer's initial window size for this new stream
                self.sendWindow = session.peerInitialWindowSize

                self.connectCompletion = completion
                self.state = .connectSent

                session.sendConnect(stream: self) { [weak self] error in
                    guard let self, let session = self.session else { return }
                    session.queue.async {
                        if let error {
                            self.state = .closed
                            let cb = self.connectCompletion
                            self.connectCompletion = nil
                            session.removeStream(self)
                            cb?(error)
                        }
                    }
                }
            }
        }
    }

    func sendData(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard let session else {
            completion(HTTP2Error.notReady)
            return
        }
        session.queue.async { [self] in
            guard state == .open else {
                completion(HTTP2Error.notReady)
                return
            }
            session.sendData(data, on: self, completion: completion)
        }
    }

    func receiveData(completion: @escaping (Data?, Error?) -> Void) {
        guard let session else {
            completion(nil, HTTP2Error.notReady)
            return
        }
        session.queue.async { [self] in
            if let error = streamError {
                completion(nil, error)
                return
            }

            if !receiveQueue.isEmpty {
                let data = receiveQueue.removeFirst()
                self.acknowledgeConsumedData(count: data.count)
                completion(data, nil)
                return
            }

            if endStreamReceived {
                state = .closed
                completion(nil, nil)  // EOF
                return
            }

            guard state == .open else {
                completion(nil, HTTP2Error.notReady)
                return
            }

            pendingReceive = completion
        }
    }

    func close() {
        guard let session else { return }
        session.queue.async { [self] in
            guard state != .closed else { return }
            let needsRst = (state == .open || state == .connectSent)
            state = .closed
            session.removeStream(self)

            // Inform the peer so it can reclaim its stream slot.
            if needsRst {
                session.sendControlFrame(
                    HTTP2Framer.rstStreamFrame(streamID: streamID, errorCode: 0x8 /* CANCEL */)
                )
            }

            if let cb = connectCompletion {
                connectCompletion = nil
                cb(HTTP2Error.connectionFailed("Stream closed"))
            }
            if let pending = pendingReceive {
                pendingReceive = nil
                pending(nil, HTTP2Error.connectionFailed("Stream closed"))
            }
        }
    }

    // MARK: - Session Callbacks (called on session.queue)

    /// Handles a HEADERS frame routed to this stream by the session.
    func handleHeaders(_ frame: HTTP2Frame) {
        guard let session, let headers = session.hpackDecoder.decodeHeaders(from: frame.payload) else {
            handleStreamError(HTTP2Error.protocolError("Failed to decode headers on stream \(streamID)"))
            return
        }

        guard let statusHeader = headers.first(where: { $0.name == ":status" }) else {
            handleStreamError(HTTP2Error.protocolError("Missing :status on stream \(streamID)"))
            return
        }

        let status = statusHeader.value

        if state == .connectSent {
            if status == "200" {
                negotiatedPaddingType = NaivePaddingNegotiator.parseResponse(headers: headers)
                state = .open
                let cb = connectCompletion
                connectCompletion = nil
                cb?(nil)
            } else if status == "407" {
                logger.error("[HTTP2Stream] Proxy authentication required (407) on stream \(self.streamID)")
                handleStreamError(HTTP2Error.authenticationRequired)
            } else {
                logger.error("[HTTP2Stream] CONNECT failed with status \(status, privacy: .public) on stream \(self.streamID)")
                handleStreamError(HTTP2Error.tunnelFailed(statusCode: status))
            }
        }
    }

    /// Handles a DATA frame payload routed to this stream by the session.
    func handleData(_ payload: Data, endStream: Bool) {
        if endStream {
            endStreamReceived = true
        }

        if let pending = pendingReceive {
            if !payload.isEmpty {
                pendingReceive = nil
                acknowledgeConsumedData(count: payload.count)
                pending(payload, nil)
            } else if endStream {
                pendingReceive = nil
                state = .closed
                session?.removeStream(self)
                pending(nil, nil)  // EOF
            }
            // Empty DATA without END_STREAM: keep waiting
        } else if !payload.isEmpty {
            receiveQueue.append(payload)
        } else if endStream && receiveQueue.isEmpty {
            state = .closed
            session?.removeStream(self)
        }

        // No more frames will arrive; free the session slot now even if
        // buffered data still needs to be consumed by receiveData().
        if endStream && state != .closed {
            session?.removeStream(self)
        }
    }

    /// Handles RST_STREAM for this stream.
    func handleReset(errorCode: UInt32) {
        logger.error("[HTTP2Stream] Stream \(self.streamID) reset: errorCode=\(errorCode)")
        handleStreamError(HTTP2Error.streamReset(streamID))
    }

    /// Handles session-level errors (GOAWAY, transport failure).
    func handleSessionError(_ error: Error) {
        handleStreamError(error)
    }

    private func handleStreamError(_ error: Error) {
        guard state != .closed else { return }
        state = .closed
        streamError = error
        session?.removeStream(self)

        if let cb = connectCompletion {
            connectCompletion = nil
            cb(error)
        }
        if let pending = pendingReceive {
            pendingReceive = nil
            pending(nil, error)
        }
    }

    // MARK: - Flow Control (called by session on session.queue)

    /// Acknowledges data the consumer has actually read, opening per-stream
    /// and connection-level receive windows. Must be called on `session.queue`.
    private func acknowledgeConsumedData(count: Int) {
        recvConsumed += count
        if recvConsumed >= recvWindowSize / 2 {
            let increment = UInt32(recvConsumed)
            recvConsumed = 0
            session?.sendControlFrame(
                HTTP2Framer.windowUpdateFrame(streamID: streamID, increment: increment)
            )
        }
        session?.acknowledgeReceivedData(count: count)
    }

    func consumeSendWindow(_ bytes: Int) {
        sendWindow -= bytes
    }

    func adjustSendWindow(delta: Int) {
        sendWindow += delta
    }
}
