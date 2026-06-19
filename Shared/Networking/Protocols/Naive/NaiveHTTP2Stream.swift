//
//  NaiveHTTP2Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 3/18/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP2Stream")

/// A single CONNECT tunnel multiplexed on an HTTP/2 multiplexer, with its own flow-control
/// window; response headers are exposed so the proxy layer can run its own negotiation.
nonisolated class NaiveHTTP2Stream: HTTPTunnel {

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

    private weak var multiplexer: NaiveHTTP2Multiplexer?

    private var state: StreamState = .idle

    // Per-stream flow control (send side)
    private(set) var sendWindow: Int

    // Per-stream flow control (receive side)
    private var recvConsumed: Int = 0
    private var recvWindowSize: Int = NaiveHTTP2FlowControl.naiveInitialWindowSize

    // Receive buffering — data delivered by the multiplexer's read loop
    private var receiveQueue: [Data] = []
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var endStreamReceived = false
    private var streamError: Error?

    private var connectCompletion: ((Error?) -> Void)?

    /// CONNECT response headers exposed for proxy-layer negotiation.
    private(set) var responseHeaders: [(name: String, value: String)] = []

    var isConnected: Bool { state == .open }

    // MARK: - Init

    init(streamID: UInt32, multiplexer: NaiveHTTP2Multiplexer, destination: String) {
        self.streamID = streamID
        self.multiplexer = multiplexer
        self.destination = destination
        self.sendWindow = NaiveHTTP2FlowControl.defaultInitialWindowSize
    }

    // MARK: - HTTPTunnel

    func openTunnel(completion: @escaping (Error?) -> Void) {
        guard let multiplexer else {
            completion(NaiveHTTP2Error.notReady)
            return
        }

        multiplexer.queue.async { [self] in
            multiplexer.ensureReady { [weak self] error in
                guard let self, let multiplexer = self.multiplexer else { return }
                // ensureReady completion fires on multiplexer.queue
                if let error {
                    self.state = .closed
                    completion(error)
                    return
                }

                // Adopt the peer's initial window size for this new stream
                self.sendWindow = multiplexer.peerInitialWindowSize

                self.connectCompletion = completion
                self.state = .connectSent

                multiplexer.sendConnect(stream: self) { [weak self] error in
                    guard let self, let multiplexer = self.multiplexer else { return }
                    multiplexer.queue.async {
                        if let error {
                            self.state = .closed
                            let cb = self.connectCompletion
                            self.connectCompletion = nil
                            multiplexer.removeStream(self)
                            cb?(error)
                        }
                    }
                }
            }
        }
    }

    func sendData(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard let multiplexer else {
            completion(NaiveHTTP2Error.notReady)
            return
        }
        multiplexer.queue.async { [self] in
            guard state == .open else {
                completion(NaiveHTTP2Error.notReady)
                return
            }
            multiplexer.sendData(data, on: self, completion: completion)
        }
    }

    func receiveData(completion: @escaping (Data?, Error?) -> Void) {
        guard let multiplexer else {
            completion(nil, NaiveHTTP2Error.notReady)
            return
        }
        multiplexer.queue.async { [self] in
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
                completion(nil, NaiveHTTP2Error.notReady)
                return
            }

            pendingReceive = completion
        }
    }

    func close() {
        guard let multiplexer else { return }
        multiplexer.queue.async { [self] in
            guard state != .closed else { return }
            let needsRst = (state == .open || state == .connectSent)
            state = .closed
            multiplexer.removeStream(self)

            // Inform the peer so it can reclaim its stream slot.
            if needsRst {
                multiplexer.sendControlFrame(
                    NaiveHTTP2Framer.rstStreamFrame(streamID: streamID, errorCode: 0x8 /* CANCEL */)
                )
            }

            if let cb = connectCompletion {
                connectCompletion = nil
                cb(NaiveHTTP2Error.connectionFailed("Stream closed"))
            }
            if let pending = pendingReceive {
                pendingReceive = nil
                pending(nil, NaiveHTTP2Error.connectionFailed("Stream closed"))
            }
        }
    }

    // MARK: - Session Callbacks (called on multiplexer.queue)

    func handleHeaders(_ frame: NaiveHTTP2Frame) {
        guard let multiplexer, let decoded = multiplexer.hpackDecoder.decodeHeaders(from: frame.payload) else {
            handleStreamError(NaiveHTTP2Error.protocolError("Failed to decode headers on stream \(streamID)"))
            return
        }
        // No re-encode/forwarding here, so the never-indexed marker can be ignored.
        let headers = decoded.fields

        guard let statusHeader = headers.first(where: { $0.name == ":status" }) else {
            handleStreamError(NaiveHTTP2Error.protocolError("Missing :status on stream \(streamID)"))
            return
        }

        let status = statusHeader.value

        if state == .connectSent {
            if status == "200" {
                responseHeaders = headers
                state = .open
                let cb = connectCompletion
                connectCompletion = nil
                cb?(nil)
            } else if status == "407" {
                handleStreamError(NaiveHTTP2Error.authenticationRequired)
            } else {
                handleStreamError(NaiveHTTP2Error.tunnelFailed(statusCode: status))
            }
        }
    }

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
                multiplexer?.removeStream(self)
                pending(nil, nil)  // EOF
            }
            // Empty DATA without END_STREAM: keep waiting
        } else if !payload.isEmpty {
            receiveQueue.append(payload)
        } else if endStream && receiveQueue.isEmpty {
            state = .closed
            multiplexer?.removeStream(self)
        }

        // END_STREAM: free the multiplexer slot now even if buffered data remains unread.
        if endStream && state != .closed {
            multiplexer?.removeStream(self)
        }
    }

    func handleReset(errorCode: UInt32) {
        if errorCode == 0x0 /* NO_ERROR */ || errorCode == 0x8 /* CANCEL */ {
            handleData(Data(), endStream: true)
            return
        }
        handleStreamError(NaiveHTTP2Error.streamReset(streamID))
    }

    func handleSessionError(_ error: Error) {
        handleStreamError(error)
    }

    private func handleStreamError(_ error: Error) {
        guard state != .closed else { return }
        state = .closed
        streamError = error
        multiplexer?.removeStream(self)

        if let cb = connectCompletion {
            connectCompletion = nil
            cb(error)
        }
        if let pending = pendingReceive {
            pendingReceive = nil
            pending(nil, error)
        }
    }

    // MARK: - Flow Control (called by multiplexer on multiplexer.queue)

    /// Opens per-stream and connection receive windows for data the consumer actually read.
    private func acknowledgeConsumedData(count: Int) {
        recvConsumed += count
        if recvConsumed >= recvWindowSize / 2 {
            let increment = UInt32(recvConsumed)
            recvConsumed = 0
            multiplexer?.sendControlFrame(
                NaiveHTTP2Framer.windowUpdateFrame(streamID: streamID, increment: increment)
            )
        }
        multiplexer?.acknowledgeReceivedData(count: count)
    }

    func consumeSendWindow(_ bytes: Int) {
        sendWindow -= bytes
    }

    func adjustSendWindow(delta: Int) {
        sendWindow += delta
    }
}
