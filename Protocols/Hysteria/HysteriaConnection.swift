//
//  HysteriaConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation

private let logger = AnywhereLogger(category: "Hysteria")

// MARK: - HysteriaConnection (TCP)

/// ProxyConnection subclass for Hysteria TCP proxy streams.
///
/// On the first write, sends the TCPRequest framing (address + padding).
/// On the first read, parses the TCPResponse (status + message + padding).
/// After the handshake, data flows bidirectionally as raw bytes.
///
/// All mutable state is serialized on `queue` (the HysteriaClient's queue,
/// which is also where `handleStreamData` is called from).
class HysteriaConnection: ProxyConnection {
    private let quic: QUICConnection
    private let streamId: Int64
    private let address: String
    private weak var owner: HysteriaClient?

    /// Whether the TCPResponse has been parsed.
    private var responseReceived = false

    private var receiveBuffer = Data()
    private var pendingReceiveCompletion: ((Data?, Error?) -> Void)?
    private var pendingQuicBytes = 0
    private var streamClosed = false

    /// Serialization queue — must be the same queue that `handleStreamData`
    /// is called on (i.e. HysteriaClient's queue).
    let queue: DispatchQueue

    init(quic: QUICConnection, streamId: Int64, address: String, queue: DispatchQueue, owner: HysteriaClient) {
        self.quic = quic
        self.streamId = streamId
        self.address = address
        self.queue = queue
        self.owner = owner
        super.init()
        self.responseHeaderReceived = true // No VLESS header to strip
    }

    override var isConnected: Bool { !streamClosed }
    override var outerTLSVersion: TLSVersion? { .tls13 }

    // MARK: - Stream Data Handler

    /// Called by HysteriaClient on `queue` when data arrives on this stream.
    func handleStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty {
            pendingQuicBytes += data.count
            receiveBuffer.append(data)
        }

        if fin {
            streamClosed = true
        }

        // Try to deliver data
        deliverPendingData()
    }

    // MARK: - Send

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else {
                completion(QUICConnection.QUICError.closed)
                return
            }
            self.quic.writeStream(self.streamId, data: data, completion: completion)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { _ in }
    }

    // MARK: - Receive

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else {
                completion(nil, nil)
                return
            }

            if !self.responseReceived {
                if let (ok, message, consumed) = HysteriaTCPFraming.parseTCPResponse(self.receiveBuffer) {
                    self.responseReceived = true
                    self.receiveBuffer = Data(self.receiveBuffer.dropFirst(consumed))
                    self.ackConsumedBytes()

                    if !ok {
                        completion(nil, HysteriaClient.HysteriaError.connectionFailed(message))
                        return
                    }
                    // Fall through to deliver any remaining data
                } else if self.streamClosed {
                    // Stream ended before a complete TCPResponse arrived.
                    completion(nil, HysteriaClient.HysteriaError.connectionFailed("stream closed before TCPResponse"))
                    return
                } else {
                    // Need more data for response header
                    self.pendingReceiveCompletion = completion
                    return
                }
            }

            if !self.receiveBuffer.isEmpty {
                self.ackConsumedBytes()
                let data = self.receiveBuffer
                self.receiveBuffer.removeAll(keepingCapacity: true)
                completion(data, nil)
            } else if self.streamClosed {
                completion(nil, nil)
            } else {
                self.pendingReceiveCompletion = completion
            }
        }
    }

    private func deliverPendingData() {
        guard let completion = pendingReceiveCompletion else { return }

        if !responseReceived {
            if let (ok, message, consumed) = HysteriaTCPFraming.parseTCPResponse(receiveBuffer) {
                responseReceived = true
                receiveBuffer = Data(receiveBuffer.dropFirst(consumed))
                ackConsumedBytes()

                if !ok {
                    pendingReceiveCompletion = nil
                    completion(nil, HysteriaClient.HysteriaError.connectionFailed(message))
                    return
                }
            } else if streamClosed {
                pendingReceiveCompletion = nil
                completion(nil, HysteriaClient.HysteriaError.connectionFailed("stream closed before TCPResponse"))
                return
            } else {
                return // Need more data
            }
        }

        if !receiveBuffer.isEmpty {
            pendingReceiveCompletion = nil
            ackConsumedBytes()
            let data = receiveBuffer
            receiveBuffer.removeAll(keepingCapacity: true)
            completion(data, nil)
        } else if streamClosed {
            pendingReceiveCompletion = nil
            completion(nil, nil)
        }
    }

    private func ackConsumedBytes() {
        let count = pendingQuicBytes
        guard count > 0 else { return }
        pendingQuicBytes = 0
        quic.extendStreamOffset(streamId, count: count)
    }

    // MARK: - Cancel

    override func cancel() {
        queue.async { [weak self] in
            guard let self, !self.streamClosed else { return }
            self.streamClosed = true
            self.quic.shutdownStream(self.streamId)
            self.pendingReceiveCompletion?(nil, nil)
            self.pendingReceiveCompletion = nil
            self.owner?.removeTCPStream(self.streamId)
        }
    }
}

// MARK: - HysteriaUDPConnection

/// ProxyConnection subclass for Hysteria UDP proxy via QUIC datagrams.
///
/// Each send/receive carries a complete UDP datagram with address framing.
/// Large datagrams are automatically fragmented/defragmented.
class HysteriaUDPConnection: ProxyConnection {
    private let session: HysteriaUDPSession
    private let address: String
    private let queue: DispatchQueue
    private weak var owner: HysteriaClient?
    private var isCancelled = false

    init(session: HysteriaUDPSession, address: String, queue: DispatchQueue, owner: HysteriaClient) {
        self.session = session
        self.address = address
        self.queue = queue
        self.owner = owner
        super.init()
        self.responseHeaderReceived = true
    }

    override var isConnected: Bool { !isCancelled }
    override var outerTLSVersion: TLSVersion? { .tls13 }

    // MARK: - Send

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        guard !isCancelled else {
            completion(HysteriaClient.HysteriaError.closed)
            return
        }
        session.send(address: address, data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { _ in }
    }

    // MARK: - Receive

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        queue.async { [weak self] in
            guard let self, !self.isCancelled else {
                completion(nil, nil)
                return
            }
            self.session.receive { msg, error in
                if let error {
                    completion(nil, error)
                } else if let msg {
                    completion(msg.data, nil)
                } else {
                    completion(nil, nil)
                }
            }
        }
    }

    // MARK: - Cancel

    override func cancel() {
        guard !isCancelled else { return }
        isCancelled = true
        session.close(error: HysteriaClient.HysteriaError.closed)
        owner?.removeUDPSession(session.sessionID)
    }
}
