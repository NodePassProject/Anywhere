//
//  VLESSConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation
import Synchronization

nonisolated final class VLESSConnection: ProxyConnection {

    private let inner: ProxyConnection

    private struct HeaderState {
        var responseHeaderReceived = false
        var pendingResponseBuffer = Data()
    }

    private let headerState = Mutex(HeaderState())

    init(inner: ProxyConnection) {
        self.inner = inner
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    // MARK: - Handshake

    /// Writes the VLESS request header (and optional initial payload); call once after construction.
    func sendHandshake(
        requestHeader: Data,
        initialData: Data?,
        completion: @escaping (Error?) -> Void
    ) {
        var payload = requestHeader
        if let initialData, !initialData.isEmpty {
            payload.append(initialData)
        }
        inner.sendRaw(data: payload, completion: completion)
    }

    // MARK: - Send (passthrough)

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        inner.sendRaw(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        inner.sendRaw(data: data)
    }

    // MARK: - Receive (strip VLESS response header on first bytes)

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        inner.receiveRaw { [weak self] data, error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Connection deallocated"))
                return
            }
            if let error {
                completion(nil, error)
                return
            }
            guard let data, !data.isEmpty else {
                completion(data, nil)
                return
            }
            self.processResponseHeader(data: data, completion: completion)
        }
    }

    /// Consumes the VLESS response header (version + addonsLength + addons), then
    /// delivers the remainder. A non-matching first byte passes the buffered bytes
    /// through as-is — some servers omit the response header entirely.
    private func processResponseHeader(data: Data, completion: @escaping (Data?, Error?) -> Void) {
        var output: Data?
        var shouldReceiveMore = false

        headerState.withLock { state in
            if state.responseHeaderReceived {
                output = data
            } else {
                state.pendingResponseBuffer.append(data)
                let buffer = state.pendingResponseBuffer
                if buffer.count < 2 {
                    shouldReceiveMore = true
                } else if buffer[buffer.startIndex] != VLESSProtocol.version {
                    // Non-VLESS response preamble — treat buffered bytes as payload.
                    state.responseHeaderReceived = true
                    output = buffer
                    state.pendingResponseBuffer.removeAll(keepingCapacity: true)
                } else {
                    let addonsLength = Int(buffer[buffer.index(buffer.startIndex, offsetBy: 1)])
                    let headerLength = 2 + addonsLength
                    if buffer.count < headerLength {
                        shouldReceiveMore = true
                    } else {
                        state.responseHeaderReceived = true
                        if buffer.count > headerLength {
                            output = Data(buffer.suffix(from: headerLength))
                        } else {
                            shouldReceiveMore = true
                        }
                        state.pendingResponseBuffer.removeAll(keepingCapacity: true)
                    }
                }
            }
        }

        if let output {
            completion(output, nil)
        } else if shouldReceiveMore {
            receiveRaw(completion: completion)
        } else {
            completion(data, nil)
        }
    }

    // MARK: - Direct (Vision bypass) passthroughs

    override func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        inner.receiveDirectRaw(completion: completion)
    }

    override func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        inner.sendDirectRaw(data: data, completion: completion)
    }

    override func sendDirectRaw(data: Data) {
        inner.sendDirectRaw(data: data)
    }

    // MARK: - Cancel

    override func cancel() {
        inner.cancel()
    }
}
