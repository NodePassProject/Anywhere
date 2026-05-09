//
//  VLESSConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/13/26.
//

import Foundation

final class VLESSConnection: ProxyConnection {

    private let inner: ProxyConnection

    /// Guards the response-header buffer below.
    private let headerLock = UnfairLock()
    private var responseHeaderReceived = false
    private var pendingResponseBuffer = Data()

    init(inner: ProxyConnection) {
        self.inner = inner
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    // MARK: - Handshake

    /// Writes the VLESS request header (and optional initial payload) to the
    /// transport. Call once immediately after construction; subsequent sends
    /// use the regular `send`/`sendRaw` API.
    ///
    /// For Vision flow callers pass `initialData = nil` — Vision sends its
    /// first payload with its own padding machinery after this completes.
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

    /// Buffers incoming bytes until the 2-byte VLESS response header (plus
    /// `addonsLength` bytes of addons) has been consumed, then delivers any
    /// remainder to `completion`. Loops via `receiveRaw` if more bytes are
    /// needed.
    ///
    /// If the first byte doesn't match `VLESSProtocol.version` we fall back
    /// to passing the data through unmodified — some lax server
    /// configurations skip the response header entirely, and refusing to
    /// continue would break them needlessly.
    private func processResponseHeader(data: Data, completion: @escaping (Data?, Error?) -> Void) {
        var output: Data?
        var shouldReceiveMore = false

        headerLock.lock()
        if responseHeaderReceived {
            output = data
            headerLock.unlock()
        } else {
            pendingResponseBuffer.append(data)
            let buffer = pendingResponseBuffer
            if buffer.count < 2 {
                shouldReceiveMore = true
                headerLock.unlock()
            } else if buffer[buffer.startIndex] != VLESSProtocol.version {
                // Non-VLESS response preamble — treat buffered bytes as payload.
                responseHeaderReceived = true
                output = buffer
                pendingResponseBuffer.removeAll(keepingCapacity: true)
                headerLock.unlock()
            } else {
                let addonsLength = Int(buffer[buffer.index(buffer.startIndex, offsetBy: 1)])
                let headerLength = 2 + addonsLength
                if buffer.count < headerLength {
                    shouldReceiveMore = true
                    headerLock.unlock()
                } else {
                    responseHeaderReceived = true
                    if buffer.count > headerLength {
                        output = Data(buffer.suffix(from: headerLength))
                    } else {
                        shouldReceiveMore = true
                    }
                    pendingResponseBuffer.removeAll(keepingCapacity: true)
                    headerLock.unlock()
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
