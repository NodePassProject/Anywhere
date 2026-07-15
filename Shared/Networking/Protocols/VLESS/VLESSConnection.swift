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
        super.init()
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    // MARK: - Handshake

    /// Writes the VLESS request header (and optional initial payload); call once after construction.
    func sendHandshake(requestHeader: Data, initialData: Data?) async throws {
        var payload = requestHeader
        if let initialData, !initialData.isEmpty {
            payload.append(initialData)
        }
        try await inner.sendRaw(payload)
    }

    // MARK: - Send (passthrough)

    override func sendRaw(_ data: Data) async throws {
        try await inner.sendRaw(data)
    }

    // MARK: - Receive (strip VLESS response header on first bytes)

    override func receiveRaw() async throws -> Data? {
        while true {
            let received = try await inner.receiveRaw()
            guard let data = received, !data.isEmpty else {
                // EOF (nil) or an empty chunk passes through unchanged.
                return received
            }
            switch processResponseHeader(data: data) {
            case .deliver(let output):
                return output
            case .needMore:
                continue
            }
        }
    }

    private enum HeaderResult {
        case deliver(Data)
        case needMore
    }

    /// Consumes the VLESS response header (version + addonsLength + addons), then
    /// delivers the remainder. A non-matching first byte passes the buffered bytes
    /// through as-is — some servers omit the response header entirely.
    private func processResponseHeader(data: Data) -> HeaderResult {
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
            return .deliver(output)
        } else if shouldReceiveMore {
            return .needMore
        } else {
            return .deliver(data)
        }
    }

    // MARK: - Direct (Vision bypass) passthroughs

    override func receiveDirectRaw() async throws -> Data? {
        try await inner.receiveDirectRaw()
    }

    override func sendDirectRaw(_ data: Data) async throws {
        try await inner.sendDirectRaw(data)
    }

    // MARK: - Cancel

    override func cancel() {
        inner.cancel()
    }
}
