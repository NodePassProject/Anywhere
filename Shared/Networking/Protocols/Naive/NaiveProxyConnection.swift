//
//  NaiveProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/9/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "NaiveProxyConnection")

// MARK: - NaiveTunnel Protocol

/// Abstraction over the HTTP CONNECT tunnel (HTTP/1.1, HTTP/2, or HTTP/3) beneath NaiveProxy padding.
nonisolated protocol NaiveTunnel: AnyObject {
    var isConnected: Bool { get }
    var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType { get }
    func openTunnel() async throws
    func sendData(_ data: Data) async throws
    /// `nil` signals EOF.
    func receiveData() async throws -> Data?
    func close()
}

// MARK: - NaiveProxyConnection

/// Padding framing applies only to the first 8 reads/writes, and only when the server negotiates variant 1.
nonisolated final class NaiveProxyConnection: ProxyConnection {
    private let tunnel: NaiveTunnel
    /// Padding framer touched by both the send and receive paths (which run on separate tasks),
    /// so it is Mutex-guarded — the lock is taken only for the synchronous frame/read, never across
    /// the tunnel `await`.
    private let paddingFramer = Mutex(NaivePaddingFramer())
    private let paddingType: NaivePaddingNegotiator.PaddingType

    init(tunnel: NaiveTunnel, paddingType: NaivePaddingNegotiator.PaddingType) {
        self.tunnel = tunnel
        self.paddingType = paddingType
    }

    var isConnected: Bool { tunnel.isConnected }
    var outerTLSVersion: TLSVersion? { .tls13 }

    // MARK: - Send

    /// Maximum payload that fits in one padding frame (2-byte length field).
    private static let maxPaddingPayload = 65535

    func sendRaw(_ data: Data) async throws {
        var data = data
        while true {
            if paddingFramer.withLock({ $0.isWritePaddingActive }) && paddingType == .variant1 {
                if data.count >= 400 && data.count <= 1024 {
                    try await sendFragmented(data: data)
                    return
                }
                // Truncate to the 2-byte length cap; spill the remainder into a follow-up frame.
                let payload = data.count > Self.maxPaddingPayload
                    ? Data(data.prefix(Self.maxPaddingPayload)) : data
                let paddingSize = Self.generateSendPaddingSize(payloadSize: payload.count)
                let framed = paddingFramer.withLock { $0.write(payload: payload, paddingSize: paddingSize) }
                try await tunnel.sendData(framed)
                if payload.count < data.count {
                    data = Data(data[payload.count...])
                    continue
                }
                return
            } else {
                try await tunnel.sendData(data)
                return
            }
        }
    }

    private func sendFragmented(data: Data) async throws {
        var offset = 0
        while offset < data.count {
            guard paddingFramer.withLock({ $0.isWritePaddingActive }) else {
                let remaining = Data(data[offset...])
                try await tunnel.sendData(remaining)
                return
            }

            let remaining = data.count - offset
            let chunkSize = remaining <= 300 ? remaining : Int.random(in: 200...300)
            let chunk = Data(data[offset..<(offset + chunkSize)])
            let paddingSize = Self.generateSendPaddingSize(payloadSize: chunk.count)
            let framed = paddingFramer.withLock { $0.write(payload: chunk, paddingSize: paddingSize) }
            try await tunnel.sendData(framed)
            offset += chunkSize
        }
    }

    // MARK: - Receive

    func receiveRaw() async throws -> Data? {
        while true {
            guard let data = try await tunnel.receiveData(), !data.isEmpty else {
                return nil
            }

            if paddingFramer.withLock({ $0.isReadPaddingActive }) && paddingType == .variant1 {
                var output = Data()
                let payloadBytes = paddingFramer.withLock { $0.read(padded: data, into: &output) }
                if payloadBytes > 0 {
                    return output
                }
                // Pure-padding frame (0 payload bytes) — re-read.
                continue
            }
            return data
        }
    }

    // MARK: - Cancel

    func cancel() {
        tunnel.close()
    }

    // MARK: - Padding Size Generation

    /// Small payloads (< 100 bytes) get biased padding `[255-len, 255]` to obscure their size.
    private static func generateSendPaddingSize(payloadSize: Int) -> Int {
        if payloadSize < 100 {
            return Int.random(in: (255 - payloadSize)...255)
        }
        return Int.random(in: 0...255)
    }
}
