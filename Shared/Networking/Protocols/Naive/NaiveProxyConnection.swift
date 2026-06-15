//
//  NaiveProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/9/26.
//

import Foundation

private let logger = AnywhereLogger(category: "NaiveProxyConnection")

// MARK: - NaiveTunnel Protocol

/// Abstraction over the HTTP CONNECT tunnel (HTTP/1.1, HTTP/2, or HTTP/3) beneath NaiveProxy padding.
protocol NaiveTunnel: AnyObject {
    var isConnected: Bool { get }
    var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType { get }
    func openTunnel(completion: @escaping (Error?) -> Void)
    func sendData(_ data: Data, completion: @escaping (Error?) -> Void)
    func receiveData(completion: @escaping (Data?, Error?) -> Void)
    func close()
}

// MARK: - NaiveProxyConnection

/// ProxyConnection that wraps a NaiveTunnel with NaiveProxy padding framing,
/// applied to the first 8 reads/writes when the server negotiates variant 1.
nonisolated class NaiveProxyConnection: ProxyConnection {
    private let tunnel: NaiveTunnel
    private var paddingFramer = NaivePaddingFramer()
    private let paddingType: NaivePaddingNegotiator.PaddingType

    init(tunnel: NaiveTunnel, paddingType: NaivePaddingNegotiator.PaddingType) {
        self.tunnel = tunnel
        self.paddingType = paddingType
        super.init()
    }

    override var isConnected: Bool { tunnel.isConnected }
    override var outerTLSVersion: TLSVersion? { .tls13 }

    // MARK: - Send

    /// Maximum payload that fits in one padding frame (2-byte length field).
    private static let maxPaddingPayload = 65535

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        if paddingFramer.isWritePaddingActive && paddingType == .variant1 {
            if data.count >= 400 && data.count <= 1024 {
                sendFragmented(data: data, offset: 0, completion: completion)
                return
            }
            // Truncate to the 2-byte length cap, matching the reference NaivePaddingFramer::Write().
            let payload = data.count > Self.maxPaddingPayload
                ? Data(data.prefix(Self.maxPaddingPayload)) : data
            let paddingSize = Self.generateSendPaddingSize(payloadSize: payload.count)
            let framed = paddingFramer.write(payload: payload, paddingSize: paddingSize)
            if payload.count < data.count {
                tunnel.sendData(framed) { [weak self] error in
                    if let error { completion(error); return }
                    let rest = Data(data[payload.count...])
                    self?.sendRaw(data: rest, completion: completion)
                }
            } else {
                tunnel.sendData(framed, completion: completion)
            }
        } else {
            tunnel.sendData(data, completion: completion)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { _ in }
    }

    private func sendFragmented(data: Data, offset: Int, completion: @escaping (Error?) -> Void) {
        guard offset < data.count else {
            completion(nil)
            return
        }

        guard paddingFramer.isWritePaddingActive else {
            let remaining = Data(data[offset...])
            tunnel.sendData(remaining, completion: completion)
            return
        }

        let remaining = data.count - offset
        let chunkSize = remaining <= 300 ? remaining : Int.random(in: 200...300)
        let chunk = Data(data[offset..<(offset + chunkSize)])
        let paddingSize = Self.generateSendPaddingSize(payloadSize: chunk.count)
        let framed = paddingFramer.write(payload: chunk, paddingSize: paddingSize)

        tunnel.sendData(framed) { [weak self] error in
            if let error {
                completion(error)
                return
            }
            self?.sendFragmented(data: data, offset: offset + chunkSize, completion: completion)
        }
    }

    // MARK: - Receive

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        tunnel.receiveData { [weak self] data, error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Connection deallocated"))
                return
            }

            if let error {
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                completion(nil, nil)
                return
            }

            if self.paddingFramer.isReadPaddingActive && self.paddingType == .variant1 {
                var output = Data()
                let payloadBytes = self.paddingFramer.read(padded: data, into: &output)
                if payloadBytes > 0 {
                    completion(output, nil)
                } else {
                    // Pure-padding frame (0 payload bytes) — re-read
                    self.receiveRaw(completion: completion)
                }
            } else {
                completion(data, nil)
            }
        }
    }

    // MARK: - Cancel

    override func cancel() {
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
