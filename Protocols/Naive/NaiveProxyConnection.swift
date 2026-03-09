//
//  NaiveProxyConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/9/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "NaiveProxy")

// MARK: - NaiveProxyConnection

/// ProxyConnection subclass that wraps an ``HTTP2Connection`` with NaiveProxy padding framing.
///
/// Applies NaivePaddingFramer on the first 8 reads and writes when the server negotiates
/// variant-1 padding. After 8 frames, data passes through unframed.
///
/// For the "server" direction (client→server), payloads < 100 bytes get biased padding
/// `[255-len, 255]` and medium payloads (400–1024 bytes) are split into 200–300 byte chunks.
/// The "client" direction (server→client) uses uniform random padding `[0, 255]`.
class NaiveProxyConnection: ProxyConnection {
    private let http2: HTTP2Connection
    private var paddingFramer = NaivePaddingFramer()
    private let paddingType: NaivePaddingNegotiator.PaddingType

    init(http2: HTTP2Connection, paddingType: NaivePaddingNegotiator.PaddingType) {
        self.http2 = http2
        self.paddingType = paddingType
        super.init()
        self.responseHeaderReceived = true  // No VLESS response header
    }

    override var isConnected: Bool { http2.isConnected }

    // MARK: - Send

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        if paddingFramer.isWritePaddingActive && paddingType == .variant1 {
            // Fragment medium payloads (400–1024 bytes) into 200–300 byte chunks
            if data.count >= 400 && data.count <= 1024 {
                sendFragmented(data: data, offset: 0, completion: completion)
                return
            }
            let paddingSize = Self.generateSendPaddingSize(payloadSize: data.count)
            let framed = paddingFramer.write(payload: data, paddingSize: paddingSize)
            http2.sendData(framed, completion: completion)
        } else {
            http2.sendData(data, completion: completion)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { error in
            if let error {
                logger.error("[Naive] Send error: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    /// Fragments medium payloads into 200–300 byte chunks, each padded separately.
    private func sendFragmented(data: Data, offset: Int, completion: @escaping (Error?) -> Void) {
        guard offset < data.count else {
            completion(nil)
            return
        }

        // Stop fragmenting if we've exhausted padding frames
        guard paddingFramer.isWritePaddingActive else {
            let remaining = Data(data[offset...])
            http2.sendData(remaining, completion: completion)
            return
        }

        let remaining = data.count - offset
        let chunkSize = remaining <= 300 ? remaining : Int.random(in: 200...300)
        let chunk = Data(data[offset..<(offset + chunkSize)])
        let paddingSize = Self.generateSendPaddingSize(payloadSize: chunk.count)
        let framed = paddingFramer.write(payload: chunk, paddingSize: paddingSize)

        http2.sendData(framed) { [weak self] error in
            if let error {
                completion(error)
                return
            }
            self?.sendFragmented(data: data, offset: offset + chunkSize, completion: completion)
        }
    }

    // MARK: - Receive

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        http2.receiveData { [weak self] data, error in
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
        http2.close()
    }

    // MARK: - Padding Size Generation

    /// Generates padding size for the send (client→server) direction.
    ///
    /// Small payloads (< 100 bytes) get biased padding `[255-len, 255]` to obscure size.
    /// All other payloads get uniform random padding `[0, 255]`.
    private static func generateSendPaddingSize(payloadSize: Int) -> Int {
        if payloadSize < 100 {
            return Int.random(in: (255 - payloadSize)...255)
        }
        return Int.random(in: 0...255)
    }
}
