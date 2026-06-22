//
//  TunneledHTTP3Client.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Foundation
@testable import Anywhere

enum TunneledHTTP3Client {
    static func get(
        proxyConnection: ProxyConnection,
        authorityHost: String,
        port: UInt16,
        path: String
    ) async throws -> HTTPResponse {
        let transport = ProxyConnectionDatagramTransport(connection: proxyConnection)
        let multiplexer = HTTP3Multiplexer(
            host: authorityHost, port: port, serverName: authorityHost, transport: transport
        )
        let request = HTTP3GetRequest(
            multiplexer: multiplexer, authorityHost: authorityHost, port: port, path: path
        )
        do {
            let response = try await request.run()
            multiplexer.close()
            return response
        } catch {
            multiplexer.close()
            throw error
        }
    }
}

private final class HTTP3GetRequest: HTTP3StreamHandler {
    private let multiplexer: HTTP3Multiplexer
    private let authority: String
    private let path: String

    private(set) var quicStreamID: Int64?
    private var headersReceived = false
    private var status: Int?
    private var responseHeaders: [(name: String, value: String)] = []
    private var body = Data()
    private var frameBuffer = Data()
    private var frameBufferOffset = 0
    private var finished = false
    private var continuation: CheckedContinuation<HTTPResponse, Error>?

    init(multiplexer: HTTP3Multiplexer, authorityHost: String, port: UInt16, path: String) {
        self.multiplexer = multiplexer
        self.authority = port == 443 ? authorityHost : "\(authorityHost):\(port)"
        self.path = path
    }

    func run() async throws -> HTTPResponse {
        try await withCheckedThrowingContinuation { continuation in
            multiplexer.queue.async { [self] in
                self.continuation = continuation
                multiplexer.ensureReady { [weak self] error in
                    guard let self else { return }
                    if let error {
                        self.complete(.failure(error))
                    } else {
                        self.sendRequest()
                    }
                }
            }
        }
    }

    private func sendRequest() {
        guard let streamID = multiplexer.openBidiStream() else {
            multiplexer.markStreamBlocked()
            complete(.failure(HTTP3Error.streamIdBlocked))
            return
        }
        quicStreamID = streamID
        multiplexer.registerStream(self, streamID: streamID)

        let headerBlock = QPACKEncoder.encodeRequestHeaders(
            method: "GET",
            authority: authority,
            path: path,
            extraHeaders: [(name: "user-agent", value: "Anywhere")]
        )
        let frame = HTTP3Framer.headersFrame(headerBlock: headerBlock)
        multiplexer.writeStream(streamID, data: frame, fin: true) { [weak self] error in
            guard let self, let error else { return }
            self.multiplexer.queue.async { self.handleSessionError(error) }
        }
    }

    // MARK: - HTTP3StreamHandler (multiplexer queue)

    func handleStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty {
            frameBuffer.append(data)
            processFrames()
        }
        if fin { finishOnEnd() }
    }

    func handleSessionError(_ error: Error) {
        complete(.failure(error))
    }

    // MARK: - Frame processing

    private func processFrames() {
        var consumedBytes = 0
        while frameBufferOffset < frameBuffer.count {
            guard let (frame, consumed) = HTTP3Framer.parseFrame(from: frameBuffer, offset: frameBufferOffset) else {
                break
            }
            frameBufferOffset += consumed
            consumedBytes += consumed

            if frame.type == HTTP3FrameType.headers.rawValue {
                if !headersReceived {
                    headersReceived = true
                    guard let headers = QPACKEncoder.decodeHeaders(from: frame.payload) else {
                        complete(.failure(HTTP3Error.connectionFailed("Malformed QPACK header block")))
                        return
                    }
                    responseHeaders = headers
                    if let raw = headers.first(where: { $0.name == ":status" })?.value {
                        status = Int(raw)
                    }
                }
            } else if frame.type == HTTP3FrameType.data.rawValue {
                body.append(frame.payload)
            }
        }
        if consumedBytes > 0, let streamID = quicStreamID {
            multiplexer.extendStreamOffset(streamID, count: consumedBytes)
        }
        compactBuffer()
    }

    private func compactBuffer() {
        if frameBufferOffset >= frameBuffer.count {
            frameBuffer = Data()
            frameBufferOffset = 0
        } else if frameBufferOffset > 64 * 1024 {
            frameBuffer = Data(frameBuffer[(frameBuffer.startIndex + frameBufferOffset)...])
            frameBufferOffset = 0
        }
    }

    private func finishOnEnd() {
        guard let status else {
            complete(.failure(HTTP3Error.connectionFailed("stream ended before response headers")))
            return
        }
        complete(.success(HTTPResponse(statusCode: status, headers: responseHeaders, body: body)))
    }

    private func complete(_ result: Result<HTTPResponse, Error>) {
        guard !finished else { return }
        finished = true
        if let streamID = quicStreamID {
            multiplexer.removeStream(self)
            multiplexer.shutdownStream(streamID, code: .noError)
        }
        let continuation = self.continuation
        self.continuation = nil
        continuation?.resume(with: result)
    }
}
