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

/// One GET exchange over the multiplexer. An actor on the multiplexer's executor, so the
/// demux events it registers enter its isolated state synchronously — the same shape as
/// the production `XHTTPH3RequestStream`/`NaiveHTTP3Stream` consumers.
private actor HTTP3GetRequest {
    private nonisolated let bridge: NGTCP2ConcurrencyBridge
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        bridge.executor.asUnownedSerialExecutor()
    }

    private let multiplexer: HTTP3Multiplexer
    private let authority: String
    private let path: String

    private var quicStreamID: Int64?
    private var headersReceived = false
    private var status: Int?
    private var responseHeaders: [(name: String, value: String)] = []
    private var body = Data()
    private var frameBuffer = Data()
    private var frameBufferOffset = 0
    private var finished = false

    /// One-shot result latch; `run()` awaits `resultTask.value`.
    private let resultSignal: AsyncThrowingStream<HTTPResponse, Error>.Continuation
    private let resultTask: Task<HTTPResponse, Error>

    init(multiplexer: HTTP3Multiplexer, authorityHost: String, port: UInt16, path: String) {
        self.bridge = multiplexer.sharedBridge
        self.multiplexer = multiplexer
        self.authority = port == 443 ? authorityHost : "\(authorityHost):\(port)"
        self.path = path
        let (resultStream, resultSignal) = AsyncThrowingStream.makeStream(of: HTTPResponse.self)
        self.resultSignal = resultSignal
        self.resultTask = Task {
            for try await response in resultStream { return response }
            throw HTTP3Error.streamClosed
        }
    }

    func run() async throws -> HTTPResponse {
        try await multiplexer.ensureReady()

        let events = HTTP3Multiplexer.StreamEvents(
            data: { [weak self] data, fin in
                self?.assumeIsolated { $0.handleStreamData(data, fin: fin) }
            },
            error: { [weak self] error in
                self?.assumeIsolated { $0.complete(.failure(error)) }
            }
        )
        guard let streamID = await multiplexer.openStream(events: events) else {
            throw HTTP3Error.streamIdBlocked
        }
        quicStreamID = streamID

        let headerBlock = QPACKEncoder.encodeRequestHeaders(
            method: "GET",
            authority: authority,
            path: path,
            extraHeaders: [(name: "user-agent", value: "Anywhere")]
        )
        let frame = HTTP3Framer.headersFrame(headerBlock: headerBlock)
        Task {
            do {
                try await multiplexer.writeStream(streamID, data: frame, fin: true)
            } catch {
                complete(.failure(error))
            }
        }
        return try await resultTask.value
    }

    // MARK: - Demux events (delivered on the shared executor)

    private func handleStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty {
            frameBuffer.append(data)
            processFrames()
        }
        if fin { finishOnEnd() }
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
            multiplexer.assumeIsolated { $0.removeStream(streamID) }
            multiplexer.shutdownStream(streamID, code: .noError)
        }
        switch result {
        case .success(let response):
            resultSignal.yield(response)
            resultSignal.finish()
        case .failure(let error):
            resultSignal.finish(throwing: error)
        }
    }
}
