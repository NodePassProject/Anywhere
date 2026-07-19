//
//  TunneledHTTP3Client.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Foundation
import Synchronization
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

private nonisolated final class HTTP3GetRequest: Sendable {

    private let multiplexer: HTTP3Multiplexer
    private let authority: String
    private let path: String

    /// Request/response state, guarded by `lock`.
    private struct State {
        var quicStreamID: Int64?
        var headersReceived = false
        var status: Int?
        var responseHeaders: [(name: String, value: String)] = []
        var body = Data()
        var frameBuffer = Data()
        var frameBufferOffset = 0
        var finished = false
    }
    private let lock = Mutex(State())

    /// One-shot result latch; `run()` awaits `resultTask.value`.
    private let resultSignal: AsyncThrowingStream<HTTPResponse, Error>.Continuation
    private let resultTask: Task<HTTPResponse, Error>

    init(multiplexer: HTTP3Multiplexer, authorityHost: String, port: UInt16, path: String) {
        self.multiplexer = multiplexer
        self.authority = port == 443 ? authorityHost : "\(authorityHost):\(port)"
        self.path = path
        let (resultStream, resultSignal) = AsyncThrowingStream.makeStream(of: HTTPResponse.self)
        self.resultSignal = resultSignal
        self.resultTask = Task {
            for try await response in resultStream { return response }
            throw AnywhereError.proxy(.http3, .streamClosed)
        }
    }

    func run() async throws -> HTTPResponse {
        try await multiplexer.ensureReady()

        let events = HTTP3Multiplexer.StreamEvents(
            data: { [weak self] data, fin in
                self?.handleStreamData(data, fin: fin)
            },
            error: { [weak self] error in
                self?.complete(.failure(error))
            }
        )
        guard let streamID = await multiplexer.openStream(events: events) else {
            throw AnywhereError.proxy(.http3, .streamIDsExhausted)
        }
        lock.withLock { $0.quicStreamID = streamID }

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
                self.complete(.failure(error))
            }
        }
        return try await resultTask.value
    }

    // MARK: - Demux events (delivered synchronously on the ngtcp2 queue)

    private func handleStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty {
            processFrames(appending: data)
        }
        if fin { finishOnEnd() }
    }

    // MARK: - Frame processing

    private func processFrames(appending data: Data) {
        var consumedBytes = 0
        var malformed = false

        lock.withLock { state in
            state.frameBuffer.append(data)
            while state.frameBufferOffset < state.frameBuffer.count {
                guard let (frame, consumed) = HTTP3Framer.parseFrame(
                    from: state.frameBuffer, offset: state.frameBufferOffset
                ) else {
                    break
                }
                state.frameBufferOffset += consumed
                consumedBytes += consumed

                if frame.type == HTTP3FrameType.headers.rawValue {
                    if !state.headersReceived {
                        state.headersReceived = true
                        guard let headers = QPACKEncoder.decodeHeaders(from: frame.payload) else {
                            malformed = true
                            break
                        }
                        state.responseHeaders = headers
                        if let raw = headers.first(where: { $0.name == ":status" })?.value {
                            state.status = Int(raw)
                        }
                    }
                } else if frame.type == HTTP3FrameType.data.rawValue {
                    state.body.append(frame.payload)
                }
            }

            if state.frameBufferOffset >= state.frameBuffer.count {
                state.frameBuffer = Data()
                state.frameBufferOffset = 0
            } else if state.frameBufferOffset > 64 * 1024 {
                state.frameBuffer = Data(state.frameBuffer[(state.frameBuffer.startIndex + state.frameBufferOffset)...])
                state.frameBufferOffset = 0
            }
        }

        if malformed {
            complete(.failure(AnywhereError.proxy(.http3, .connectionClosed(detail: "Malformed QPACK header block"))))
            return
        }
        if consumedBytes > 0, let streamID = lock.withLock({ $0.quicStreamID }) {
            multiplexer.extendStreamOffset(streamID, count: consumedBytes)
        }
    }

    private func finishOnEnd() {
        let snapshot: (status: Int?, headers: [(name: String, value: String)], body: Data) =
            lock.withLock { (status: $0.status, headers: $0.responseHeaders, body: $0.body) }
        guard let status = snapshot.status else {
            complete(.failure(AnywhereError.proxy(.http3, .connectionClosed(detail: "stream ended before response headers"))))
            return
        }
        complete(.success(HTTPResponse(statusCode: status, headers: snapshot.headers, body: snapshot.body)))
    }

    private func complete(_ result: Result<HTTPResponse, Error>) {
        let sid: Int64?? = lock.withLock { state in
            guard !state.finished else { return nil }
            state.finished = true
            return .some(state.quicStreamID)
        }
        guard let sid else { return }
        if let streamID = sid {
            multiplexer.removeStream(streamID)
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
