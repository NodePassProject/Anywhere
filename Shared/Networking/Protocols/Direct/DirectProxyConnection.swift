//
//  DirectProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

nonisolated final class DirectProxyConnection: ProxyConnection, @unchecked Sendable {

    private let transport: any AsyncByteTransport
    
    private struct SendJob: @unchecked Sendable {
        let data: Data
        let endOfStream: Bool
        let completion: ((Error?) -> Void)?
    }

    private let jobsContinuation: AsyncStream<SendJob>.Continuation
    private let pump: Task<Void, Never>

    init(transport: any AsyncByteTransport) {
        self.transport = transport
        let (stream, continuation) = AsyncStream.makeStream(of: SendJob.self)
        self.jobsContinuation = continuation
        pump = Task {
            for await job in stream {
                do {
                    if job.endOfStream {
                        try await transport.finishSend()
                    } else {
                        try await transport.send(job.data)
                    }
                    job.completion?(nil)
                } catch {
                    job.completion?(error)
                }
            }
        }
        super.init()
    }

    deinit {
        jobsContinuation.finish()
        pump.cancel()
    }

    override var isConnected: Bool { transport.isReady }

    override func sendRaw(_ data: Data) async throws {
        try await transport.send(data)
    }

    override func receiveRaw() async throws -> Data? {
        switch try await transport.receive() {
        case .bytes(let data): return data
        case .end: return nil
        }
    }

    override func closeWrite() async throws {
        try await transport.finishSend()
    }

    override func cancel() {
        jobsContinuation.finish()
        pump.cancel()
        transport.cancel()
    }
}
