//
//  CallbackByteTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation

// MARK: - CallbackByteTransport

/// Presents an ``AsyncByteTransport`` through the completion-handler
/// ``RawTransport`` surface, for callback-based consumers.
///
/// A callback consumer can fire-and-forget `send(A); send(B)`, which would race if
/// each were bridged to its own `Task`, so sends are drained in submission order by
/// one pump task (`finishSend` ordered after them). Receives are single-flight per
/// the `RawTransport` contract, so each bridges to one `await transport.receive()`.
nonisolated final class CallbackByteTransport: RawTransport, @unchecked Sendable {

    private let transport: any AsyncByteTransport

    /// One ordered send job for the pump. `@unchecked` because the caller's
    /// completion isn't `Sendable`, but it only ever runs on the pump task.
    private struct SendJob: @unchecked Sendable {
        let data: Data
        let endOfStream: Bool
        let completion: ((Error?) -> Void)?
    }

    private let jobs: AsyncStream<SendJob>
    private let jobsContinuation: AsyncStream<SendJob>.Continuation
    private let pump: Task<Void, Never>

    init(_ transport: any AsyncByteTransport) {
        self.transport = transport
        let (stream, continuation) = AsyncStream.makeStream(of: SendJob.self)
        self.jobs = stream
        self.jobsContinuation = continuation
        // Capture locals (not `self`) so the pump doesn't retain the adapter.
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
    }

    deinit {
        jobsContinuation.finish()
        pump.cancel()
    }

    // MARK: - RawTransport

    var isTransportReady: Bool { transport.isReady }

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        jobsContinuation.yield(SendJob(data: data, endOfStream: false, completion: completion))
    }

    func send(data: Data) {
        jobsContinuation.yield(SendJob(data: data, endOfStream: false, completion: nil))
    }

    func closeWrite(completion: @escaping (Error?) -> Void) {
        jobsContinuation.yield(SendJob(data: Data(), endOfStream: true, completion: completion))
    }

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        Task {
            do {
                switch try await transport.receive() {
                case .bytes(let data): completion(data, false, nil)
                case .end: completion(nil, true, nil)
                }
            } catch {
                completion(nil, true, error)
            }
        }
    }

    func forceCancel() {
        jobsContinuation.finish()
        pump.cancel()
        transport.cancel()
    }
}
