//
//  MITMByteLeg.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Foundation
import Synchronization

protocol MITMByteLeg: AnyObject {
    var negotiatedALPN: String { get }

    func prependToReceiveBuffer(_ data: Data)

    func receive() async throws -> Data?

    func send(_ data: Data) async throws

    func cancel()
}

extension TLSRecordConnection: MITMByteLeg {}

nonisolated final class PlaintextLeg: MITMByteLeg {
    let negotiatedALPN: String = ""

    private let transport: any RawTransport

    private struct State {
        var prepended = Data()
        var cancelled = false
    }
    private let state = Mutex(State())

    init(transport: any RawTransport) {
        self.transport = transport
    }

    func prependToReceiveBuffer(_ data: Data) {
        guard !data.isEmpty else { return }
        state.withLock { $0.prepended.append(data) }
    }

    func receive() async throws -> Data? {
        // Deliver any handshake-buffered bytes first; extract under the lock.
        let (buffered, isCancelled): (Data?, Bool) = state.withLock { state in
            if !state.prepended.isEmpty {
                let data = state.prepended
                state.prepended = Data()
                return (data, false)
            }
            return (nil, state.cancelled)
        }
        if let buffered { return buffered }
        if isCancelled { return nil }

        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            transport.receive { data, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let data, !data.isEmpty {
                    continuation.resume(returning: data)
                } else {
                    continuation.resume(returning: nil)   // isComplete or empty → EOF
                }
            }
        }
    }

    func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            transport.send(data: data) { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
    }

    func cancel() {
        state.withLock { state in
            state.cancelled = true
            state.prepended = Data()
        }
        transport.forceCancel()
    }
}
