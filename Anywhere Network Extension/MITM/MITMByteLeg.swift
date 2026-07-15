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

    private let transport: any AsyncByteTransport

    private struct State {
        var prepended = Data()
        var cancelled = false
    }
    private let state = Mutex(State())

    init(transport: any AsyncByteTransport) {
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

        switch try await transport.receive() {
        case .bytes(let data): return data
        case .end:             return nil
        }
    }

    func send(_ data: Data) async throws {
        try await transport.send(data)
    }

    func cancel() {
        state.withLock { state in
            state.cancelled = true
            state.prepended = Data()
        }
        transport.cancel()
    }
}
