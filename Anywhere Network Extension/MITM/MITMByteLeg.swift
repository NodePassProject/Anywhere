//
//  MITMByteLeg.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Foundation
import Synchronization

nonisolated protocol MITMByteLeg: AnyObject, Sendable {
    var negotiatedALPN: String { get }

    func prependToReceiveBuffer(_ data: Data)

    func receive() async throws -> Data?

    func send(_ data: Data) async throws

    func cancel()
}

extension TLSRecordConnection: MITMByteLeg {}

nonisolated final class PlaintextLeg: MITMByteLeg, Sendable {
    let negotiatedALPN: String = ""

    private let transport: any ByteTransport

    private enum Phase: PhaseTransitionable {
        case open
        case cancelled

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.open, .cancelled):
                return true
            default:
                return false
            }
        }
    }

    private struct State: PhaseHolding {
        var phase: Phase = .open
        var prepended = Data()
    }
    private let state = Mutex(State())

    init(transport: any ByteTransport) {
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
            return (nil, state.phase == .cancelled)
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
        let claimed = state.withLock { state -> Bool in
            guard state.transition(to: .cancelled) else { return false }
            state.prepended = Data()
            return true
        }
        guard claimed else { return }
        transport.cancel()
    }
}
