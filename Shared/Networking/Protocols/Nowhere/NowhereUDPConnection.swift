//
//  NowhereUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

actor NowhereUDPConnection {
    private let session: NowhereSession
    private let destination: NowhereProtocol.Target

    private enum Phase: PhaseTransitionable {
        case idle
        case opening
        case ready
        case closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .opening),
                 (.opening, .ready):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }
    private struct Lifecycle: PhaseHolding {
        var phase: Phase = .idle
        var resultReceived = false
        var controlStreamID: Int64?
    }

    private nonisolated let lifecycle = Mutex(Lifecycle())

    // MARK: Control stream (handshake)

    private let controlInbox = AsyncInbox<Data>()

    // MARK: Inbound datagrams

    private let datagramInbox = NowhereDatagramInbox()
    private var nextPacketID: UInt32 = 1

    init(
        session: NowhereSession,
        destination: NowhereProtocol.Target
    ) {
        self.session = session
        self.destination = destination
    }

    nonisolated var isConnected: Bool {
        lifecycle.withLock { if case .ready = $0.phase { true } else { false } }
    }
    nonisolated var outerTLSVersion: TLSVersion? { .tls13 }
    nonisolated var deliversDatagrams: Bool { true }

    // MARK: - Open

    func open() async throws {
        let begin = lifecycle.withLock { $0.transition(to: .opening) }
        guard begin else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
        do {
            let request = NowhereProtocol.encodeFlowRequest(kind: .udp, target: destination)
            let sid = try await session.openUDPControlStream(for: self, request: request)
            let flowID = try NowhereProtocol.udpFlowID(streamID: sid)
            let streamAdopted = lifecycle.withLock { state in
                guard state.phase == .opening else { return false }
                state.controlStreamID = sid
                return true
            }
            guard streamAdopted else {
                session.shutdownStream(sid)
                session.releaseUDPControlStream(sid)
                session.releaseUDPSession(flowID)
                throw AnywhereError.proxy(.nowhere, .streamClosed)
            }
            guard let chunk = try await nextControlChunk(),
                  let result = NowhereProtocol.decodeFlowResult(chunk) else {
                throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "UDP control stream closed before READY"))
            }
            session.extendStreamOffset(sid, count: chunk.count)
            switch result {
            case .ready:
                break
            case .reject(let code):
                throw AnywhereError.proxy(.nowhere, .flowRejected(code: code.rawValue))
            }
            session.activateUDPSession(flowID)
            guard lifecycle.withLock({ $0.transition(to: .ready) }) else {
                throw AnywhereError.proxy(.nowhere, .streamClosed)
            }
        } catch {
            fail(error)
            throw error
        }
    }

    // MARK: - Demux feed

    nonisolated func handleControlStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty {
            let accepted = lifecycle.withLock { state in
                guard state.phase == .opening, !state.resultReceived, data.count == 1 else { return false }
                state.resultReceived = true
                return true
            }
            guard accepted else {
                terminate(error: AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Unexpected UDP control stream data")))
                return
            }
            controlInbox.yield(data)
        }
        if fin { terminate(error: nil) }
    }

    nonisolated func handleControlStreamTermination(error: Error?) {
        terminate(error: error)
    }

    nonisolated func handleIncomingDatagram(_ datagram: NowhereQueuedDatagram) {
        datagramInbox.yield(datagram)
    }

    nonisolated func handleFlowClose() {
        terminate(error: nil)
    }

    nonisolated func handleSessionClose() {
        terminate(error: nil)
    }

    nonisolated func handleSessionError(_ error: Error) {
        if case AnywhereError.quic(.closed(graceful: true)) = error {
            terminate(error: nil)
        } else {
            terminate(error: error)
        }
    }

    // MARK: - ProxyConnection overrides

    func receiveRaw() async throws -> Data? {
        guard let datagram = try await nextDatagram() else { return nil }
        return datagram.payload
    }

    func sendRaw(_ data: Data) async throws {
        guard isConnected else {
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }
        try await attemptSend(data: data, maxSizeOverride: nil, retriesLeft: 1)
    }

    private func attemptSend(
        data: Data,
        maxSizeOverride: Int?,
        retriesLeft: Int
    ) async throws {
        let maxSize: Int
        if let maxSizeOverride {
            maxSize = maxSizeOverride
        } else {
            maxSize = await session.currentMaxDatagramPayloadSize()
        }
        let frames: [Data]
        do {
            let packetID = data.count + NowhereProtocol.udpHeaderSize <= maxSize
                ? 0
                : newPacketID()
            frames = try NowhereProtocol.encodeUDPDataFragments(
                flowID: try currentFlowID(),
                packetID: packetID,
                payload: data,
                maxDatagramSize: maxSize
            )
        } catch AnywhereError.proxy(.nowhere, .packetTooLarge) {
            return
        }
        do {
            try await session.writeDatagrams(frames)
        } catch {
            if case AnywhereError.quic(.datagramTooLarge(let maxBound)) = error,
               retriesLeft > 0 {
                guard isConnected else {
                    throw AnywhereError.proxy(.nowhere, .streamClosed)
                }
                try await attemptSend(
                    data: data,
                    maxSizeOverride: maxBound,
                    retriesLeft: retriesLeft - 1
                )
                return
            }
            if case AnywhereError.quic(.datagramTooLarge) = error {
                return
            }
            if case AnywhereError.quic(.datagramQueueFull) = error {
                return
            }
            throw error
        }
    }

    nonisolated func cancel() {
        terminate(error: nil)
    }

    // MARK: - Teardown

    private nonisolated func terminate(error: Error?) {
        let cleanup: (changed: Bool, streamID: Int64?) = lifecycle.withLock { state in
            guard state.transition(to: .closed) else { return (false, nil) }
            let sid = state.controlStreamID
            state.controlStreamID = nil
            return (true, sid)
        }
        guard cleanup.changed else { return }
        if let error {
            datagramInbox.finish(error: error)
            controlInbox.finish(throwing: error)
        } else {
            datagramInbox.finish()
            controlInbox.finish()
        }
        if let sid = cleanup.streamID {
            session.shutdownStream(sid)
            session.releaseUDPControlStream(sid)
            if let flowID = try? NowhereProtocol.udpFlowID(streamID: sid) {
                session.releaseUDPSession(flowID)
            }
        }
    }

    private nonisolated func fail(_ error: Error) {
        terminate(error: error)
    }

    private nonisolated func currentFlowID() throws -> UInt32 {
        guard let sid = lifecycle.withLock({ $0.controlStreamID }) else {
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }
        return try NowhereProtocol.udpFlowID(streamID: sid)
    }

    // MARK: - Pull helpers

    private func nextControlChunk() async throws -> Data? {
        try await controlInbox.next()
    }

    private func nextDatagram() async throws -> NowhereQueuedDatagram? {
        try await datagramInbox.next()
    }

    // MARK: - Helpers

    private func newPacketID() -> UInt32 {
        let packetID = nextPacketID
        nextPacketID = nextPacketID == UInt32.max ? 1 : nextPacketID + 1
        return packetID
    }
}

extension NowhereUDPConnection: ProxyConnection {}

private nonisolated final class NowhereDatagramInbox: Sendable {
    private struct State {
        var buffer: [NowhereQueuedDatagram] = []
        var finished = false
        var failure: Error?
    }

    private let state = Mutex(State())
    private let signal = AsyncInbox<Void>(capacity: 1)
    private let capacity = 64

    func yield(_ datagram: NowhereQueuedDatagram) {
        let accepted = state.withLock { state in
            guard !state.finished, state.buffer.count < capacity else { return false }
            state.buffer.append(datagram)
            return true
        }
        if accepted { signal.yield(()) }
    }

    func finish(error: Error? = nil) {
        state.withLock { state in
            guard !state.finished else { return }
            state.finished = true
            state.failure = error
            state.buffer.removeAll(keepingCapacity: false)
        }
        signal.finish()
    }

    func next() async throws -> NowhereQueuedDatagram? {
        while true {
            try Task.checkCancellation()
            let result: (datagram: NowhereQueuedDatagram?, finished: Bool) = try state.withLock { state in
                if let error = state.failure {
                    state.failure = nil
                    throw error
                }
                if !state.buffer.isEmpty {
                    return (state.buffer.removeFirst(), false)
                }
                return (nil, state.finished)
            }
            if let datagram = result.datagram { return datagram }
            if result.finished { return nil }
            _ = try await signal.next()
        }
    }
}
