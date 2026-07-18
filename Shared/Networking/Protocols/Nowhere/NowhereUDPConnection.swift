//
//  NowhereUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

// MARK: Various code quality violation issues in this file (handler patterns), consider refactor

import Foundation
import Synchronization

actor NowhereUDPConnection {

    private let session: NowhereSession
    private let destination: NowhereProtocol.Target
    private let flowHeader: NowhereProtocol.FlowHeader
    private let expectsResult: Bool

    /// Readiness mirror for the nonisolated `isConnected`/send-guard.
    private nonisolated let _isReady = Atomic<Bool>(false)

    // MARK: Control stream (handshake)

    /// Control-stream bytes for the flow-open handshake. Producer is `Sendable` (ngtcp2 queue);
    /// single consumer via `nextControlChunk()`.
    private let controlInbox = AsyncInbox<Data>()
    private var controlStreamID: Int64 = -1

    // MARK: Inbound datagrams

    /// Bounded so a burst that outruns the reader drops the newest rather than growing without
    /// limit; single consumer via `nextDatagram()`.
    private let datagramInbox = AsyncInbox<NowhereQueuedDatagram>(capacity: NowhereUDPConnection.maxBufferedDatagrams)
    private static let maxBufferedDatagrams = 64
    private var nextPacketID: UInt32 = 1

    // MARK: Termination

    private struct TerminationState {
        var handler: (@Sendable (Error?) -> Void)?
        var terminated = false
        var error: Error?
    }
    private let termination = Mutex(TerminationState())

    /// Guards `teardown()` so the flow is released exactly once.
    private var closed = false

    init(
        session: NowhereSession,
        destination: NowhereProtocol.Target,
        flowHeader: NowhereProtocol.FlowHeader
    ) {
        self.session = session
        self.destination = destination
        self.flowHeader = flowHeader
        self.expectsResult = flowHeader.role != .open
    }

    nonisolated var isConnected: Bool { _isReady.load(ordering: .relaxed) }
    nonisolated var outerTLSVersion: TLSVersion? { .tls13 }
    nonisolated var deliversDatagrams: Bool { true }

    nonisolated func setNowhereTerminationHandler(_ handler: (@Sendable (Error?) -> Void)?) {
        let immediate: ((@Sendable (Error?) -> Void), Error?)? = termination.withLock { state in
            if state.terminated {
                guard let handler else { return nil }
                return (handler, state.error)
            }
            state.handler = handler
            return nil
        }
        immediate?.0(immediate?.1)
    }

    // MARK: - Open

    func open() async throws {
        do {
            _ = try await session.registerUDPSession(self, requestedFlowID: flowHeader.flowID)
            let request = try NowhereProtocol.encodeFlowRequest(
                header: flowHeader,
                target: flowHeader.carriesTarget ? destination : nil
            )
            let sid = try await session.openUDPControlStream(for: self, request: request)
            controlStreamID = sid

            if expectsResult {
                var buffer = Data()
                while true {
                    guard let chunk = try await nextControlChunk() else {
                        throw NowhereError.connectionFailed("UDP control stream closed before READY")
                    }
                    buffer.append(chunk)
                    session.extendStreamOffset(sid, count: chunk.count)
                    guard buffer.count >= NowhereProtocol.flowResultSize else { continue }
                    guard let result = NowhereProtocol.decodeFlowResult(buffer) else {
                        throw NowhereError.connectionFailed("Invalid UDP flow result")
                    }
                    switch result {
                    case .ready:
                        break
                    case .reject(let code):
                        throw NowhereError.flowRejected(code)
                    }
                    break
                }
            }

            // Handshake done: the control stream is no longer needed.
            releaseControlStream(reset: false)
            if flowHeader.role != .open {
                await session.activateUDPSession(flowHeader.flowID)
                _isReady.store(true, ordering: .relaxed)
            }
        } catch {
            fail(error)
            throw error
        }
    }

    // MARK: - Demux feed (nonisolated; driven on the ngtcp2 queue)

    /// Control-stream bytes / FIN — the flow-open handshake response.
    nonisolated func handleControlStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty { controlInbox.yield(Data(data)) }
        if fin { controlInbox.finish() }
    }

    nonisolated func handleControlStreamTermination(error: Error?) {
        if let error { controlInbox.finish(throwing: error) } else { controlInbox.finish() }
    }

    /// One inbound `.data` datagram (the session filters `.close` into `handleFlowClose`).
    nonisolated func handleIncomingDatagram(_ datagram: NowhereQueuedDatagram) {
        datagramInbox.yield(datagram)
    }

    nonisolated func handleFlowClose() {
        terminate(error: nil, sendAdvisory: false)
    }

    nonisolated func handleSessionClose() {
        terminate(error: nil, sendAdvisory: false)
    }

    nonisolated func handleSessionError(_ error: Error) {
        if let quicError = error as? QUICConnection.QUICError, case .closedOK = quicError {
            terminate(error: nil, sendAdvisory: false)
        } else {
            terminate(error: error, sendAdvisory: false)
        }
    }

    // MARK: - ProxyConnection overrides

    func receiveRaw() async throws -> Data? {
        guard let datagram = try await nextDatagram() else { return nil }
        return datagram.payload
    }

    /// Called by the logical split-flow coordinator after the selected downlink has READY.
    func activatePairedFlow() async {
        guard !_isReady.load(ordering: .relaxed), !closed else { return }
        await session.activateUDPSession(flowHeader.flowID)
        _isReady.store(true, ordering: .relaxed)
    }

    func sendRaw(_ data: Data) async throws {
        guard _isReady.load(ordering: .relaxed) else {
            throw NowhereError.streamClosed
        }
        // Packet IDs are allocated only when the final PMTU requires fragmentation.
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
                flowID: flowHeader.flowID,
                packetID: packetID,
                payload: data,
                maxDatagramSize: maxSize
            )
        } catch NowhereError.udpPacketTooLarge {
            // UDP is lossy by contract. Drop only this packet; keep the flow alive.
            return
        }
        do {
            try await session.writeDatagrams(frames)
        } catch {
            if let quicError = error as? QUICConnection.QUICError,
               case .datagramTooLarge(let maxBound) = quicError,
               retriesLeft > 0 {
                guard _isReady.load(ordering: .relaxed) else {
                    throw NowhereError.streamClosed
                }
                // A new identity prevents the receiver from mixing fragments encoded with
                // different geometry after the path MTU changed mid-send.
                try await attemptSend(
                    data: data,
                    maxSizeOverride: maxBound,
                    retriesLeft: retriesLeft - 1
                )
                return
            }
            if let quicError = error as? QUICConnection.QUICError,
               case .datagramTooLarge = quicError {
                return  // path bound changed again; drop without closing the flow
            }
            if let quicError = error as? QUICConnection.QUICError,
               case .datagramQueueFull = quicError {
                return  // reject newest packet; preserve queued packets and the flow
            }
            throw error
        }
    }

    nonisolated func cancel() {
        terminate(error: nil, sendAdvisory: true)
    }

    // MARK: - Teardown

    /// Single terminal path: mirrors readiness off, finishes both inboxes, fires the termination
    /// handler once, and hops a `Task` to the isolated release work.
    private nonisolated func terminate(error: Error?, sendAdvisory: Bool) {
        let wasReady = _isReady.exchange(false, ordering: .relaxed)
        if let error {
            datagramInbox.finish(throwing: error)
            controlInbox.finish(throwing: error)
        } else {
            datagramInbox.finish()
            controlInbox.finish()
        }
        notifyTermination(error: error)
        Task { await self.teardown(sendAdvisory: sendAdvisory, reset: !wasReady) }
    }

    private func fail(_ error: Error) {
        terminate(error: error, sendAdvisory: false)
    }

    private func teardown(sendAdvisory: Bool, reset: Bool) async {
        guard !closed else { return }
        closed = true
        if sendAdvisory { await sendCloseFrame() }
        releaseControlStream(reset: reset)
        session.releaseUDPSession(flowHeader.flowID)
    }

    private func sendCloseFrame() async {
        guard let frame = try? NowhereProtocol.encodeUDPControl(type: .close, flowID: flowHeader.flowID) else {
            return
        }
        try? await session.writeDatagrams([frame])
    }

    private func releaseControlStream(reset: Bool) {
        guard controlStreamID >= 0 else { return }
        let sid = controlStreamID
        controlStreamID = -1
        if reset { session.shutdownStream(sid) }
        session.releaseUDPControlStream(sid)
    }

    private nonisolated func notifyTermination(error: Error?) {
        let handler: (@Sendable (Error?) -> Void)? = termination.withLock { state in
            guard !state.terminated else { return nil }
            state.terminated = true
            state.error = error
            let handler = state.handler
            state.handler = nil
            return handler
        }
        handler?(error)
    }

    // MARK: - Pull helpers

    private func nextControlChunk() async throws -> Data? {
        try await controlInbox.next()
    }

    private func nextDatagram() async throws -> NowhereQueuedDatagram? {
        try await datagramInbox.next()
    }

    // MARK: - Helpers

    /// Next PacketID. Actor-isolated, so concurrent sends never collide.
    private func newPacketID() -> UInt32 {
        let packetID = nextPacketID
        nextPacketID = nextPacketID == UInt32.max ? 1 : nextPacketID + 1
        return packetID
    }
}

extension NowhereUDPConnection: ProxyConnection, NowhereTerminationObservable {}
