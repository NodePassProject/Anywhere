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
    private let flowHeader: NowhereProtocol.FlowHeader
    private let expectsResult: Bool

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
        var routeRegistered = false
        var controlStreamID: Int64?
    }

    private nonisolated let lifecycle = Mutex(Lifecycle())

    // MARK: Control stream (handshake)

    private let controlInbox = AsyncInbox<Data>()

    // MARK: Inbound datagrams

    private let datagramInbox = AsyncInbox<NowhereQueuedDatagram>(capacity: NowhereUDPConnection.maxBufferedDatagrams)
    private static let maxBufferedDatagrams = 64
    private var nextPacketID: UInt32 = 1

    // MARK: Termination

    private let termination = TerminationLatch()

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

    nonisolated var isConnected: Bool {
        lifecycle.withLock { if case .ready = $0.phase { true } else { false } }
    }
    nonisolated var outerTLSVersion: TLSVersion? { .tls13 }
    nonisolated var deliversDatagrams: Bool { true }

    nonisolated func setNowhereTerminationHandler(_ handler: (@Sendable (Error?) -> Void)?) {
        termination.install(handler)
    }

    // MARK: - Open

    func open() async throws {
        let begin = lifecycle.withLock { $0.transition(to: .opening) }
        guard begin else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
        do {
            _ = try await session.registerUDPSession(self, requestedFlowID: flowHeader.flowID)
            let registrationAdopted = lifecycle.withLock { state in
                guard case .opening = state.phase else { return false }
                state.routeRegistered = true
                return true
            }
            guard registrationAdopted else {
                session.releaseUDPSession(flowHeader.flowID)
                throw AnywhereError.proxy(.nowhere, .streamClosed)
            }
            let request = try NowhereProtocol.encodeFlowRequest(
                header: flowHeader,
                target: flowHeader.carriesTarget ? destination : nil
            )
            let sid = try await session.openUDPControlStream(for: self, request: request)
            let streamAdopted = lifecycle.withLock { state in
                guard case .opening = state.phase else { return false }
                state.controlStreamID = sid
                return true
            }
            guard streamAdopted else {
                session.shutdownStream(sid)
                session.releaseUDPControlStream(sid)
                throw AnywhereError.proxy(.nowhere, .streamClosed)
            }

            if expectsResult {
                var buffer = Data()
                while true {
                    guard let chunk = try await nextControlChunk() else {
                        throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "UDP control stream closed before READY"))
                    }
                    buffer.append(chunk)
                    session.extendStreamOffset(sid, count: chunk.count)
                    guard buffer.count >= NowhereProtocol.flowResultSize else { continue }
                    guard let result = NowhereProtocol.decodeFlowResult(buffer) else {
                        throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Invalid UDP flow result"))
                    }
                    switch result {
                    case .ready:
                        break
                    case .reject(let code):
                        throw AnywhereError.proxy(.nowhere, .flowRejected(code: code.rawValue))
                    }
                    break
                }
            }

            releaseControlStream(reset: false)
            if flowHeader.role != .open {
                session.activateUDPSession(flowHeader.flowID)
                let activated = lifecycle.withLock { $0.transition(to: .ready) }
                guard activated else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
            } else {
                let stillOpening = lifecycle.withLock { state in
                    if case .opening = state.phase { true } else { false }
                }
                guard stillOpening else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
            }
        } catch {
            fail(error)
            throw error
        }
    }

    // MARK: - Demux feed (nonisolated; driven on the ngtcp2 queue)

    nonisolated func handleControlStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty { controlInbox.yield(Data(data)) }
        if fin { controlInbox.finish() }
    }

    nonisolated func handleControlStreamTermination(error: Error?) {
        if let error { controlInbox.finish(throwing: error) } else { controlInbox.finish() }
    }

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
        if case AnywhereError.quic(.closed(graceful: true)) = error {
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

    nonisolated func activatePairedFlow() {
        let opening = lifecycle.withLock { state in
            if case .opening = state.phase { true } else { false }
        }
        guard opening else { return }
        session.activateUDPSession(flowHeader.flowID)
        _ = lifecycle.withLock { $0.transition(to: .ready) }
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
                flowID: flowHeader.flowID,
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
        terminate(error: nil, sendAdvisory: true)
    }

    // MARK: - Teardown

    private nonisolated func terminate(error: Error?, sendAdvisory: Bool) {
        enum Prior { case ready, notReady }
        typealias Cleanup = (prior: Prior, controlStreamID: Int64?, releaseRoute: Bool)
        let cleanup: Cleanup? = lifecycle.withLock { state in
            let prior: Prior
            switch state.phase {
            case .closed: return nil
            case .ready:
                prior = .ready
            case .idle, .opening:
                prior = .notReady
            }
            state.transition(to: .closed)
            let result = (prior, state.controlStreamID, state.routeRegistered)
            state.controlStreamID = nil
            state.routeRegistered = false
            return result
        }
        guard let cleanup else { return }
        if let error {
            datagramInbox.finish(throwing: error)
            controlInbox.finish(throwing: error)
        } else {
            datagramInbox.finish()
            controlInbox.finish()
        }
        termination.fire(error)
        if sendAdvisory {
            Task { [self] in
                await sendCloseFrame()
                finishTeardown(
                    controlStreamID: cleanup.controlStreamID,
                    resetControlStream: cleanup.prior == .notReady,
                    releaseRoute: cleanup.releaseRoute
                )
            }
        } else {
            finishTeardown(
                controlStreamID: cleanup.controlStreamID,
                resetControlStream: cleanup.prior == .notReady,
                releaseRoute: cleanup.releaseRoute
            )
        }
    }

    private func fail(_ error: Error) {
        terminate(error: error, sendAdvisory: false)
    }

    private func sendCloseFrame() async {
        guard let frame = try? NowhereProtocol.encodeUDPControl(type: .close, flowID: flowHeader.flowID) else {
            return
        }
        try? await session.writeDatagrams([frame])
    }

    private nonisolated func finishTeardown(
        controlStreamID: Int64?,
        resetControlStream: Bool,
        releaseRoute: Bool
    ) {
        if let controlStreamID {
            if resetControlStream { session.shutdownStream(controlStreamID) }
            session.releaseUDPControlStream(controlStreamID)
        }
        if releaseRoute {
            session.releaseUDPSession(flowHeader.flowID)
        }
    }

    private nonisolated func releaseControlStream(reset: Bool) {
        let sid = lifecycle.withLock { state -> Int64? in
            defer { state.controlStreamID = nil }
            return state.controlStreamID
        }
        guard let sid else { return }
        if reset { session.shutdownStream(sid) }
        session.releaseUDPControlStream(sid)
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

extension NowhereUDPConnection: ProxyConnection, NowhereTerminationObservable {}
