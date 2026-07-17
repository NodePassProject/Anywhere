//
//  NowhereUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

actor NowhereUDPConnection: ProxyConnection, NowhereTerminationObservable {

    private let session: NowhereSession
    private let destination: String
    private let flowHeader: NowhereProtocol.FlowHeader
    private let expectsResult: Bool

    /// Readiness mirror for the nonisolated `isConnected`/send-guard.
    private nonisolated let _isReady = Atomic<Bool>(false)

    // MARK: Control stream (handshake)

    private nonisolated let controlInbox: AsyncThrowingStream<Data, Error>.Continuation
    private var controlIterator: AsyncThrowingStream<Data, Error>.AsyncIterator
    private var controlStreamID: Int64 = -1

    // MARK: Inbound datagrams

    /// Bounded so a burst that outruns the reader drops oldest rather than growing without limit.
    private nonisolated let datagramInbox: AsyncThrowingStream<NowhereProtocol.UDPMessage, Error>.Continuation
    private var datagramIterator: AsyncThrowingStream<NowhereProtocol.UDPMessage, Error>.AsyncIterator
    private static let maxBufferedDatagrams = 512

    // MARK: Reassembly (actor-isolated)

    private struct DefragSlot {
        var fragments: [Data?]
        var received: Int
        var receivedBytes: Int
        let fragmentCount: Int
        let totalLength: Int
        let createdAt: DispatchTime
    }
    private var defragSlots: [UInt32: DefragSlot] = [:]
    private static let defragSlotTTLNanos: UInt64 = 10 * 1_000_000_000
    private static let maxDefragSlots = 32
    private var nextPacketID: UInt32 = 1

    // MARK: Termination

    private struct TerminationState {
        var handler: ((Error?) -> Void)?
        var terminated = false
        var error: Error?
    }
    private let termination = Mutex(TerminationState())

    /// Guards `teardown()` so the flow is released exactly once.
    private var closed = false

    init(
        session: NowhereSession,
        destination: String,
        flowHeader: NowhereProtocol.FlowHeader
    ) {
        self.session = session
        self.destination = destination
        self.flowHeader = flowHeader
        self.expectsResult = flowHeader.role != .open
        let (controlStream, controlInbox) = AsyncThrowingStream.makeStream(of: Data.self)
        self.controlInbox = controlInbox
        self.controlIterator = controlStream.makeAsyncIterator()
        let (datagramStream, datagramInbox) = AsyncThrowingStream.makeStream(
            of: NowhereProtocol.UDPMessage.self,
            bufferingPolicy: .bufferingNewest(Self.maxBufferedDatagrams)
        )
        self.datagramInbox = datagramInbox
        self.datagramIterator = datagramStream.makeAsyncIterator()
    }

    nonisolated var isConnected: Bool { _isReady.load(ordering: .relaxed) }
    nonisolated var outerTLSVersion: TLSVersion? { .tls13 }
    nonisolated var deliversDatagrams: Bool { true }

    nonisolated func setNowhereTerminationHandler(_ handler: ((Error?) -> Void)?) {
        let immediate: (((Error?) -> Void), Error?)? = termination.withLock { state in
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
            let sid = try await session.openUDPControlStream(for: self)
            controlStreamID = sid

            let request = try NowhereProtocol.encodeFlowRequest(
                header: flowHeader,
                target: destination,
                protocolSpec: session.protocolSpec
            )
            // Half-close our send side: the control stream carries only this one request.
            try await session.writeStream(sid, data: request, fin: true)

            if expectsResult {
                var buffer = Data()
                while true {
                    guard let chunk = try await nextControlChunk() else {
                        throw NowhereError.connectionFailed("UDP control stream closed before READY")
                    }
                    buffer.append(chunk)
                    session.extendStreamOffset(sid, count: chunk.count)
                    guard buffer.count >= NowhereProtocol.flowResultSize else { continue }
                    guard buffer.count == NowhereProtocol.flowResultSize,
                          let result = NowhereProtocol.decodeFlowResult(buffer) else {
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
            _isReady.store(true, ordering: .relaxed)
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
    nonisolated func handleIncomingDatagram(_ message: NowhereProtocol.UDPMessage) {
        datagramInbox.yield(message)
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
        while true {
            guard let message = try await nextDatagram() else { return nil }
            let payload: Data?
            if message.fragmentCount <= 1 {
                payload = message.payload
            } else {
                payload = assembleFragment(message)
            }
            guard let out = payload, !out.isEmpty else { continue }
            return out
        }
    }

    func sendRaw(_ data: Data) async throws {
        guard _isReady.load(ordering: .relaxed) else {
            throw NowhereError.streamClosed
        }
        // No send lock: actor isolation makes PacketID allocation atomic (distinct ids per
        // concurrent send), and QUIC writes each datagram batch atomically.
        try await attemptSend(data: data, packetID: newPacketID(), maxSizeOverride: nil, retriesLeft: 1)
    }

    private func attemptSend(
        data: Data,
        packetID: UInt32,
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
                    packetID: newPacketID(),
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
        defragSlots.removeAll()
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
        let handler: ((Error?) -> Void)? = termination.withLock { state in
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
        var iterator = controlIterator
        let next = try await iterator.next()
        controlIterator = iterator
        return next
    }

    private func nextDatagram() async throws -> NowhereProtocol.UDPMessage? {
        var iterator = datagramIterator
        let next = try await iterator.next()
        datagramIterator = iterator
        return next
    }

    // MARK: - Reassembly

    private func assembleFragment(_ message: NowhereProtocol.UDPMessage) -> Data? {
        guard message.fragmentCount > 1, message.fragmentID < message.fragmentCount else { return nil }
        cleanupExpiredDefragSlots()
        let now = DispatchTime.now()
        let totalLength = Int(message.totalLength)

        var slot: DefragSlot
        if let existing = defragSlots[message.packetID],
           existing.fragmentCount == Int(message.fragmentCount),
           existing.totalLength == totalLength {
            slot = existing
        } else {
            // New slot: evict the oldest first if at the cap.
            if defragSlots[message.packetID] == nil, defragSlots.count >= Self.maxDefragSlots {
                if let victim = defragSlots.min(by: { $0.value.createdAt < $1.value.createdAt })?.key {
                    defragSlots.removeValue(forKey: victim)
                }
            }
            slot = DefragSlot(
                fragments: Array(repeating: nil, count: Int(message.fragmentCount)),
                received: 0,
                receivedBytes: 0,
                fragmentCount: Int(message.fragmentCount),
                totalLength: totalLength,
                createdAt: now
            )
        }

        let index = Int(message.fragmentID)
        if slot.fragments[index] != nil {
            return nil  // duplicate fragment
        }
        guard slot.receivedBytes + message.payload.count <= totalLength else {
            defragSlots.removeValue(forKey: message.packetID)
            return nil  // overflows the declared length
        }
        slot.fragments[index] = message.payload
        slot.received += 1
        slot.receivedBytes += message.payload.count

        if slot.received < slot.fragmentCount {
            defragSlots[message.packetID] = slot
            return nil
        }

        defragSlots.removeValue(forKey: message.packetID)
        var full = Data(capacity: totalLength)
        for fragment in slot.fragments {
            guard let fragment else { return nil }
            full.append(fragment)
        }
        guard full.count == totalLength else { return nil }
        return full
    }

    private func cleanupExpiredDefragSlots() {
        let now = DispatchTime.now().uptimeNanoseconds
        defragSlots = defragSlots.filter { now &- $0.value.createdAt.uptimeNanoseconds < Self.defragSlotTTLNanos }
    }

    // MARK: - Helpers

    /// Next PacketID. Actor-isolated, so concurrent sends never collide.
    private func newPacketID() -> UInt32 {
        let packetID = nextPacketID
        nextPacketID = nextPacketID == UInt32.max ? 1 : nextPacketID + 1
        return packetID
    }
}
