//
//  NowhereUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

nonisolated final class NowhereUDPConnection: ProxyConnection, NowhereTerminationObservable {

    enum State { case idle, openingControl, waitingResult, ready, closed }

    enum ControlResultStep: Equatable {
        case needMore
        case ready
        case reject(NowhereProtocol.FlowRejectCode)
        case invalid
    }

    private let session: NowhereSession
    private let destination: String
    private let flowHeader: NowhereProtocol.FlowHeader
    private let expectsResult: Bool

    private var _state: State = .idle
    private var state: State {
        get { _state }
        set {
            _state = newValue
            _isReady.store(newValue == .ready, ordering: .relaxed)
        }
    }
    private let _isReady = Atomic<Bool>(false)

    private var controlStreamID: Int64 = -1
    private var controlBuffer = Data()
    private var controlReadClosed = false
    /// Resolves when the UDP flow result is demuxed (or the open fails). The waiter
    /// continuation lives in the promise (async infra), bridging the control-stream handshake.
    private let openPromise = AsyncPromise<Void>()

    /// Reassembled inbound datagrams / EOF / error, pushed on `session.queue` (inside ngtcp2's
    /// recv_datagram) and pulled by `receiveRaw`. The session's byte budget (`reserveUDPBuffer`)
    /// bounds how much can queue here — datagrams are dropped once the budget is exhausted.
    private let inbox = AsyncByteChannel()
    /// Bytes reserved for datagrams still queued in `inbox`; released on consume or close.
    private var reservedInboxBytes = 0
    /// Serializes framed datagram writes (and PacketID allocation) across the wire `await`.
    private let sendMutex = AsyncMutex()

    private struct TerminationState {
        var handler: ((Error?) -> Void)?
        var terminated = false
        var error: Error?
    }
    private let termination = Mutex(TerminationState())

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
    /// Pending TTL sweep of `defragSlots`, confined to `session.queue`.
    private var defragCleanup: Task<Void, Never>?
    private var nextPacketID: UInt32 = 1

    init(
        session: NowhereSession,
        destination: String,
        flowHeader: NowhereProtocol.FlowHeader
    ) {
        self.session = session
        self.destination = destination
        self.flowHeader = flowHeader
        self.expectsResult = flowHeader.role != .open
    }

    var isConnected: Bool {
        _isReady.load(ordering: .relaxed)
    }

    var outerTLSVersion: TLSVersion? { .tls13 }
    var deliversDatagrams: Bool { true }

    func setNowhereTerminationHandler(_ handler: ((Error?) -> Void)?) {
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

    func open() async throws {
        // Claim the flow on the ngtcp2 queue; `openPromise` resolves later in
        // `finishOpen` (result) or `fail` (error).
        let started: Bool = await session.run { [self] in
            guard state == .idle else { return false }
            state = .openingControl
            return true
        }
        guard started else { throw NowhereError.notReady }

        // Register the flow, then open the control stream.
        Task { [weak self] in
            guard let self else { return }
            do {
                _ = try await self.session.registerUDPSession(
                    self,
                    requestedFlowID: self.flowHeader.flowID
                )
                self.openControlStream()
            } catch {
                await self.session.run { self.fail(error) }
            }
        }
        try await openPromise.value()
    }

    private func openControlStream() {
        Task { [weak self] in
            guard let self else { return }
            let sid: Int64
            do {
                sid = try await self.session.openUDPControlStream(for: self)
            } catch {
                self.session.queue.async { self.fail(error) }
                return
            }
            self.session.queue.async {
                // Adopt the stream id on the session queue before sending the request, so
                // interleaved control data / termination race against a valid id. If we
                // already terminated during the open hop, reset and release the freshly opened
                // stream (teardown ran before the id was adopted, so it couldn't).
                guard self.state == .openingControl else {
                    self.session.shutdownStream(sid)
                    self.session.releaseUDPControlStream(sid)
                    return
                }
                self.controlStreamID = sid

                let request: Data
                do {
                    request = try NowhereProtocol.encodeFlowRequest(
                        header: self.flowHeader,
                        target: self.destination,
                        protocolSpec: self.session.protocolSpec
                    )
                } catch {
                    self.fail(error)
                    return
                }

                Task { [weak self] in
                    guard let self else { return }
                    let writeError: Error?
                    do {
                        try await self.session.writeStream(sid, data: request, fin: true)
                        writeError = nil
                    } catch {
                        writeError = error
                    }
                    self.session.queue.async {
                        // Peer data/FIN can beat this local write callback. A complete
                        // buffered F2 is authoritative and must be consumed first.
                        self.processControlResultIfAvailable()
                        guard self.state == .openingControl else { return }
                        if let writeError {
                            self.fail(writeError)
                            return
                        }
                        guard self.state == .openingControl else { return }
                        if self.expectsResult {
                            self.state = .waitingResult
                            self.processControlResultIfAvailable()
                        } else {
                            self.releaseControlStream(reset: false)
                            self.finishOpen()
                        }
                    }
                }
            }
        }
    }

    func handleControlStreamData(_ data: Data, fin: Bool) {
        dispatchPrecondition(condition: .onQueue(session.queue))
        guard state != .closed else { return }
        if !data.isEmpty {
            controlBuffer.append(data)
            if controlStreamID >= 0 {
                session.extendStreamOffset(controlStreamID, count: data.count)
            }
        }
        if fin { controlReadClosed = true }

        if state == .openingControl || state == .waitingResult {
            processControlResultIfAvailable()
            if Self.shouldFailControlEOF(
                expectsResult: expectsResult,
                state: state,
                bufferedBytes: controlBuffer.count
            ) {
                fail(NowhereError.connectionFailed("UDP control stream closed before READY"))
            }
            return
        }

        if state == .ready, !controlBuffer.isEmpty {
            fail(NowhereError.connectionFailed("Unexpected UDP control data"))
        }
    }

    func handleControlStreamTermination(error: Error?) {
        dispatchPrecondition(condition: .onQueue(session.queue))
        controlStreamID = -1
        // ngtcp2 may report data+FIN before the local write completion. Accept a
        // complete READY/REJECT already buffered before interpreting termination.
        processControlResultIfAvailable()
        guard state != .ready, state != .closed else { return }
        if let error {
            fail(error)
        } else if expectsResult, state != .ready && state != .closed {
            fail(NowhereError.connectionFailed("UDP control stream closed before READY"))
        }
    }

    private func processControlResultIfAvailable() {
        switch Self.controlResultStep(state: state, buffer: controlBuffer) {
        case .needMore:
            return
        case .invalid:
            fail(NowhereError.connectionFailed("Invalid UDP flow result"))
        case .ready:
            controlBuffer.removeAll(keepingCapacity: false)
            releaseControlStream(reset: false)
            finishOpen()
        case .reject(let code):
            controlBuffer.removeAll(keepingCapacity: false)
            releaseControlStream(reset: false)
            fail(NowhereError.flowRejected(code))
        }
    }

    static func controlResultStep(state: State, buffer: Data) -> ControlResultStep {
        guard state == .openingControl || state == .waitingResult else { return .needMore }
        guard buffer.count >= NowhereProtocol.flowResultSize else { return .needMore }
        guard buffer.count == NowhereProtocol.flowResultSize,
              let result = NowhereProtocol.decodeFlowResult(buffer) else { return .invalid }
        switch result {
        case .ready: return .ready
        case .reject(let code): return .reject(code)
        }
    }

    static func shouldFailControlEOF(
        expectsResult: Bool,
        state: State,
        bufferedBytes: Int
    ) -> Bool {
        expectsResult && state != .ready
            && bufferedBytes < NowhereProtocol.flowResultSize
    }

    private func finishOpen() {
        guard state != .closed else { return }
        state = .ready
        openPromise.resolve(.success(()))
    }

    func handleFlowClose() {
        dispatchPrecondition(condition: .onQueue(session.queue))
        closeNormally(sendAdvisory: false)
    }

    func handleIncomingDatagram(_ message: NowhereProtocol.UDPMessage) {
        dispatchPrecondition(condition: .onQueue(session.queue))
        guard state == .ready else { return }
        if message.fragmentCount == 1 {
            guard session.reserveUDPBuffer(bytes: message.payload.count, reassemblySlot: false) else {
                return
            }
            deliverReservedPacket(message.payload, reservedBytes: message.payload.count)
            return
        }
        guard let payload = assembleFragment(message) else { return }
        deliverReservedPacket(payload, reservedBytes: Int(message.totalLength))
    }

    private func deliverReservedPacket(_ payload: Data, reservedBytes: Int) {
        // The reservation stays held until the app consumes this datagram in `receiveRaw`
        // (or the flow closes); `reservedBytes` equals `payload.count`.
        reservedInboxBytes += reservedBytes
        inbox.yield(payload)
    }

    func sendRaw(_ data: Data) async throws {
        guard _isReady.load(ordering: .relaxed) else {
            throw NowhereError.streamClosed
        }
        // Serialize so PacketID allocation and datagram order match on-wire order.
        try await sendMutex.withLock {
            try await self.attemptSend(
                data: data,
                packetID: self.newPacketID(),
                maxSizeOverride: nil,
                retriesLeft: 1
            )
        }
    }

    /// Runs under `sendMutex`.
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
                // The first batch may have been partially transmitted before the path MTU
                // changed. A new identity prevents the receiver from mixing fragments
                // encoded with different geometry.
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
                // The path bound changed again. Drop this packet without closing the flow.
                return
            }
            if let quicError = error as? QUICConnection.QUICError,
               case .datagramQueueFull = quicError {
                // Reject newest packet atomically; preserve queued packets and the flow.
                return
            }
            throw error
        }
    }

    func receiveRaw() async throws -> Data? {
        let data = try await inbox.next()
        if let data {
            consumeReservation(bytes: data.count)
        }
        return data
    }

    /// Frees the byte budget held for a consumed datagram, on `session.queue`. Skips a
    /// connection already closed (close released the whole reservation at once).
    private func consumeReservation(bytes: Int) {
        let body = { [weak self] in
            guard let self, self.state != .closed else { return }
            self.reservedInboxBytes = max(0, self.reservedInboxBytes - bytes)
            self.session.releaseUDPBuffer(bytes: bytes, reassemblySlot: false)
        }
        if session.isOnQueue { body() } else { session.queue.async(execute: body) }
    }

    func cancel() {
        session.queue.async { [weak self] in
            self?.closeNormally(sendAdvisory: true)
        }
    }

    private func closeNormally(sendAdvisory: Bool) {
        guard state != .closed else { return }
        let wasReady = state == .ready
        state = .closed
        if sendAdvisory { sendCloseFrame() }
        releaseControlStream(reset: !wasReady)
        session.releaseUDPSession(flowHeader.flowID)
        releaseAllBufferedData()
        openPromise.resolve(.failure(NowhereError.streamClosed))
        inbox.cancel()
        notifyTermination(error: nil)
    }

    private func sendCloseFrame() {
        guard let frame = try? NowhereProtocol.encodeUDPControl(
            type: .close,
            flowID: flowHeader.flowID
        ) else { return }
        // Best-effort advisory close, over the QUIC ngtcp2-boundary continuation.
        Task { [weak self] in
            try? await self?.session.writeDatagrams([frame])
        }
    }

    private func releaseControlStream(reset: Bool) {
        guard controlStreamID >= 0 else { return }
        let sid = controlStreamID
        controlStreamID = -1
        if reset { session.shutdownStream(sid) }
        session.releaseUDPControlStream(sid)
    }

    func handleSessionError(_ error: Error) {
        if let quicError = error as? QUICConnection.QUICError, case .closedOK = quicError {
            handleSessionClose()
            return
        }
        session.queue.async { [weak self] in self?.fail(error) }
    }

    func handleSessionClose() {
        session.queue.async { [weak self] in
            self?.closeNormally(sendAdvisory: false)
        }
    }

    private func fail(_ error: Error) {
        guard state != .closed else { return }
        state = .closed
        releaseControlStream(reset: true)
        session.releaseUDPSession(flowHeader.flowID)
        releaseAllBufferedData()
        openPromise.resolve(.failure(error))
        // Ordered after every datagram already queued in the inbox; the error surfaces
        // on the next (or a parked) receive, replacing the old `closureError` stash.
        inbox.fail(error)
        notifyTermination(error: error)
    }

    private func notifyTermination(error: Error?) {
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

    /// Returns a complete packet while keeping its `totalLength` byte reservation;
    /// the caller transfers that reservation to immediate delivery or the packet queue.
    private func assembleFragment(_ message: NowhereProtocol.UDPMessage) -> Data? {
        guard message.fragmentCount > 1,
              message.fragmentID < message.fragmentCount else { return nil }
        cleanupExpiredDefragSlots()
        let now = DispatchTime.now()
        var slot: DefragSlot

        if let existing = defragSlots[message.packetID],
           existing.fragmentCount == Int(message.fragmentCount),
           existing.totalLength == Int(message.totalLength) {
            slot = existing
        } else {
            if let old = defragSlots.removeValue(forKey: message.packetID) {
                session.releaseUDPBuffer(bytes: old.totalLength, reassemblySlot: true)
            }
            let totalLength = Int(message.totalLength)
            guard session.reserveUDPBuffer(bytes: totalLength, reassemblySlot: true) else {
                return nil
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
        if let existing = slot.fragments[index] {
            if existing != message.payload {
                defragSlots.removeValue(forKey: message.packetID)
                session.releaseUDPBuffer(bytes: slot.totalLength, reassemblySlot: true)
                scheduleDefragCleanup()
            }
            return nil
        }
        guard slot.receivedBytes <= slot.totalLength - message.payload.count else {
            defragSlots.removeValue(forKey: message.packetID)
            session.releaseUDPBuffer(bytes: slot.totalLength, reassemblySlot: true)
            scheduleDefragCleanup()
            return nil
        }
        slot.fragments[index] = message.payload
        slot.received += 1
        slot.receivedBytes += message.payload.count
        if slot.received < slot.fragmentCount {
            defragSlots[message.packetID] = slot
            scheduleDefragCleanup()
            return nil
        }

        defragSlots.removeValue(forKey: message.packetID)
        session.releaseUDPBuffer(bytes: 0, reassemblySlot: true)
        scheduleDefragCleanup()
        var full = Data(capacity: slot.totalLength)
        for fragment in slot.fragments {
            guard let fragment else {
                session.releaseUDPBuffer(bytes: slot.totalLength, reassemblySlot: false)
                return nil
            }
            full.append(fragment)
        }
        guard full.count == slot.totalLength else {
            session.releaseUDPBuffer(bytes: slot.totalLength, reassemblySlot: false)
            return nil
        }
        return full
    }

    private func cleanupExpiredDefragSlots() {
        let now = DispatchTime.now().uptimeNanoseconds
        var expired: [UInt32] = []
        for (key, slot) in defragSlots {
            let created = slot.createdAt.uptimeNanoseconds
            if now >= created, now - created >= Self.defragSlotTTLNanos {
                expired.append(key)
            }
        }
        for key in expired {
            if let slot = defragSlots.removeValue(forKey: key) {
                session.releaseUDPBuffer(bytes: slot.totalLength, reassemblySlot: true)
            }
        }
    }

    private func scheduleDefragCleanup() {
        defragCleanup?.cancel()
        defragCleanup = nil
        guard let earliest = defragSlots.values.map(\.createdAt.uptimeNanoseconds).min() else { return }
        let deadlineNanos = earliest + Self.defragSlotTTLNanos
        let nowNanos = DispatchTime.now().uptimeNanoseconds
        let delayNanos = deadlineNanos > nowNanos ? deadlineNanos - nowNanos : 0
        // Fires on `session.queue` (hopped back on) so the sweep and reschedule stay
        // serialized with the defrag state.
        defragCleanup = Task { [weak self] in
            try? await Task.sleep(nanoseconds: delayNanos)
            guard !Task.isCancelled, let self else { return }
            self.session.queue.async {
                self.cleanupExpiredDefragSlots()
                self.scheduleDefragCleanup()
            }
        }
    }

    private func releaseAllBufferedData() {
        defragCleanup?.cancel()
        defragCleanup = nil
        // Release reservations for datagrams still queued in the inbox (cancel/fail discards
        // the queued items without a per-item consume hook).
        if reservedInboxBytes > 0 {
            session.releaseUDPBuffer(bytes: reservedInboxBytes, reassemblySlot: false)
            reservedInboxBytes = 0
        }
        for slot in defragSlots.values {
            session.releaseUDPBuffer(bytes: slot.totalLength, reassemblySlot: true)
        }
        defragSlots.removeAll(keepingCapacity: false)
    }

    /// Next PacketID; called only under `sendMutex`, so no queue confinement is needed.
    private func newPacketID() -> UInt32 {
        let packetID = nextPacketID
        nextPacketID = Self.advancedPacketID(after: packetID)
        return packetID
    }

    static func advancedPacketID(after packetID: UInt32) -> UInt32 {
        packetID == UInt32.max ? 1 : packetID + 1
    }
}
