//
//  AnyTLSMultiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "AnyTLSMultiplexer")

nonisolated final class AnyTLSMultiplexer: Multiplexer, Sendable {

    // MARK: - Properties

    private let inner: ProxyConnection
    private let outerTLSVersion: TLSVersion?
    private let passwordHash: Data

    enum Phase: PhaseTransitionable {
        case idle
        case starting
        case ready
        case closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .starting),
                 (.starting, .ready):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }

    private struct State: PhaseHolding {
        var phase: Phase = .idle

        var padding: AnyTLSPaddingScheme

        var streams: [UInt32: AnyTLSStream] = [:]
        var nextStreamID: UInt32 = 0
        var peerVersion: UInt8 = 0

        var packetCounter: UInt32 = 0
        var sendPadding: Bool = true

        var buffering: Bool = true
        var outboundBuffer: Data = Data()

        var synDoneDeadline: DeadlineToken?

        var readTask: Task<Void, Never>?

        var receiveBuffer = Data()

        var reserved: Bool = false
    }

    private let state: Mutex<State>

    private let sendChain = SerialSender()

    let seq: UInt64

    private let onClose: (@Sendable (AnyTLSMultiplexer) -> Void)?

    // MARK: - Init

    init(inner: ProxyConnection, passwordHash: Data, padding: AnyTLSPaddingScheme,
         seq: UInt64 = 0, onClose: (@Sendable (AnyTLSMultiplexer) -> Void)? = nil) {
        self.inner = inner
        self.outerTLSVersion = inner.outerTLSVersion
        self.passwordHash = passwordHash
        self.seq = seq
        self.onClose = onClose
        self.state = Mutex(State(padding: padding))
    }

    // MARK: - Capacity

    var isClosed: Bool { state.withLock { $0.phase == .closed } }

    var activeStreamCount: Int { state.withLock { $0.streams.count + ($0.reserved ? 1 : 0) } }

    func tryReserveStream() -> Bool {
        state.withLock { state in
            guard state.phase != .closed, !state.reserved, state.streams.isEmpty else { return false }
            state.reserved = true
            return true
        }
    }

    func releaseReservation() {
        state.withLock { $0.reserved = false }
    }

    // MARK: - Lifecycle

    func start() async {
        guard state.withLock({ $0.transition(to: .starting) }) else { return }
        let padding = state.withLock { $0.padding }
        var prologue = Data()
        prologue.append(passwordHash)
        let paddingLength: Int
        let firstSchedule = padding.generateRecordPayloadSizes(packet: 0)
        if let first = firstSchedule.first, first > 0 {
            paddingLength = first
        } else {
            paddingLength = 0
        }
        prologue.append(UInt8((paddingLength >> 8) & 0xFF))
        prologue.append(UInt8( paddingLength       & 0xFF))
        if paddingLength > 0 {
            prologue.append(Data(repeating: 0, count: paddingLength))
        }
        do {
            let pending = state.withLock { chainSend(prologue, state: &$0) }
            try await pending.value()
        } catch {
            handleTransportFailure(error)
            return
        }

        let settings: [String: String] = [
            "v": "2",
            "client": AnyTLSProtocol.clientVersion,
            "padding-md5": padding.md5Hex,
        ]
        let payload = AnyTLSProtocol.encodeStringMap(settings)
        try? await writeControl(cmd: AnyTLSProtocol.cmdSettings, sid: 0, payload: payload)

        startReadLoop()
    }

    private func armSynDoneTimerLocked(_ state: inout State) {
        state.synDoneDeadline?.cancel()
        state.synDoneDeadline = TickScheduler.shared.schedule(in: .seconds(3), precision: .relaxed) { [weak self] in
            self?.close(error: AnywhereError.proxy(.anyTLS, .openTimeout))
        }
    }

    private func cancelSynDoneTimerLocked(_ state: inout State) {
        state.synDoneDeadline?.cancel()
        state.synDoneDeadline = nil
    }

    // MARK: - Streams

    func openStream(onEnd: (@Sendable () -> Void)? = nil) async -> AnyTLSStream? {
        typealias Opened = (
            stream: AnyTLSStream,
            sid: UInt32,
            armWatchdog: Bool,
            bufferedBytes: Int,
            peerVersion: UInt8
        )
        let opened: Opened? = state.withLock { (state: inout State) -> Opened? in
            if state.phase == .closed {
                return nil
            }
            state.nextStreamID &+= 1
            if state.nextStreamID == 0 { state.nextStreamID = 1 }    // skip 0 (reserved for control)
            let sid = state.nextStreamID
            let stream = AnyTLSStream(
                sid: sid,
                multiplexer: self,
                outerTLSVersion: outerTLSVersion,
                onEnd: onEnd
            )
            state.streams[sid] = stream

            let armWatchdog = sid >= 2 && state.peerVersion >= 2
            if armWatchdog {
                armSynDoneTimerLocked(&state)
            }
            return (stream, sid, armWatchdog, state.outboundBuffer.count, state.peerVersion)
        }
        guard let opened else { return nil }

        let synFrame = AnyTLSProtocol.encodeFrameHeader(cmd: AnyTLSProtocol.cmdSYN, sid: opened.sid, length: 0)
        try? await writeConnLocked(synFrame)

        let live = state.withLock { state -> Bool in
            guard state.phase != .closed else { return false }
            state.buffering = false
            return true
        }
        guard live else { return nil }
        
        return opened.stream
    }

    func removeStream(sid: UInt32) {
        let removed: AnyTLSStream? = state.withLock { state in
            guard state.phase != .closed else { return nil }
            return state.streams.removeValue(forKey: sid)
        }
        guard let stream = removed else { return }

        let finFrame = AnyTLSProtocol.encodeFrameHeader(cmd: AnyTLSProtocol.cmdFIN, sid: sid, length: 0)
        Task { try? await writeConnLocked(finFrame) }

        stream.deliverClose(error: nil)
    }

    // MARK: - Send

    func writeData(sid: UInt32, data: Data) async throws {
        guard !data.isEmpty else { return }
        let max = Int(UInt16.max)
        if data.count <= max {
            let frame = AnyTLSProtocol.encodeFrame(cmd: AnyTLSProtocol.cmdPSH, sid: sid, payload: data)
            try await writeConnLocked(frame)
            return
        }
        var offset = data.startIndex
        while offset < data.endIndex {
            let end = Swift.min(offset + max, data.endIndex)
            let frame = AnyTLSProtocol.encodeFrame(cmd: AnyTLSProtocol.cmdPSH, sid: sid, payload: data[offset..<end])
            try await writeConnLocked(frame)
            offset = end
        }
    }

    private func writeControl(cmd: UInt8, sid: UInt32, payload: Data) async throws {
        let frame = AnyTLSProtocol.encodeFrame(cmd: cmd, sid: sid, payload: payload)
        try await writeConnLocked(frame)
    }

    private func writeConnLocked(_ bytes: Data) async throws {
        enum Action {
            case rejected
            case buffered
            case send(SerialSender.Pending)
        }

        let action: Action = state.withLock { (state: inout State) -> Action in
            if state.phase == .closed {
                return .rejected
            }
            if state.buffering {
                state.outboundBuffer.append(bytes)
                return .buffered
            }
            var pending = bytes
            if !state.outboundBuffer.isEmpty {
                pending = state.outboundBuffer + pending
                state.outboundBuffer.removeAll(keepingCapacity: false)
            }

            let output: Data
            if !state.sendPadding {
                output = pending
            } else {
                state.packetCounter &+= 1
                let packet = state.packetCounter
                let scheme = state.padding
                if packet >= scheme.stop {
                    state.sendPadding = false
                    output = pending
                } else {
                    let schedule = scheme.generateRecordPayloadSizes(packet: packet)
                    output = Self.applyPaddingSchedule(pending: pending, schedule: schedule)
                }
            }
            return .send(chainSend(output, state: &state))
        }

        switch action {
        case .rejected:
            throw AnywhereError.proxy(.anyTLS, .connectionClosed(detail: "AnyTLS multiplexer closed"))
        case .buffered:
            return
        case .send(let pending):
            try await pending.value()
        }
    }

    private func chainSend(_ output: Data, state: inout State) -> SerialSender.Pending {
        let inner = self.inner
        return sendChain.submit { try await inner.send(output) }
    }

    private static func applyPaddingSchedule(pending: Data, schedule: [Int]) -> Data {
        if schedule.isEmpty { return pending }
        var output = Data(capacity: pending.count + 64)
        var cursor = pending.startIndex
        let end = pending.endIndex
        scheduleLoop: for size in schedule {
            let remaining = end - cursor
            if size == AnyTLSPaddingScheme.checkMark {
                if remaining == 0 { break scheduleLoop }
                continue
            }
            let want = size
            if remaining > want {
                output.append(pending[cursor..<(cursor + want)])
                cursor += want
            } else if remaining > 0 {
                output.append(pending[cursor..<end])
                cursor = end
                let paddingLen = want - remaining - AnyTLSProtocol.headerSize
                if paddingLen > 0 {
                    let waste = AnyTLSProtocol.encodeFrame(
                        cmd: AnyTLSProtocol.cmdWaste,
                        sid: 0,
                        payload: Data(repeating: 0, count: paddingLen)
                    )
                    output.append(waste)
                }
            } else {
                let waste = AnyTLSProtocol.encodeFrame(
                    cmd: AnyTLSProtocol.cmdWaste,
                    sid: 0,
                    payload: Data(repeating: 0, count: size)
                )
                output.append(waste)
            }
        }
        if cursor < end {
            output.append(pending[cursor..<end])
        }
        return output
    }

    // MARK: - Read Loop

    private func startReadLoop() {
        let task = Task {
            do {
                while true {
                    try Task.checkCancellation()
                    guard let data = try await inner.receive() else {
                        handleTransportEOF()
                        return
                    }
                    await handleInbound(data)
                }
            } catch {
                handleTransportFailure(error)
            }
        }
        let accepted: Bool = state.withLock { state in
            guard state.transition(to: .ready) else { return false }
            state.readTask = task
            return true
        }
        if !accepted {
            task.cancel()
        }
    }

    private func handleTransportEOF() {
        close(error: AnywhereError.proxy(.anyTLS, .connectionClosed(detail: "AnyTLS session closed by peer")))
    }

    private func handleTransportFailure(_ error: Error) {
        close(error: error)
    }

    // MARK: - Demux

    private func handleInbound(_ data: Data) async {
        let dispatched: [(cmd: UInt8, sid: UInt32, payload: Data)] = state.withLock { state in
            state.receiveBuffer.appendCompacting(data)
            var dispatched: [(cmd: UInt8, sid: UInt32, payload: Data)] = []
            let base = state.receiveBuffer.startIndex
            var consumed = 0
            while state.receiveBuffer.count - consumed >= AnyTLSProtocol.headerSize {
                guard let header = AnyTLSProtocol.decodeFrameHeader(state.receiveBuffer, at: consumed) else { break }
                let totalLen = AnyTLSProtocol.headerSize + Int(header.length)
                if state.receiveBuffer.count - consumed < totalLen { break }
                let payloadStart = base + consumed + AnyTLSProtocol.headerSize
                let payload = Data(state.receiveBuffer[payloadStart..<(base + consumed + totalLen)])
                consumed += totalLen
                dispatched.append((header.cmd, header.sid, payload))
            }
            if consumed > 0 {
                state.receiveBuffer = consumed == state.receiveBuffer.count
                    ? Data()
                    : Data(state.receiveBuffer[(base + consumed)...])
            }
            return dispatched
        }

        for frame in dispatched {
            await routeFrame(cmd: frame.cmd, sid: frame.sid, payload: frame.payload)
        }
    }

    private func routeFrame(cmd: UInt8, sid: UInt32, payload: Data) async {
        switch cmd {
        case AnyTLSProtocol.cmdPSH:
            let stream = state.withLock { $0.streams[sid] }
            guard let stream else {
                logger.warning("[AnyTLSMultiplexer] cmdPSH for unknown sid=\(sid) (\(payload.count)B) — dropping")
                break
            }
            stream.deliverData(payload)
            await stream.awaitDownlinkCredit()

        case AnyTLSProtocol.cmdSYNACK:
            let stream = state.withLock { (state: inout State) -> AnyTLSStream? in
                cancelSynDoneTimerLocked(&state)
                return state.streams[sid]
            }
            if !payload.isEmpty {
                let message = String(data: payload, encoding: .utf8) ?? "<binary>"
                stream?.deliverClose(error: AnywhereError.proxy(.anyTLS, .protocolViolation(detail: "AnyTLS remote: \(message)")))
                state.withLock { $0.streams[sid] = nil }
            }

        case AnyTLSProtocol.cmdFIN:
            let stream = state.withLock { $0.streams.removeValue(forKey: sid) }
            stream?.deliverClose(error: nil)

        case AnyTLSProtocol.cmdWaste:
            break

        case AnyTLSProtocol.cmdServerSettings:
            let map = AnyTLSProtocol.decodeStringMap(payload)
            if let v = map["v"], let parsed = UInt8(v) {
                state.withLock { $0.peerVersion = parsed }
            } else {
                logger.warning("[AnyTLSMultiplexer] cmdServerSettings missing or invalid v: \(map)")
            }

        case AnyTLSProtocol.cmdAlert:
            let message = String(data: payload, encoding: .utf8) ?? "<binary>"
            close(error: AnywhereError.proxy(.anyTLS, .protocolViolation(detail: "AnyTLS alert: \(message)")))

        case AnyTLSProtocol.cmdUpdatePaddingScheme:
            if let new = AnyTLSPaddingScheme.parse(payload) {
                state.withLock { $0.padding = new }
            } else {
                logger.warning("[AnyTLSMultiplexer] cmdUpdatePaddingScheme: failed to parse payload (\(payload.count)B)")
            }

        case AnyTLSProtocol.cmdHeartRequest:
            let pong = AnyTLSProtocol.encodeFrameHeader(cmd: AnyTLSProtocol.cmdHeartResponse, sid: sid, length: 0)
            try? await writeConnLocked(pong)

        case AnyTLSProtocol.cmdHeartResponse:
            break

        default:
            logger.warning("[AnyTLSMultiplexer] unknown cmd=\(cmd) sid=\(sid) \(payload.count)B — ignoring")
        }
    }

    // MARK: - Close

    func close(error: Error? = nil) {
        typealias Teardown = (liveStreams: [AnyTLSStream], readTask: Task<Void, Never>?)
        let teardown: Teardown? = state.withLock { (state: inout State) -> Teardown? in
            guard state.transition(to: .closed) else { return nil }
            state.reserved = false
            cancelSynDoneTimerLocked(&state)
            let live = Array(state.streams.values)
            state.streams.removeAll(keepingCapacity: false)
            state.outboundBuffer.removeAll(keepingCapacity: false)
            let read = state.readTask
            state.readTask = nil
            return (live, read)
        }
        guard let (liveStreams, readTask) = teardown else { return }
        
        for stream in liveStreams {
            stream.deliverClose(error: error)
        }
        readTask?.cancel()
        sendChain.cancel()
        inner.cancel()
        onClose?(self)
    }

    deinit {
        state.withLock { $0.synDoneDeadline?.cancel() }
    }
}
