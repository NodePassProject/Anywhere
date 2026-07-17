//
//  AnyTLSMultiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "AnyTLSMultiplexer")

nonisolated final class AnyTLSMultiplexer: Multiplexer {

    // MARK: - Properties

    private let inner: ProxyConnection
    private let outerTLSVersion: TLSVersion?
    private let passwordHash: Data

    /// Fields guarded by `lock`.
    private struct State {
        /// Mutable so cmdUpdatePaddingScheme can swap it.
        var padding: AnyTLSPaddingScheme

        var streams: [UInt32: AnyTLSStream] = [:]
        var nextStreamID: UInt32 = 0
        var peerVersion: UInt8 = 0

        var packetCounter: UInt32 = 0
        var sendPadding: Bool = true

        /// While true, writes accumulate in `outboundBuffer` so cmdSettings+cmdSYN+SocksAddr
        /// land in one TLS record.
        var buffering: Bool = true
        var outboundBuffer: Data = Data()

        var synDoneTask: Task<Void, Never>?

        /// Buffer for partial inbound frames (TLS records don't align with AnyTLS frames).
        var recvBuffer = Data()

        var closed: Bool = false

        /// Set while an acquire has claimed this mux for serial reuse (before its stream opens).
        var reserved: Bool = false

        /// Tail of the wire-send chain. Each send links after the previous one and runs only once
        /// it finishes, so the padding-schedule packet order matches on-wire order without a lock —
        /// the compute (`packetCounter`/padding) and the link happen together under ``lock``.
        var sendTail: Task<Void, Error>?
    }

    private let lock: Mutex<State>

    var seq: UInt64 = 0

    var onClose: (() -> Void)?

    // MARK: - Init

    init(inner: ProxyConnection, passwordHash: Data, padding: AnyTLSPaddingScheme) {
        self.inner = inner
        self.outerTLSVersion = inner.outerTLSVersion
        self.passwordHash = passwordHash
        self.lock = Mutex(State(padding: padding))
    }

    // MARK: - Capacity

    var isAlive: Bool { lock.withLock { !$0.closed } }
    var isClosed: Bool { lock.withLock { $0.closed } }
    /// Counts an active reservation as a live stream so the pool's idle sweep never treats a
    /// mux that's reserved-for-reuse (but between reserve and its first `openStream`) as idle.
    var activeStreamCount: Int { lock.withLock { $0.streams.count + ($0.reserved ? 1 : 0) } }

    /// Atomically claims a live, unreserved, stream-free multiplexer for serial reuse;
    /// returns false otherwise. Released via ``releaseReservation()`` when the stream ends.
    func tryReserveStream() -> Bool {
        lock.withLock { state in
            guard !state.closed, !state.reserved, state.streams.isEmpty else { return false }
            state.reserved = true
            return true
        }
    }

    func releaseReservation() {
        lock.withLock { $0.reserved = false }
    }

    // MARK: - Lifecycle

    /// packetCounter intentionally stays 0 here so the padding schedule aligns with the server.
    func start() async {
        // Snapshot; the scheme can't change before startReadLoop() arms inbound handling.
        let padding = lock.withLock { $0.padding }
        var prologue = Data()
        prologue.append(passwordHash)
        let paddingLen: Int
        let firstSchedule = padding.generateRecordPayloadSizes(packet: 0)
        if let first = firstSchedule.first, first > 0 {
            paddingLen = first
        } else {
            paddingLen = 0
        }
        prologue.append(UInt8((paddingLen >> 8) & 0xFF))
        prologue.append(UInt8( paddingLen       & 0xFF))
        if paddingLen > 0 {
            prologue.append(Data(repeating: 0, count: paddingLen))
        }
        logger.debug("[AnyTLSMultiplexer] prologue \(prologue.count)B (hash=32 + lenHdr=2 + zeros=\(paddingLen)) padding-md5=\(padding.md5Hex)")
        // The prologue rides ahead of the framed writes (not through the padding scheduler);
        // linked first on the send chain so it precedes every writeConnLocked flush.
        do {
            let task = lock.withLock { chainSend(prologue, state: &$0) }
            try await task.value
        } catch {
            logger.debug("[AnyTLSMultiplexer] prologue write failed: \(error.localizedDescription)")
            handleTransportFailure(error)
            return
        }

        // cmdSettings — buffered until the first stream open flushes it.
        let settings: [String: String] = [
            "v": "2",
            "client": AnyTLSProtocol.clientVersion,
            "padding-md5": padding.md5Hex,
        ]
        let payload = AnyTLSProtocol.encodeStringMap(settings)
        logger.debug("[AnyTLSMultiplexer] cmdSettings buffered (\(payload.count)B payload)")
        try? await writeControl(cmd: AnyTLSProtocol.cmdSettings, sid: 0, payload: payload)

        startReadLoop()
    }

    /// Must be called with `lock` held (inside a `withLock` on it).
    private func armSynDoneTimerLocked(_ state: inout State) {
        state.synDoneTask?.cancel()
        state.synDoneTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard !Task.isCancelled else { return }
            self?.close(error: ProxyError.connectionFailed("AnyTLS SYN-ACK timeout"))
        }
    }

    /// Must be called with `lock` held (inside a `withLock` on it).
    private func cancelSynDoneTimerLocked(_ state: inout State) {
        state.synDoneTask?.cancel()
        state.synDoneTask = nil
    }

    // MARK: - Streams

    /// Opens a new logical stream; the caller's first write (the destination address)
    /// becomes the cmdPSH that flushes the buffered cmdSettings + cmdSYN.
    func openStream() async -> AnyTLSStream? {
        typealias Opened = (stream: AnyTLSStream, sid: UInt32, armWatchdog: Bool,
                            bufferedBytes: Int, peerVersion: UInt8)
        let opened: Opened? = lock.withLock { (state: inout State) -> Opened? in
            if state.closed {
                return nil
            }
            state.nextStreamID &+= 1
            if state.nextStreamID == 0 { state.nextStreamID = 1 }    // skip 0 (reserved for control)
            let sid = state.nextStreamID
            let stream = AnyTLSStream(sid: sid, multiplexer: self, outerTLSVersion: outerTLSVersion)
            state.streams[sid] = stream

            // v2 watchdog: close the multiplexer if no SYNACK within 3 s (cleared on cmdSYNACK).
            let armWatchdog = sid >= 2 && state.peerVersion >= 2
            if armWatchdog {
                armSynDoneTimerLocked(&state)
            }
            return (stream, sid, armWatchdog, state.outboundBuffer.count, state.peerVersion)
        }
        guard let opened else {
            logger.debug("[AnyTLSMultiplexer] openStream rejected — multiplexer closed")
            return nil
        }

        logger.debug("[AnyTLSMultiplexer] openStream sid=\(opened.sid) peerVersion=\(opened.peerVersion) watchdog=\(opened.armWatchdog) buffered=\(opened.bufferedBytes)B")

        // Awaited so the SYN is enqueued (buffered on the first stream, sent on a reused mux)
        // strictly before the caller's first cmdPSH.
        let synFrame = AnyTLSProtocol.encodeFrameHeader(cmd: AnyTLSProtocol.cmdSYN, sid: opened.sid, length: 0)
        try? await writeConnLocked(synFrame)

        lock.withLock { $0.buffering = false }
        return opened.stream
    }

    func removeStream(sid: UInt32) {
        let removed: AnyTLSStream? = lock.withLock { state in
            guard !state.closed else { return nil }
            return state.streams.removeValue(forKey: sid)
        }
        guard let stream = removed else { return }

        let finFrame = AnyTLSProtocol.encodeFrameHeader(cmd: AnyTLSProtocol.cmdFIN, sid: sid, length: 0)
        Task { [weak self] in try? await self?.writeConnLocked(finFrame) }

        // Surface a clean EOF locally so any waiting receive unblocks.
        stream.deliverClose(error: nil)
    }

    // MARK: - Send

    func writeData(sid: UInt32, data: Data) async throws {
        guard !data.isEmpty else { return }
        // cmdPSH carries at most 65535 bytes per frame; chunk longer payloads.
        let max = Int(UInt16.max)
        if data.count <= max {
            let frame = AnyTLSProtocol.encodeFrame(cmd: AnyTLSProtocol.cmdPSH, sid: sid, payload: data)
            try await writeConnLocked(frame)
            return
        }
        var offset = 0
        while offset < data.count {
            let end = min(offset + max, data.count)
            let chunk = data.subdata(in: offset..<end)
            let frame = AnyTLSProtocol.encodeFrame(cmd: AnyTLSProtocol.cmdPSH, sid: sid, payload: chunk)
            try await writeConnLocked(frame)
            offset = end
        }
    }

    private func writeControl(cmd: UInt8, sid: UInt32, payload: Data) async throws {
        let frame = AnyTLSProtocol.encodeFrame(cmd: cmd, sid: sid, payload: payload)
        try await writeConnLocked(frame)
    }

    /// Padding-aware writer: buffers while `buffering`, otherwise slices output per the padding
    /// schedule, topping up with cmdWaste. The compute (`packetCounter`/padding) and the send-chain
    /// link happen together under ``lock``, so packet order matches on-wire order without a lock held
    /// across the `await`.
    private func writeConnLocked(_ bytes: Data) async throws {
        enum Action {
            case rejected
            case buffered
            case send(Task<Void, Error>)
        }

        let action: Action = lock.withLock { (state: inout State) -> Action in
            if state.closed {
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
            logger.debug("[AnyTLSMultiplexer] writeConn rejected — multiplexer closed (\(bytes.count)B)")
            throw ProxyError.connectionFailed("AnyTLS multiplexer closed")
        case .buffered:
            return
        case .send(let task):
            try await task.value
        }
    }

    /// Links one wire write after the current send tail and returns its task. The write runs only
    /// once the previous one finishes, giving strict on-wire order with backpressure and error
    /// propagation (via the returned task's `value`) and no lock held across the `await`.
    /// Must be called with ``lock`` held.
    private func chainSend(_ output: Data, state: inout State) -> Task<Void, Error> {
        let inner = self.inner
        let previous = state.sendTail
        let task = Task<Void, Error> {
            _ = try? await previous?.value
            try await inner.send(output)
        }
        state.sendTail = task
        return task
    }

    /// Slices `pending` into the padding schedule's record sizes, topping up short
    /// chunks with cmdWaste frames.
    private static func applyPaddingSchedule(pending: Data, schedule: [Int]) -> Data {
        if schedule.isEmpty { return pending }
        var output = Data(capacity: pending.count + 64)
        var remaining = pending
        scheduleLoop: for size in schedule {
            if size == AnyTLSPaddingScheme.checkMark {
                if remaining.isEmpty { break scheduleLoop }
                continue
            }
            let want = size
            if remaining.count > want {
                output.append(remaining.prefix(want))
                remaining.removeFirst(want)
            } else if !remaining.isEmpty {
                // Top up with a cmdWaste frame so the chunk hits exactly `want` bytes.
                let payloadLeft = remaining.count
                output.append(remaining)
                remaining.removeAll(keepingCapacity: false)
                let paddingLen = want - payloadLeft - AnyTLSProtocol.headerSize
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
        if !remaining.isEmpty {
            output.append(remaining)
        }
        return output
    }

    // MARK: - Read Loop

    private func startReadLoop() {
        logger.debug("[AnyTLSMultiplexer] recv loop started")
        Task { [weak self] in
            do {
                while true {
                    guard let self else { return }
                    guard let data = try await self.inner.receive() else {
                        logger.debug("[AnyTLSMultiplexer] inner transport EOF")
                        self.handleTransportEOF()
                        return
                    }
                    await self.handleInbound(data)
                }
            } catch {
                logger.debug("[AnyTLSMultiplexer] inner transport error: \(error.localizedDescription)")
                self?.handleTransportFailure(error)
            }
        }
    }

    private func handleTransportEOF() {
        close(error: nil)
    }

    private func handleTransportFailure(_ error: Error) {
        close(error: error)
    }

    // MARK: - Demux

    private func handleInbound(_ data: Data) async {
        let dispatched: [(cmd: UInt8, sid: UInt32, payload: Data)] = lock.withLock { state in
            state.recvBuffer.appendCompacting(data)
            var dispatched: [(cmd: UInt8, sid: UInt32, payload: Data)] = []
            while state.recvBuffer.count >= AnyTLSProtocol.headerSize {
                guard let header = AnyTLSProtocol.decodeFrameHeader(state.recvBuffer) else { break }
                let totalLen = AnyTLSProtocol.headerSize + Int(header.length)
                if state.recvBuffer.count < totalLen { break }
                let payload = state.recvBuffer.subdata(in: AnyTLSProtocol.headerSize..<totalLen)
                state.recvBuffer.removeSubrange(0..<totalLen)
                dispatched.append((header.cmd, header.sid, payload))
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
            let stream = lock.withLock { $0.streams[sid] }
            if stream == nil {
                logger.warning("[AnyTLSMultiplexer] cmdPSH for unknown sid=\(sid) (\(payload.count)B) — dropping")
            } else {
                logger.debug("[AnyTLSMultiplexer] cmdPSH sid=\(sid) \(payload.count)B")
            }
            stream?.deliverData(payload)

        case AnyTLSProtocol.cmdSYNACK:
            let stream = lock.withLock { (state: inout State) -> AnyTLSStream? in
                cancelSynDoneTimerLocked(&state)
                return state.streams[sid]
            }
            if !payload.isEmpty {
                let message = String(data: payload, encoding: .utf8) ?? "<binary>"
                logger.debug("[AnyTLSMultiplexer] cmdSYNACK error sid=\(sid): \(message)")
                stream?.deliverClose(error: ProxyError.protocolError("AnyTLS remote: \(message)"))
                lock.withLock { $0.streams[sid] = nil }
            } else {
                logger.debug("[AnyTLSMultiplexer] cmdSYNACK ok sid=\(sid)")
            }

        case AnyTLSProtocol.cmdFIN:
            let stream = lock.withLock { $0.streams.removeValue(forKey: sid) }
            logger.debug("[AnyTLSMultiplexer] cmdFIN sid=\(sid) (had stream=\(stream != nil))")
            stream?.deliverClose(error: nil)

        case AnyTLSProtocol.cmdWaste:
            logger.debug("[AnyTLSMultiplexer] cmdWaste sid=\(sid) \(payload.count)B (drained)")

        case AnyTLSProtocol.cmdServerSettings:
            let map = AnyTLSProtocol.decodeStringMap(payload)
            if let v = map["v"], let parsed = UInt8(v) {
                lock.withLock { $0.peerVersion = parsed }
                logger.debug("[AnyTLSMultiplexer] cmdServerSettings peerVersion=\(parsed) keys=\(Array(map.keys))")
            } else {
                logger.warning("[AnyTLSMultiplexer] cmdServerSettings missing or invalid v: \(map)")
            }

        case AnyTLSProtocol.cmdAlert:
            let message = String(data: payload, encoding: .utf8) ?? "<binary>"
            logger.debug("[AnyTLSMultiplexer] cmdAlert from server: \(message)")
            close(error: ProxyError.protocolError("AnyTLS alert: \(message)"))

        case AnyTLSProtocol.cmdUpdatePaddingScheme:
            if let new = AnyTLSPaddingScheme.parse(payload) {
                lock.withLock { $0.padding = new }
                logger.debug("[AnyTLSMultiplexer] cmdUpdatePaddingScheme applied md5=\(new.md5Hex) stop=\(new.stop)")
            } else {
                logger.warning("[AnyTLSMultiplexer] cmdUpdatePaddingScheme: failed to parse payload (\(payload.count)B)")
            }

        case AnyTLSProtocol.cmdHeartRequest:
            logger.debug("[AnyTLSMultiplexer] cmdHeartRequest sid=\(sid) — replying")
            let pong = AnyTLSProtocol.encodeFrameHeader(cmd: AnyTLSProtocol.cmdHeartResponse, sid: sid, length: 0)
            try? await writeConnLocked(pong)

        case AnyTLSProtocol.cmdHeartResponse:
            break

        default:
            logger.warning("[AnyTLSMultiplexer] unknown cmd=\(cmd) sid=\(sid) \(payload.count)B — ignoring")
        }
    }

    // MARK: - Close

    /// Idempotent; a non-nil error propagates to every live stream.
    func close(error: Error? = nil) {
        let liveStreams: [AnyTLSStream]? = lock.withLock { (state: inout State) -> [AnyTLSStream]? in
            guard !state.closed else { return nil }
            state.closed = true
            state.reserved = false
            cancelSynDoneTimerLocked(&state)
            let live = Array(state.streams.values)
            state.streams.removeAll(keepingCapacity: false)
            state.outboundBuffer.removeAll(keepingCapacity: false)
            return live
        }
        guard let liveStreams else { return }

        let reasonText = error.map { $0.localizedDescription } ?? "clean"
        logger.debug("[AnyTLSMultiplexer] close seq=\(seq) streams=\(liveStreams.count) reason=\(reasonText)")
        for stream in liveStreams {
            stream.deliverClose(error: error)
        }
        inner.cancel()
        onClose?()
    }

    deinit {
        // Reclaim the SYN-done watchdog if the multiplexer was dropped without close().
        lock.withLock { $0.synDoneTask?.cancel() }
    }
}
