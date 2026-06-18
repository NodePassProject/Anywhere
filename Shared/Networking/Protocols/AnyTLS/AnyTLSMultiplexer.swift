//
//  AnyTLSMultiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "AnyTLSMultiplexer")

/// Owns one TLS connection and multiplexes logical streams over it via AnyTLS framing.
nonisolated final class AnyTLSMultiplexer: Multiplexer {

    // MARK: - Properties

    private let inner: ProxyConnection
    private let outerTLSVersion: TLSVersion?
    private let passwordHash: Data

    private let lock = UnfairLock()

    /// Mutable so cmdUpdatePaddingScheme can swap it.
    private var padding: AnyTLSPaddingScheme

    private var streams: [UInt32: AnyTLSStream] = [:]
    private var nextStreamID: UInt32 = 0
    private var peerVersion: UInt8 = 0

    private var pktCounter: UInt32 = 0
    private var sendPadding: Bool = true

    /// While true, writes accumulate in `outboundBuffer` so cmdSettings+cmdSYN+SocksAddr
    /// land in one TLS record (matches sing-anytls).
    private var buffering: Bool = true
    private var outboundBuffer: Data = Data()

    var idleSince: CFAbsoluteTime = .greatestFiniteMagnitude
    var seq: UInt64 = 0

    private let timerQueue = DispatchQueue(label: AWCore.Identifier.anyTLSSessionTimerQueue)
    private var synDoneTimer: DispatchSourceTimer?

    /// Buffer for partial inbound frames (TLS records don't align with AnyTLS frames).
    private var recvBuffer = Data()

    private var closed: Bool = false

    /// Invoked once when the multiplexer transitions to closed.
    var onClose: (() -> Void)?

    // MARK: - Init

    init(inner: ProxyConnection, passwordHash: Data, padding: AnyTLSPaddingScheme) {
        self.inner = inner
        self.outerTLSVersion = inner.outerTLSVersion
        self.passwordHash = passwordHash
        self.padding = padding
    }

    // MARK: - Capacity

    var isAlive: Bool { lock.withLock { !closed } }
    var isClosed: Bool { lock.withLock { closed } }
    var activeStreamCount: Int { lock.withLock { streams.count } }

    // MARK: - Lifecycle

    /// Sends the prologue + buffered cmdSettings, then starts the recv loop.
    /// pktCounter intentionally stays 0 here so the padding schedule aligns with the server.
    func start() {
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
        inner.send(data: prologue) { [weak self] error in
            if let error {
                logger.debug("[AnyTLSMultiplexer] prologue write failed: \(error.localizedDescription)")
                self?.handleTransportFailure(error)
            } else {
                logger.debug("[AnyTLSMultiplexer] prologue write completed")
            }
        }

        // cmdSettings — buffered until the first stream open flushes it.
        let settings: [String: String] = [
            "v": "2",
            "client": AnyTLSProtocol.clientVersion,
            "padding-md5": padding.md5Hex,
        ]
        let payload = AnyTLSProtocol.encodeStringMap(settings)
        logger.debug("[AnyTLSMultiplexer] cmdSettings buffered (\(payload.count)B payload)")
        writeControl(cmd: AnyTLSProtocol.cmdSettings, sid: 0, payload: payload, completion: { _ in })

        startReadLoop()
    }

    private func armSynDoneTimerLocked() {
        synDoneTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(deadline: .now() + .seconds(3))
        timer.setEventHandler { [weak self] in
            self?.close(error: ProxyError.connectionFailed("AnyTLS SYN-ACK timeout"))
        }
        timer.resume()
        synDoneTimer = timer
    }

    private func cancelSynDoneTimerLocked() {
        synDoneTimer?.cancel()
        synDoneTimer = nil
    }

    // MARK: - Streams

    /// Opens a new logical stream; the caller's first write (the destination address)
    /// becomes the cmdPSH that flushes the buffered cmdSettings + cmdSYN.
    func openStream() -> AnyTLSStream? {
        lock.lock()
        if closed {
            lock.unlock()
            logger.debug("[AnyTLSMultiplexer] openStream rejected — multiplexer closed")
            return nil
        }
        nextStreamID &+= 1
        if nextStreamID == 0 { nextStreamID = 1 }    // skip 0 (reserved for control)
        let sid = nextStreamID
        let stream = AnyTLSStream(sid: sid, multiplexer: self, outerTLSVersion: outerTLSVersion)
        streams[sid] = stream

        // v2 watchdog: close the multiplexer if no SYNACK within 3 s (cleared on cmdSYNACK).
        let armWatchdog = sid >= 2 && peerVersion >= 2
        if armWatchdog {
            armSynDoneTimerLocked()
        }
        let bufferedBytes = outboundBuffer.count
        let pv = peerVersion
        lock.unlock()

        logger.debug("[AnyTLSMultiplexer] openStream sid=\(sid) peerVersion=\(pv) watchdog=\(armWatchdog) buffered=\(bufferedBytes)B")

        let synFrame = AnyTLSProtocol.encodeFrameHeader(cmd: AnyTLSProtocol.cmdSYN, sid: sid, length: 0)
        writeConnLocked(synFrame, completion: { _ in })

        lock.lock()
        buffering = false
        lock.unlock()
        return stream
    }

    /// Removes the stream and emits cmdFIN.
    func removeStream(sid: UInt32) {
        lock.lock()
        guard !closed, let stream = streams.removeValue(forKey: sid) else {
            lock.unlock()
            return
        }
        lock.unlock()

        let finFrame = AnyTLSProtocol.encodeFrameHeader(cmd: AnyTLSProtocol.cmdFIN, sid: sid, length: 0)
        writeConnLocked(finFrame, completion: { _ in })

        // Surface a clean EOF locally so any waiting receive callback unblocks.
        stream.deliverClose(error: nil)
    }

    // MARK: - Send

    func writeData(sid: UInt32, data: Data, completion: @escaping (Error?) -> Void) {
        guard !data.isEmpty else { completion(nil); return }
        // cmdPSH carries at most 65535 bytes per frame; chunk longer payloads.
        let max = Int(UInt16.max)
        if data.count <= max {
            let frame = AnyTLSProtocol.encodeFrame(cmd: AnyTLSProtocol.cmdPSH, sid: sid, payload: data)
            writeConnLocked(frame, completion: completion)
            return
        }
        var offset = 0
        while offset < data.count {
            let end = min(offset + max, data.count)
            let chunk = data.subdata(in: offset..<end)
            let frame = AnyTLSProtocol.encodeFrame(cmd: AnyTLSProtocol.cmdPSH, sid: sid, payload: chunk)
            let isLast = end == data.count
            writeConnLocked(frame) { error in
                if isLast { completion(error) }
            }
            offset = end
        }
    }

    private func writeControl(cmd: UInt8, sid: UInt32, payload: Data, completion: @escaping (Error?) -> Void) {
        let frame = AnyTLSProtocol.encodeFrame(cmd: cmd, sid: sid, payload: payload)
        writeConnLocked(frame, completion: completion)
    }

    /// Padding-aware writer (replicates sing-anytls's `Session.writeConn`): buffers while
    /// `buffering`, otherwise slices output per the padding schedule, topping up with cmdWaste.
    private func writeConnLocked(_ bytes: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        if closed {
            lock.unlock()
            logger.debug("[AnyTLSMultiplexer] writeConn rejected — multiplexer closed (\(bytes.count)B)")
            completion(ProxyError.connectionFailed("AnyTLS multiplexer closed"))
            return
        }
        if buffering {
            outboundBuffer.append(bytes)
            let total = outboundBuffer.count
            lock.unlock()
            logger.debug("[AnyTLSMultiplexer] writeConn buffered \(bytes.count)B (total=\(total)B)")
            completion(nil)
            return
        }
        var pending = bytes
        let prependedBufferSize = outboundBuffer.count
        if !outboundBuffer.isEmpty {
            pending = outboundBuffer + pending
            outboundBuffer.removeAll(keepingCapacity: false)
        }

        if !sendPadding {
            lock.unlock()
            if prependedBufferSize > 0 {
                logger.debug("[AnyTLSMultiplexer] writeConn flush+raw \(pending.count)B (was buffered=\(prependedBufferSize))")
            }
            inner.send(data: pending, completion: completion)
            return
        }

        pktCounter &+= 1
        let pkt = pktCounter
        let scheme = padding
        if pkt >= scheme.stop {
            sendPadding = false
            lock.unlock()
            logger.debug("[AnyTLSMultiplexer] writeConn pkt=\(pkt) ≥ stop=\(scheme.stop) — sending raw, padding off")
            inner.send(data: pending, completion: completion)
            return
        }
        let schedule = scheme.generateRecordPayloadSizes(packet: pkt)
        lock.unlock()
        logger.debug("[AnyTLSMultiplexer] writeConn pkt=\(pkt) bytes=\(pending.count) (was buffered=\(prependedBufferSize)) schedule=\(schedule)")

        if schedule.isEmpty {
            inner.send(data: pending, completion: completion)
            return
        }

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

        inner.send(data: output, completion: completion)
    }

    // MARK: - Read Loop

    private func startReadLoop() {
        logger.debug("[AnyTLSMultiplexer] recv loop started")
        inner.startReceiving { [weak self] data in
            self?.handleInbound(data)
        } errorHandler: { [weak self] error in
            if let error {
                logger.debug("[AnyTLSMultiplexer] inner transport error: \(error.localizedDescription)")
                self?.handleTransportFailure(error)
            } else {
                logger.debug("[AnyTLSMultiplexer] inner transport EOF")
                self?.handleTransportEOF()
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

    private func handleInbound(_ data: Data) {
        lock.lock()
        recvBuffer.appendCompacting(data)
        var dispatched: [(cmd: UInt8, sid: UInt32, payload: Data)] = []
        while recvBuffer.count >= AnyTLSProtocol.headerSize {
            guard let header = AnyTLSProtocol.decodeFrameHeader(recvBuffer) else { break }
            let totalLen = AnyTLSProtocol.headerSize + Int(header.length)
            if recvBuffer.count < totalLen { break }
            let payload = recvBuffer.subdata(in: AnyTLSProtocol.headerSize..<totalLen)
            recvBuffer.removeSubrange(0..<totalLen)
            dispatched.append((header.cmd, header.sid, payload))
        }
        lock.unlock()

        for frame in dispatched {
            routeFrame(cmd: frame.cmd, sid: frame.sid, payload: frame.payload)
        }
    }

    private func routeFrame(cmd: UInt8, sid: UInt32, payload: Data) {
        switch cmd {
        case AnyTLSProtocol.cmdPSH:
            lock.lock()
            let stream = streams[sid]
            lock.unlock()
            if stream == nil {
                logger.warning("[AnyTLSMultiplexer] cmdPSH for unknown sid=\(sid) (\(payload.count)B) — dropping")
            } else {
                logger.debug("[AnyTLSMultiplexer] cmdPSH sid=\(sid) \(payload.count)B")
            }
            stream?.deliverData(payload)

        case AnyTLSProtocol.cmdSYNACK:
            lock.lock()
            cancelSynDoneTimerLocked()
            let stream = streams[sid]
            lock.unlock()
            if !payload.isEmpty {
                let msg = String(data: payload, encoding: .utf8) ?? "<binary>"
                logger.debug("[AnyTLSMultiplexer] cmdSYNACK error sid=\(sid): \(msg)")
                stream?.deliverClose(error: ProxyError.protocolError("AnyTLS remote: \(msg)"))
                lock.withLock { streams[sid] = nil }
            } else {
                logger.debug("[AnyTLSMultiplexer] cmdSYNACK ok sid=\(sid)")
            }

        case AnyTLSProtocol.cmdFIN:
            lock.lock()
            let stream = streams.removeValue(forKey: sid)
            lock.unlock()
            logger.debug("[AnyTLSMultiplexer] cmdFIN sid=\(sid) (had stream=\(stream != nil))")
            stream?.deliverClose(error: nil)

        case AnyTLSProtocol.cmdWaste:
            logger.debug("[AnyTLSMultiplexer] cmdWaste sid=\(sid) \(payload.count)B (drained)")

        case AnyTLSProtocol.cmdServerSettings:
            let map = AnyTLSProtocol.decodeStringMap(payload)
            if let v = map["v"], let parsed = UInt8(v) {
                lock.withLock { peerVersion = parsed }
                logger.debug("[AnyTLSMultiplexer] cmdServerSettings peerVersion=\(parsed) keys=\(Array(map.keys))")
            } else {
                logger.warning("[AnyTLSMultiplexer] cmdServerSettings missing or invalid v: \(map)")
            }

        case AnyTLSProtocol.cmdAlert:
            let msg = String(data: payload, encoding: .utf8) ?? "<binary>"
            logger.debug("[AnyTLSMultiplexer] cmdAlert from server: \(msg)")
            close(error: ProxyError.protocolError("AnyTLS alert: \(msg)"))

        case AnyTLSProtocol.cmdUpdatePaddingScheme:
            if let new = AnyTLSPaddingScheme.parse(payload) {
                lock.withLock { padding = new }
                logger.debug("[AnyTLSMultiplexer] cmdUpdatePaddingScheme applied md5=\(new.md5Hex) stop=\(new.stop)")
            } else {
                logger.warning("[AnyTLSMultiplexer] cmdUpdatePaddingScheme: failed to parse payload (\(payload.count)B)")
            }

        case AnyTLSProtocol.cmdHeartRequest:
            logger.debug("[AnyTLSMultiplexer] cmdHeartRequest sid=\(sid) — replying")
            let pong = AnyTLSProtocol.encodeFrameHeader(cmd: AnyTLSProtocol.cmdHeartResponse, sid: sid, length: 0)
            writeConnLocked(pong, completion: { _ in })

        case AnyTLSProtocol.cmdHeartResponse:
            // Active polling not implemented; drop.
            break

        default:
            logger.warning("[AnyTLSMultiplexer] unknown cmd=\(cmd) sid=\(sid) \(payload.count)B — ignoring")
        }
    }

    // MARK: - Close

    /// Idempotent; a non-nil error propagates to every live stream.
    func close(error: Error? = nil) {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        cancelSynDoneTimerLocked()
        let liveStreams = Array(streams.values)
        streams.removeAll(keepingCapacity: false)
        outboundBuffer.removeAll(keepingCapacity: false)
        lock.unlock()

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
        synDoneTimer?.cancel()
    }
}
