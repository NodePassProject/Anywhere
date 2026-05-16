//
//  AnyTLSSession.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

private let logger = AnywhereLogger(category: "AnyTLSSession")

/// Owns one TLS connection and multiplexes one or more `AnyTLSStream`s over
/// it via the AnyTLS framing. Mirrors `session.Session` (client side) in
/// sing-anytls 0.0.11.
///
/// Lifecycle:
/// 1. Constructed with a freshly-handshaken TLS `inner` connection.
/// 2. `start()` writes the post-TLS prologue (`SHA256(password) +
///    paddingLen + paddingZeros`), enqueues the buffered cmdSettings frame,
///    and kicks off the recv loop.
/// 3. `openStream()` allocates a new `sid`, sends `cmdSYN(sid)`, and flips
///    `buffering = false` so the next `cmdPSH(sid, addr)` written by the
///    caller flushes the cmdSettings buffer alongside it.
/// 4. Inbound frames are demuxed by cmd: cmdPSH → stream, cmdSYNACK →
///    cancel handshake watcher / surface error, cmdHeartRequest → reply,
///    cmdUpdatePaddingScheme → atomically swap the padding factory.
/// 5. `close()` is idempotent; pool-driven death uses ``onClose`` to let the
///    `AnyTLSClient` evict this session from the pool.
nonisolated final class AnyTLSSession {

    private let inner: ProxyConnection
    private let outerTLSVersion: TLSVersion?
    private let passwordHash: Data

    private let lock = UnfairLock()

    /// Mutable so cmdUpdatePaddingScheme can swap it. All sessions for a
    /// given `AnyTLSClient` share the same atomic ref through the client.
    private var padding: AnyTLSPaddingScheme

    private var streams: [UInt32: AnyTLSStream] = [:]
    private var nextStreamID: UInt32 = 0
    private var peerVersion: UInt8 = 0

    private var pktCounter: UInt32 = 0
    private var sendPadding: Bool = true

    /// Until the first `OpenStream` flushes the buffer, every `writeConn`
    /// just appends to `outboundBuffer`. This lets cmdSettings+cmdSYN+
    /// SocksAddr land in a single TLS record (matches sing-anytls's
    /// `b.WriteTo(conn)` semantics).
    private var buffering: Bool = true
    private var outboundBuffer: Data = Data()

    /// Set by `AnyTLSClient` when it inserts/withdraws the session from
    /// the idle pool.
    var idleSince: Date = Date.distantFuture
    var seq: UInt64 = 0

    /// Dispatch queue for the synDone watchdog timer.
    private let timerQueue = DispatchQueue(label: "AnyTLSSession.timer")
    private var synDoneTimer: DispatchSourceTimer?

    /// Buffer for partial inbound frames (TLS records don't align with
    /// AnyTLS frames).
    private var recvBuffer = Data()

    private var closed: Bool = false

    /// Invoked once when the session transitions to closed. The
    /// `AnyTLSClient` uses it to drop the session from the pool.
    var onClose: (() -> Void)?

    init(inner: ProxyConnection, passwordHash: Data, padding: AnyTLSPaddingScheme) {
        self.inner = inner
        self.outerTLSVersion = inner.outerTLSVersion
        self.passwordHash = passwordHash
        self.padding = padding
    }

    var isAlive: Bool { lock.withLock { !closed } }

    // MARK: - Start

    /// Sends the prologue + buffered cmdSettings, then starts the recv loop.
    ///
    /// The first padding scheme call (`generateRecordPayloadSizes(packet: 0)`)
    /// determines `paddingLen` for the prologue (default scheme returns
    /// `[30]`, so 30 zero bytes are emitted). The cmdSettings frame is
    /// written through `writeConn`, which during `buffering=true` just
    /// appends to `outboundBuffer` instead of touching the wire — so nothing
    /// goes out until the first stream's payload flushes the buffer.
    ///
    /// Note: pktCounter is intentionally still 0 after this call. It only
    /// increments on actual `writeConn` invocations that hit the wire (i.e.
    /// after `buffering=false`), so the per-packet padding schedule lines up
    /// with what the server expects.
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
        logger.info("[AnyTLSSession] prologue \(prologue.count)B (hash=32 + lenHdr=2 + zeros=\(paddingLen)) padding-md5=\(padding.md5Hex)")
        inner.send(data: prologue) { [weak self] error in
            if let error {
                logger.warning("[AnyTLSSession] prologue write failed: \(error.localizedDescription)")
                self?.handleTransportFailure(error)
            } else {
                logger.debug("[AnyTLSSession] prologue write completed")
            }
        }

        // cmdSettings — buffered until the first stream open flushes it.
        let settings: [String: String] = [
            "v": "2",
            "client": AnyTLSProtocol.clientVersion,
            "padding-md5": padding.md5Hex,
        ]
        let payload = AnyTLSProtocol.encodeStringMap(settings)
        logger.debug("[AnyTLSSession] cmdSettings buffered (\(payload.count)B payload)")
        writeControl(cmd: AnyTLSProtocol.cmdSettings, sid: 0, payload: payload, completion: { _ in })

        startRecvLoop()
    }

    // MARK: - Stream open / close

    /// Opens a new logical stream. The caller should immediately write the
    /// destination address (`AnyTLSProtocol.encodeAddrPort`) on the returned
    /// stream — that write becomes the cmdPSH that flushes the buffered
    /// cmdSettings + cmdSYN to the wire.
    func openStream() -> AnyTLSStream? {
        lock.lock()
        if closed {
            lock.unlock()
            logger.warning("[AnyTLSSession] openStream rejected — session closed")
            return nil
        }
        nextStreamID &+= 1
        if nextStreamID == 0 { nextStreamID = 1 }    // skip 0 (reserved for control)
        let sid = nextStreamID
        let stream = AnyTLSStream(sid: sid, session: self, outerTLSVersion: outerTLSVersion)
        streams[sid] = stream

        // Watchdog for v2 servers: if the SYNACK doesn't arrive within 3 s,
        // the session is wedged; close it. Cleared on cmdSYNACK in recvLoop.
        let armWatchdog = sid >= 2 && peerVersion >= 2
        if armWatchdog {
            armSynDoneTimerLocked()
        }
        let bufferedBytes = outboundBuffer.count
        let pv = peerVersion
        lock.unlock()

        logger.debug("[AnyTLSSession] openStream sid=\(sid) peerVersion=\(pv) watchdog=\(armWatchdog) buffered=\(bufferedBytes)B")

        let synFrame = AnyTLSProtocol.encodeFrameHeader(cmd: AnyTLSProtocol.cmdSYN, sid: sid, length: 0)
        // cmdSYN is still part of the buffered batch until we flip the flag.
        writeConnLocked(synFrame, completion: { _ in })

        // After the first SYN, subsequent payload writes (the SocksAddr
        // cmdPSH from the caller) will flush the buffer.
        lock.lock()
        buffering = false
        lock.unlock()
        return stream
    }

    /// Sent by `AnyTLSStream.cancel()`. Removes the stream and emits cmdFIN.
    func streamClosed(sid: UInt32) {
        lock.lock()
        guard !closed, let stream = streams.removeValue(forKey: sid) else {
            lock.unlock()
            return
        }
        lock.unlock()

        let finFrame = AnyTLSProtocol.encodeFrameHeader(cmd: AnyTLSProtocol.cmdFIN, sid: sid, length: 0)
        writeConnLocked(finFrame, completion: { _ in })

        // Surface a clean EOF locally too so any waiting `receiveRaw`
        // callback unblocks.
        stream.deliverClose(error: nil)
    }

    // MARK: - Outbound writes

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

    /// Padding-aware writer. Replicates `Session.writeConn` from sing-anytls:
    /// while `buffering`, accumulate into `outboundBuffer`; otherwise prepend
    /// the buffer (if any), then for each packet within the `stop` window
    /// derive a per-packet schedule from the current padding factory and
    /// slice the outbound bytes into frame-aligned chunks, topping up with
    /// `cmdWaste(0)` filler frames when the schedule asks for more bytes
    /// than the payload provides.
    private func writeConnLocked(_ bytes: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        if closed {
            lock.unlock()
            logger.debug("[AnyTLSSession] writeConn rejected — session closed (\(bytes.count)B)")
            completion(ProxyError.connectionFailed("AnyTLS session closed"))
            return
        }
        if buffering {
            outboundBuffer.append(bytes)
            let total = outboundBuffer.count
            lock.unlock()
            logger.debug("[AnyTLSSession] writeConn buffered \(bytes.count)B (total=\(total)B)")
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
                logger.debug("[AnyTLSSession] writeConn flush+raw \(pending.count)B (was buffered=\(prependedBufferSize))")
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
            logger.debug("[AnyTLSSession] writeConn pkt=\(pkt) ≥ stop=\(scheme.stop) — sending raw, padding off")
            inner.send(data: pending, completion: completion)
            return
        }
        let schedule = scheme.generateRecordPayloadSizes(packet: pkt)
        lock.unlock()
        logger.debug("[AnyTLSSession] writeConn pkt=\(pkt) bytes=\(pending.count) (was buffered=\(prependedBufferSize)) schedule=\(schedule)")

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

    // MARK: - Receive loop

    private func startRecvLoop() {
        logger.debug("[AnyTLSSession] recv loop started")
        inner.startReceiving { [weak self] data in
            self?.handleInbound(data)
        } errorHandler: { [weak self] error in
            if let error {
                logger.warning("[AnyTLSSession] inner transport error: \(error.localizedDescription)")
                self?.handleTransportFailure(error)
            } else {
                logger.info("[AnyTLSSession] inner transport EOF")
                self?.handleTransportEOF()
            }
        }
    }

    private func handleInbound(_ data: Data) {
        lock.lock()
        recvBuffer.append(data)
        // Snapshot frames to dispatch outside the lock to avoid reentrancy
        // (frame handlers may call back into the session via writeControl).
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
            dispatchFrame(cmd: frame.cmd, sid: frame.sid, payload: frame.payload)
        }
    }

    private func dispatchFrame(cmd: UInt8, sid: UInt32, payload: Data) {
        switch cmd {
        case AnyTLSProtocol.cmdPSH:
            lock.lock()
            let stream = streams[sid]
            lock.unlock()
            if stream == nil {
                logger.warning("[AnyTLSSession] cmdPSH for unknown sid=\(sid) (\(payload.count)B) — dropping")
            } else {
                logger.debug("[AnyTLSSession] cmdPSH sid=\(sid) \(payload.count)B")
            }
            stream?.deliverData(payload)

        case AnyTLSProtocol.cmdSYNACK:
            lock.lock()
            cancelSynDoneTimerLocked()
            let stream = streams[sid]
            lock.unlock()
            if !payload.isEmpty {
                let msg = String(data: payload, encoding: .utf8) ?? "<binary>"
                logger.warning("[AnyTLSSession] cmdSYNACK error sid=\(sid): \(msg)")
                stream?.deliverClose(error: ProxyError.protocolError("AnyTLS remote: \(msg)"))
                lock.withLock { streams[sid] = nil }
            } else {
                logger.debug("[AnyTLSSession] cmdSYNACK ok sid=\(sid)")
            }

        case AnyTLSProtocol.cmdFIN:
            lock.lock()
            let stream = streams.removeValue(forKey: sid)
            lock.unlock()
            logger.debug("[AnyTLSSession] cmdFIN sid=\(sid) (had stream=\(stream != nil))")
            stream?.deliverClose(error: nil)

        case AnyTLSProtocol.cmdWaste:
            logger.debug("[AnyTLSSession] cmdWaste sid=\(sid) \(payload.count)B (drained)")

        case AnyTLSProtocol.cmdServerSettings:
            let map = AnyTLSProtocol.decodeStringMap(payload)
            if let v = map["v"], let parsed = UInt8(v) {
                lock.withLock { peerVersion = parsed }
                logger.info("[AnyTLSSession] cmdServerSettings peerVersion=\(parsed) keys=\(Array(map.keys))")
            } else {
                logger.warning("[AnyTLSSession] cmdServerSettings missing or invalid v: \(map)")
            }

        case AnyTLSProtocol.cmdAlert:
            let msg = String(data: payload, encoding: .utf8) ?? "<binary>"
            logger.warning("[AnyTLSSession] cmdAlert from server: \(msg)")
            close(reason: ProxyError.protocolError("AnyTLS alert: \(msg)"))

        case AnyTLSProtocol.cmdUpdatePaddingScheme:
            if let new = AnyTLSPaddingScheme.parse(payload) {
                lock.withLock { padding = new }
                logger.info("[AnyTLSSession] cmdUpdatePaddingScheme applied md5=\(new.md5Hex) stop=\(new.stop)")
            } else {
                logger.warning("[AnyTLSSession] cmdUpdatePaddingScheme: failed to parse payload (\(payload.count)B)")
            }

        case AnyTLSProtocol.cmdHeartRequest:
            logger.debug("[AnyTLSSession] cmdHeartRequest sid=\(sid) — replying")
            let pong = AnyTLSProtocol.encodeFrameHeader(cmd: AnyTLSProtocol.cmdHeartResponse, sid: sid, length: 0)
            writeConnLocked(pong, completion: { _ in })

        case AnyTLSProtocol.cmdHeartResponse:
            // Active polling not implemented; drop.
            break

        default:
            logger.warning("[AnyTLSSession] unknown cmd=\(cmd) sid=\(sid) \(payload.count)B — ignoring")
        }
    }

    // MARK: - Teardown

    private func handleTransportEOF() {
        close(reason: nil)
    }

    private func handleTransportFailure(_ error: Error) {
        close(reason: error)
    }

    /// Idempotent. `reason == nil` means clean close; non-nil propagates to
    /// every live stream so callers see the underlying transport error.
    func close(reason: Error? = nil) {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        cancelSynDoneTimerLocked()
        let liveStreams = Array(streams.values)
        streams.removeAll(keepingCapacity: false)
        outboundBuffer.removeAll(keepingCapacity: false)
        lock.unlock()

        let reasonText = reason.map { $0.localizedDescription } ?? "clean"
        logger.info("[AnyTLSSession] close seq=\(seq) streams=\(liveStreams.count) reason=\(reasonText)")
        for stream in liveStreams {
            stream.deliverClose(error: reason)
        }
        inner.cancel()
        onClose?()
    }

    // MARK: - SynDone watchdog

    private func armSynDoneTimerLocked() {
        synDoneTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(deadline: .now() + .seconds(3))
        timer.setEventHandler { [weak self] in
            self?.close(reason: ProxyError.connectionFailed("AnyTLS SYN-ACK timeout"))
        }
        timer.resume()
        synDoneTimer = timer
    }

    private func cancelSynDoneTimerLocked() {
        synDoneTimer?.cancel()
        synDoneTimer = nil
    }
}
