//
//  XHTTPConnection+H2Transport.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

// MARK: - HTTP/2 Transport (Setup, Send, Receive)

extension XHTTPConnection {

    // MARK: HTTP/2 Setup

    /// HTTP/2 setup: preface + SETTINGS + WINDOW_UPDATE + HEADERS in one write,
    /// without waiting for the server's SETTINGS first.
    func performH2Setup() async throws {
        var initData = h2ClientPreface()

        // Setup deliberately does not wait for the 200 response HEADERS: some CDNs
        // buffer it until the backend sees POST body data, so waiting would deadlock.
        switch role {
        case .uploadOnly:
            // POST is stream 1; no download stream, so reads are only a flow-control/response drain.
            h2UploadStreamId = 1
            h2DownloadStreamId = .max
            if mode == .streamUp {
                let uploadHeaders = encodeH2UploadHeaders(seq: nil)
                initData.append(buildH2Frame(type: Self.h2FrameHeaders, flags: Self.h2FlagEndHeaders, streamId: h2UploadStreamId, payload: uploadHeaders))
            }
            do {
                try await download.send(initData)
            } catch {
                throw XHTTPError.setupFailed("H2 upload setup send failed: \(error.localizedDescription)")
            }
            try await processInitialServerFrames()
            startH2UploadPump()

        case .downloadOnly:
            let headerBlock = encodeH2RequestHeaders(method: "GET", includeMeta: true)
            initData.append(buildH2Frame(type: Self.h2FrameHeaders, flags: Self.h2FlagEndHeaders | Self.h2FlagEndStream, streamId: 1, payload: headerBlock))
            do {
                try await download.send(initData)
            } catch {
                throw XHTTPError.setupFailed("H2 download setup send failed: \(error.localizedDescription)")
            }
            try await processInitialServerFrames()

        case .combined:
            if mode == .streamOne {
                let headerBlock = encodeH2RequestHeaders(method: "POST", includeMeta: false)
                initData.append(buildH2Frame(type: Self.h2FrameHeaders, flags: Self.h2FlagEndHeaders, streamId: 1, payload: headerBlock))
            } else {
                let headerBlock = encodeH2RequestHeaders(method: "GET", includeMeta: true)
                initData.append(buildH2Frame(type: Self.h2FrameHeaders, flags: Self.h2FlagEndHeaders | Self.h2FlagEndStream, streamId: 1, payload: headerBlock))
            }
            if mode == .streamUp {
                let uploadHeaders = encodeH2UploadHeaders(seq: nil)
                initData.append(buildH2Frame(type: Self.h2FrameHeaders, flags: Self.h2FlagEndHeaders, streamId: h2UploadStreamId, payload: uploadHeaders))
            }
            do {
                try await download.send(initData)
            } catch {
                throw XHTTPError.setupFailed("H2 setup send failed: \(error.localizedDescription)")
            }
            try await processInitialServerFrames()
        }
    }

    /// Client preface + SETTINGS (ENABLE_PUSH off, 4MB stream window, 10MB max
    /// header list) + a 1GB connection-level WINDOW_UPDATE.
    private func h2ClientPreface() -> Data {
        var initData = Data()
        initData.append(Self.h2Preface)

        var settingsPayload = Data()
        settingsPayload.append(contentsOf: [0x00, 0x02, 0x00, 0x00, 0x00, 0x00])
        let winSize = Self.h2StreamWindowSize
        settingsPayload.append(contentsOf: [
            0x00, 0x04,
            UInt8((winSize >> 24) & 0xFF), UInt8((winSize >> 16) & 0xFF),
            UInt8((winSize >> 8) & 0xFF), UInt8(winSize & 0xFF)
        ])
        settingsPayload.append(contentsOf: [0x00, 0x06, 0x00, 0xA0, 0x00, 0x00])
        initData.append(buildH2Frame(type: Self.h2FrameSettings, flags: 0, streamId: 0, payload: settingsPayload))

        let windowIncrement = Self.h2ConnectionWindowSize
        var wuPayload = Data(count: 4)
        wuPayload[0] = UInt8((windowIncrement >> 24) & 0xFF)
        wuPayload[1] = UInt8((windowIncrement >> 16) & 0xFF)
        wuPayload[2] = UInt8((windowIncrement >> 8) & 0xFF)
        wuPayload[3] = UInt8(windowIncrement & 0xFF)
        initData.append(buildH2Frame(type: Self.h2FrameWindowUpdate, flags: 0, streamId: 0, payload: wuPayload))
        return initData
    }

    /// Frame pump for an `.uploadOnly` leg: keeps flow control current, ACKs SETTINGS/PING,
    /// and discards POST responses; never delivers data since `h2DownloadStreamId == .max`.
    func startH2UploadPump() {
        Task { [weak self] in
            while true {
                guard let self else { return }
                let data: Data?
                do {
                    data = try await self.receiveH2Data()
                } catch {
                    self.markH2Closed()
                    return
                }
                if data == nil { self.markH2Closed(); return }
            }
        }
    }

    /// Reads frames until the server's SETTINGS is received and ACKed; does not
    /// wait for the 200 OK, and early HEADERS complete the setup.
    private func processInitialServerFrames() async throws {
        while true {
            let frame: H2Framing.Frame
            do {
                frame = try await h2FrameReader.readFrame()
            } catch {
                throw XHTTPError.setupFailed("H2 setup read failed: \(error.localizedDescription)")
            }

            switch frame.type {
            case Self.h2FrameSettings:
                if frame.flags & Self.h2FlagAck == 0 {
                    parseH2Settings(frame.payload)
                    let ack = buildH2Frame(type: Self.h2FrameSettings, flags: Self.h2FlagAck, streamId: 0, payload: Data())
                    try? await download.send(ack)
                    return
                }
                continue

            case Self.h2FrameHeaders:
                let isDownload = frame.streamId == 0 || frame.streamId == h2DownloadStreamId
                if isDownload {
                    if let rejection = checkH2ResponseStatus(frame.payload) {
                        throw XHTTPError.setupFailed("H2 response rejected: \(rejection)")
                    }
                    lock.withLock { h2ResponseReceived = true }
                }
                return

            case Self.h2FrameWindowUpdate:
                let resumptions: [CheckedContinuation<Void, Never>] = lock.withLock {
                    if frame.payload.count >= 4 {
                        let windowIncrementRaw = frame.payload.prefix(4).withUnsafeBytes {
                            $0.load(as: UInt32.self).bigEndian
                        }
                        let increment = Int(windowIncrementRaw & 0x7FFFFFFF)
                        if frame.streamId == 0 {
                            h2PeerConnectionWindow += increment
                        } else if h2PacketStreamWindows[frame.streamId] != nil {
                            h2PacketStreamWindows[frame.streamId]! += increment
                        } else {
                            h2PeerStreamSendWindow += increment
                        }
                    }
                    let resumptions = h2FlowResumptions
                    h2FlowResumptions.removeAll()
                    return resumptions
                }
                for continuation in resumptions { continuation.resume() }
                continue

            case Self.h2FramePing:
                let pong = buildH2Frame(type: Self.h2FramePing, flags: Self.h2FlagAck, streamId: 0, payload: frame.payload)
                try? await download.send(pong)
                continue

            case Self.h2FrameGoaway:
                throw XHTTPError.setupFailed("Server sent GOAWAY")

            default:
                continue
            }
        }
    }

    // MARK: HTTP/2 Send

    /// Marks the stream closed and wakes sends parked on flow control — a send awaiting a
    /// WINDOW_UPDATE that will never arrive must observe the close, not hang until cancel().
    func markH2Closed() {
        let resumptions: [CheckedContinuation<Void, Never>] = lock.withLock {
            h2StreamClosed = true
            let resumptions = h2FlowResumptions
            h2FlowResumptions.removeAll()
            return resumptions
        }
        for continuation in resumptions { continuation.resume() }
    }

    /// Suspends until a WINDOW_UPDATE re-opens a send window (or the stream closes). `hasWindow`
    /// is evaluated under the lock so a window re-open racing the caller's check isn't missed.
    private func parkForH2Flow(hasWindow: () -> Bool) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let resumeNow: Bool = lock.withLock {
                if h2StreamClosed { return true }
                if hasWindow() { return true }
                h2FlowResumptions.append(continuation)
                return false
            }
            if resumeNow { continuation.resume() }
        }
    }

    /// Sends DATA frames respecting peer flow control, batching as much as the window allows
    /// into one transport write; the remainder awaits a WINDOW_UPDATE.
    func sendH2Data(data: Data, streamId: UInt32, offset: Int = 0) async throws {
        enum BuildStep {
            case closed
            case park
            case built(frames: Data, nextOffset: Int)
        }
        var currentOffset = offset
        while currentOffset < data.count {
            let step: BuildStep = lock.withLock {
                if h2StreamClosed { return .closed }
                let maxSize = h2MaxFrameSize
                let window = min(h2PeerConnectionWindow, h2PeerStreamSendWindow)
                guard window > 0 else { return .park }

                var frames = Data()
                var current = currentOffset
                var windowRemaining = window
                while current < data.count {
                    let remaining = data.count - current
                    let chunkSize = min(remaining, min(maxSize, windowRemaining))
                    guard chunkSize > 0 else { break }
                    let chunk = Data(data[data.startIndex + current ..< data.startIndex + current + chunkSize])
                    frames.append(buildH2Frame(type: Self.h2FrameData, flags: 0, streamId: streamId, payload: chunk))
                    current += chunkSize
                    windowRemaining -= chunkSize
                }
                let totalSent = window - windowRemaining
                h2PeerConnectionWindow -= totalSent
                h2PeerStreamSendWindow -= totalSent
                return .built(frames: frames, nextOffset: current)
            }

            switch step {
            case .closed:
                throw XHTTPError.connectionClosed
            case .park:
                await parkForH2Flow { min(self.h2PeerConnectionWindow, self.h2PeerStreamSendWindow) > 0 }
            case .built(let frames, let nextOffset):
                do {
                    try await download.send(frames)
                } catch {
                    markH2Closed()
                    throw error
                }
                currentOffset = nextOffset
            }
        }
    }

    /// Sends a packet-up batch as a new HTTP/2 stream. Called under `packetUpMutex`.
    func sendH2PacketUp(data: Data) async throws {
        enum Build {
            case closed
            case headersOnly(Data)
            case withBody(outbound: Data, streamId: UInt32, nextOffset: Int, maxSize: Int, streamWindow: Int)
        }
        let build: Build = lock.withLock {
            if h2StreamClosed { return .closed }
            let streamId = h2NextPacketStreamId
            h2NextPacketStreamId += 2
            let seq = nextSeq
            nextSeq += 1
            let maxSize = h2MaxFrameSize
            // Packet-up: each new stream has h2PeerInitialWindowSize; only conn window is shared.
            let streamWindow = h2PeerInitialWindowSize
            let connectionWindow = h2PeerConnectionWindow

            // Header/cookie placement carries the payload in the HEADERS block; the body stays empty.
            let dataFields = uplinkDataFields(for: data)
            let bodyInHeaders = !dataFields.isEmpty
            let bodyLength = bodyInHeaders ? 0 : data.count
            let headerBlock = encodeH2UploadHeaders(seq: seq, contentLength: bodyLength, uplinkData: dataFields)
            let sendsBody = !bodyInHeaders && !data.isEmpty
            let headerFlags: UInt8 = sendsBody
                ? Self.h2FlagEndHeaders
                : (Self.h2FlagEndHeaders | Self.h2FlagEndStream)
            var outbound = buildH2Frame(type: Self.h2FrameHeaders, flags: headerFlags, streamId: streamId, payload: headerBlock)

            guard sendsBody else { return .headersOnly(outbound) }

            let window = min(connectionWindow, streamWindow)
            var currentOffset = 0
            var windowRemaining = window
            while currentOffset < data.count {
                let remaining = data.count - currentOffset
                let chunkSize = min(remaining, min(maxSize, windowRemaining))
                guard chunkSize > 0 else { break }
                let isLast = (currentOffset + chunkSize) >= data.count
                let flags: UInt8 = isLast ? Self.h2FlagEndStream : 0
                let chunk = Data(data[data.startIndex + currentOffset ..< data.startIndex + currentOffset + chunkSize])
                outbound.append(buildH2Frame(type: Self.h2FrameData, flags: flags, streamId: streamId, payload: chunk))
                currentOffset += chunkSize
                windowRemaining -= chunkSize
            }
            let totalSent = window - windowRemaining
            h2PeerConnectionWindow -= totalSent
            // Stream window for this stream is not tracked globally (short-lived).
            let perStreamRemaining = streamWindow - totalSent
            return .withBody(outbound: outbound, streamId: streamId, nextOffset: currentOffset, maxSize: maxSize, streamWindow: perStreamRemaining)
        }

        switch build {
        case .closed:
            throw XHTTPError.connectionClosed
        case .headersOnly(let outbound):
            // Rate limiting between POSTs is enforced upstream by `rateLimitPacketUp`.
            do {
                try await download.send(outbound)
            } catch {
                markH2Closed()
                throw error
            }
        case .withBody(let outbound, let streamId, let nextOffset, let maxSize, let streamWindow):
            do {
                try await download.send(outbound)
            } catch {
                markH2Closed()
                throw error
            }
            if nextOffset < data.count {
                do {
                    try await sendH2PacketUpData(data: data, streamId: streamId, offset: nextOffset, maxSize: maxSize, streamWindow: streamWindow)
                } catch {
                    markH2Closed()
                    throw error
                }
            }
        }
    }

    /// Sends packet-up DATA frames with END_STREAM on the last; `streamWindow` is the
    /// per-stream remaining window (not stored globally — packet-up streams are short-lived).
    private func sendH2PacketUpData(data: Data, streamId: UInt32, offset: Int = 0, maxSize: Int, streamWindow: Int) async throws {
        enum BuildStep {
            case closed
            case park
            case built(frames: Data, nextOffset: Int, streamWindow: Int)
        }
        var currentOffset = offset
        var currentStreamWindow = streamWindow
        while currentOffset < data.count {
            let step: BuildStep = lock.withLock {
                if h2StreamClosed { return .closed }
                // Use the window updated by WINDOW_UPDATE if this send was previously blocked.
                let effectiveStreamWindow = h2PacketStreamWindows.removeValue(forKey: streamId) ?? currentStreamWindow
                let window = min(h2PeerConnectionWindow, effectiveStreamWindow)
                guard window > 0 else {
                    h2PacketStreamWindows[streamId] = effectiveStreamWindow
                    return .park
                }
                var frames = Data()
                var current = currentOffset
                var windowRemaining = window
                while current < data.count {
                    let remaining = data.count - current
                    let chunkSize = min(remaining, min(maxSize, windowRemaining))
                    guard chunkSize > 0 else { break }
                    let isLast = (current + chunkSize) >= data.count
                    let flags: UInt8 = isLast ? Self.h2FlagEndStream : 0
                    let chunk = Data(data[data.startIndex + current ..< data.startIndex + current + chunkSize])
                    frames.append(buildH2Frame(type: Self.h2FrameData, flags: flags, streamId: streamId, payload: chunk))
                    current += chunkSize
                    windowRemaining -= chunkSize
                }
                let totalSent = window - windowRemaining
                h2PeerConnectionWindow -= totalSent
                let newStreamWindow = effectiveStreamWindow - totalSent
                return .built(frames: frames, nextOffset: current, streamWindow: newStreamWindow)
            }

            switch step {
            case .closed:
                throw XHTTPError.connectionClosed
            case .park:
                await parkForH2Flow { min(self.h2PeerConnectionWindow, self.h2PacketStreamWindows[streamId] ?? currentStreamWindow) > 0 }
            case .built(let frames, let nextOffset, let newStreamWindow):
                do {
                    try await download.send(frames)
                } catch {
                    markH2Closed()
                    throw error
                }
                currentOffset = nextOffset
                currentStreamWindow = newStreamWindow
            }
        }
    }

    // MARK: HTTP/2 Receive

    /// Receives DATA from the download stream; frames for other streams are silently consumed.
    /// Returns `nil` on EOF. The straight-line `async` loop replaces the callback recursion.
    func receiveH2Data() async throws -> Data? {
        let buffered: Data? = lock.withLock {
            if !h2DataBuffer.isEmpty {
                let data = h2DataBuffer
                h2DataBuffer.removeAll()
                return data
            }
            return nil
        }
        if let buffered { return buffered }
        if lock.withLock({ h2StreamClosed }) { return nil }

        while true {
            let frame: H2Framing.Frame
            do {
                frame = try await h2FrameReader.readFrame()
            } catch {
                if let xhttpError = error as? XHTTPError, case .streamEnded = xhttpError {
                    // Graceful end of stream (clean transport FIN) → EOF.
                    markH2Closed()
                    return nil
                }
                throw error
            }

            let isDownloadStream = frame.streamId == 0 || frame.streamId == h2DownloadStreamId

            switch frame.type {
            case Self.h2FrameData:
                // Batch WINDOW_UPDATEs at >= 50% of window consumed. Stream-level updates only
                // for the download stream — updating a possibly-closed upload stream draws
                // RST_STREAM (STREAM_CLOSED).
                if !frame.payload.isEmpty {
                    let updates: Data = lock.withLock {
                        h2ConnectionReceiveConsumed += frame.payload.count
                        if isDownloadStream {
                            h2StreamReceiveConsumed += frame.payload.count
                        }
                        let windowSize = h2LocalWindowSize
                        let connConsumed = h2ConnectionReceiveConsumed
                        let streamConsumed = h2StreamReceiveConsumed
                        let threshold = windowSize / 2
                        if connConsumed >= threshold { h2ConnectionReceiveConsumed = 0 }
                        if streamConsumed >= threshold { h2StreamReceiveConsumed = 0 }

                        var updates = Data()
                        if connConsumed >= threshold {
                            let increment = UInt32(connConsumed)
                            var windowUpdatePayload = Data(count: 4)
                            windowUpdatePayload[0] = UInt8((increment >> 24) & 0xFF); windowUpdatePayload[1] = UInt8((increment >> 16) & 0xFF)
                            windowUpdatePayload[2] = UInt8((increment >> 8) & 0xFF); windowUpdatePayload[3] = UInt8(increment & 0xFF)
                            updates.append(buildH2Frame(type: Self.h2FrameWindowUpdate, flags: 0, streamId: 0, payload: windowUpdatePayload))
                        }
                        if isDownloadStream && streamConsumed >= threshold {
                            let increment = UInt32(streamConsumed)
                            var windowUpdatePayload = Data(count: 4)
                            windowUpdatePayload[0] = UInt8((increment >> 24) & 0xFF); windowUpdatePayload[1] = UInt8((increment >> 16) & 0xFF)
                            windowUpdatePayload[2] = UInt8((increment >> 8) & 0xFF); windowUpdatePayload[3] = UInt8(increment & 0xFF)
                            updates.append(buildH2Frame(type: Self.h2FrameWindowUpdate, flags: 0, streamId: frame.streamId, payload: windowUpdatePayload))
                        }
                        return updates
                    }
                    if !updates.isEmpty {
                        try? await download.send(updates)
                    }
                }

                if isDownloadStream {
                    if frame.flags & Self.h2FlagEndStream != 0 {
                        markH2Closed()
                    }
                    if frame.payload.isEmpty {
                        if frame.flags & Self.h2FlagEndStream != 0 { return nil }
                        // else: keep reading
                    } else {
                        return frame.payload
                    }
                }
                // non-download stream (or empty non-end frame): keep reading

            case Self.h2FrameHeaders:
                if isDownloadStream {
                    if frame.flags & Self.h2FlagEndStream != 0 {
                        markH2Closed()
                        return nil
                    } else if !lock.withLock({ h2ResponseReceived }) {
                        if checkH2ResponseStatus(frame.payload) == nil {
                            lock.withLock { h2ResponseReceived = true }
                        }
                    }
                }
                // Ignore upload responses regardless of status; a non-200 must not tear down the
                // download. In all cases keep reading.

            case Self.h2FrameSettings:
                if frame.flags & Self.h2FlagAck == 0 {
                    parseH2Settings(frame.payload)
                    let ack = buildH2Frame(type: Self.h2FrameSettings, flags: Self.h2FlagAck, streamId: 0, payload: Data())
                    try? await download.send(ack)
                }

            case Self.h2FrameWindowUpdate:
                let resumptions: [CheckedContinuation<Void, Never>] = lock.withLock {
                    if frame.payload.count >= 4 {
                        let raw = frame.payload.prefix(4).withUnsafeBytes {
                            $0.load(as: UInt32.self).bigEndian
                        }
                        let increment = Int(raw & 0x7FFFFFFF)
                        if frame.streamId == 0 {
                            h2PeerConnectionWindow += increment
                        } else if h2PacketStreamWindows[frame.streamId] != nil {
                            h2PacketStreamWindows[frame.streamId]! += increment
                        } else {
                            h2PeerStreamSendWindow += increment
                        }
                    }
                    let resumptions = h2FlowResumptions
                    h2FlowResumptions.removeAll()
                    return resumptions
                }
                for continuation in resumptions { continuation.resume() }

            case Self.h2FramePing:
                let pong = buildH2Frame(type: Self.h2FramePing, flags: Self.h2FlagAck, streamId: 0, payload: frame.payload)
                try? await download.send(pong)

            case Self.h2FrameGoaway:
                markH2Closed()
                return nil

            case Self.h2FrameRstStream:
                if isDownloadStream {
                    markH2Closed()
                    return nil
                }
                // Upload stream resets are expected after the POST completes; keep reading.

            default:
                break
            }
        }
    }

    // MARK: Shared-H2 (xmux) session setup & send

    /// Setup over a shared multiplexing H2 connection; mirrors the H3 path but with HPACK headers.
    func performSharedH2Setup() async throws {
        guard let shared = sharedH2 else {
            throw XHTTPError.setupFailed("no shared H2 connection")
        }
        switch role {
        case .downloadOnly:
            try await setupSharedH2Download(shared)
        case .uploadOnly:
            // packet-up opens a stream per batch, so only stream-up opens anything at setup.
            if mode == .streamUp {
                try await openSharedH2Upload(shared)
            }
        case .combined:
            switch mode {
            case .streamOne:
                // Full-duplex POST on one stream; can't wait for the response (CDN buffering).
                let stream = shared.openStream()
                lock.withLock { sharedH2Download = stream }
                xmuxLease?.noteRequest()
                let headers = encodeH2RequestHeaders(method: "POST", includeMeta: false)
                try await stream.sendHeaders(headers, endStream: false)
            case .streamUp:
                try await setupSharedH2Download(shared)
                guard let shared = sharedH2 else { throw XHTTPError.connectionClosed }
                try await openSharedH2Upload(shared)
            default: // packet-up (and .auto already resolved)
                try await setupSharedH2Download(shared)
            }
        }
    }

    /// Opens the GET download stream; returns on send (a CDN may withhold the 200 until upload flows).
    private func setupSharedH2Download(_ shared: XHTTPH2Multiplexer) async throws {
        let stream = shared.openStream()
        lock.withLock { sharedH2Download = stream }
        xmuxLease?.noteRequest()
        let headers = encodeH2RequestHeaders(method: "GET", includeMeta: true)
        try await stream.sendHeaders(headers, endStream: true)
    }

    /// Opens the persistent stream-up upload POST; its response is drained.
    private func openSharedH2Upload(_ shared: XHTTPH2Multiplexer) async throws {
        let stream = shared.openStream()
        lock.withLock { sharedH2Upload = stream }
        xmuxLease?.noteRequest()
        let headers = encodeH2UploadHeaders(seq: nil)
        try await stream.sendHeaders(headers, endStream: false)
        stream.drainResponse()
    }

    /// Sends one packet-up batch as its own shared-H2 stream; the response only acks receipt.
    /// Called under `packetUpMutex`.
    func sendSharedH2PacketUp(data: Data) async throws {
        guard let shared = sharedH2 else { throw XHTTPError.connectionClosed }
        let seq = lock.withLock { () -> Int64 in let s = nextSeq; nextSeq += 1; return s }
        xmuxLease?.noteRequest()

        // Header/cookie placement carries the payload in the HEADERS block; the body stays empty.
        let dataFields = uplinkDataFields(for: data)
        let bodyInHeaders = !dataFields.isEmpty
        let bodyLength = bodyInHeaders ? 0 : data.count
        let headers = encodeH2UploadHeaders(seq: seq, contentLength: bodyLength, uplinkData: dataFields)
        let stream = shared.openStream()

        if bodyInHeaders || data.isEmpty {
            do {
                try await stream.sendHeaders(headers, endStream: true)
            } catch {
                stream.close()
                throw error
            }
            stream.drainResponse()
        } else {
            do {
                try await stream.sendHeaders(headers, endStream: false)
                try await stream.sendData(data, endStream: true)
            } catch {
                stream.close()
                throw error
            }
            stream.drainResponse()
        }
    }
}
