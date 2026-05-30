//
//  XHTTPConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

// MARK: - HTTP/2 Transport (Setup, Send, Receive)

extension XHTTPConnection {

    // MARK: HTTP/2 Setup

    /// Performs HTTP/2 connection setup matching Go's http2.Transport behavior.
    ///
    /// Go's http2.Transport sends preface + SETTINGS + WINDOW_UPDATE immediately,
    /// then sends HEADERS without waiting for the server's SETTINGS first.
    /// We replicate this by sending preface + SETTINGS + WINDOW_UPDATE + HEADERS
    /// all in one write, then processing server frames (SETTINGS, ACK, etc.)
    /// while waiting for the response HEADERS (200 OK).
    func performH2Setup(completion: @escaping (Error?) -> Void) {
        var initData = h2ClientPreface()

        // HEADERS go out immediately, before the server's SETTINGS arrive, to save
        // a round trip; SETTINGS are handled afterward in processInitialServerFrames.
        // That step deliberately does not wait for the 200 response HEADERS: some
        // CDNs buffer the response until the backend produces body data, which only
        // happens after the POST sent post-setup, so waiting would deadlock.
        switch role {
        case .uploadOnly:
            // Upload leg on its own connection: the POST is stream 1, and no stream
            // here is the download stream — reads are a flow-control/response drain
            // (see startH2UploadPump). packet-up opens a stream per batch later.
            h2UploadStreamId = 1
            h2DownloadStreamId = .max
            if mode == .streamUp {
                let uploadHeaders = encodeH2UploadHeaders(seq: nil)
                initData.append(buildH2Frame(type: Self.h2FrameHeaders, flags: Self.h2FlagEndHeaders, streamId: h2UploadStreamId, payload: uploadHeaders))
            }
            downloadSend(initData) { [weak self] error in
                if let error {
                    completion(XHTTPError.setupFailed("H2 upload setup send failed: \(error.localizedDescription)"))
                    return
                }
                self?.processInitialServerFrames { [weak self] err in
                    if err == nil { self?.startH2UploadPump() }
                    completion(err)
                }
            }

        case .downloadOnly:
            // Download leg: GET on stream 1 only (no upload stream on this leg).
            let headerBlock = encodeH2RequestHeaders(method: "GET", includeMeta: true)
            initData.append(buildH2Frame(type: Self.h2FrameHeaders, flags: Self.h2FlagEndHeaders | Self.h2FlagEndStream, streamId: 1, payload: headerBlock))
            downloadSend(initData) { [weak self] error in
                if let error {
                    completion(XHTTPError.setupFailed("H2 download setup send failed: \(error.localizedDescription)"))
                    return
                }
                self?.processInitialServerFrames(completion: completion)
            }

        case .combined:
            if mode == .streamOne {
                let headerBlock = encodeH2RequestHeaders(method: "POST", includeMeta: false)
                initData.append(buildH2Frame(type: Self.h2FrameHeaders, flags: Self.h2FlagEndHeaders, streamId: 1, payload: headerBlock))
            } else {
                let headerBlock = encodeH2RequestHeaders(method: "GET", includeMeta: true)
                initData.append(buildH2Frame(type: Self.h2FrameHeaders, flags: Self.h2FlagEndHeaders | Self.h2FlagEndStream, streamId: 1, payload: headerBlock))
            }
            // For stream-up, also open the upload stream (stream 3) on this connection.
            if mode == .streamUp {
                let uploadHeaders = encodeH2UploadHeaders(seq: nil)
                initData.append(buildH2Frame(type: Self.h2FrameHeaders, flags: Self.h2FlagEndHeaders, streamId: h2UploadStreamId, payload: uploadHeaders))
            }
            downloadSend(initData) { [weak self] error in
                if let error {
                    completion(XHTTPError.setupFailed("H2 setup send failed: \(error.localizedDescription)"))
                    return
                }
                self?.processInitialServerFrames(completion: completion)
            }
        }
    }

    /// Builds the H2 client preface + client SETTINGS (ENABLE_PUSH off, 4MB stream
    /// window, 10MB max header list) + a 1GB connection-level WINDOW_UPDATE. Shared
    /// by all roles so each leg of a detached session opens its H2 connection
    /// identically.
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

    /// Background frame pump for an `.uploadOnly` H2 leg. Keeps connection-level
    /// flow control current (WINDOW_UPDATE), ACKs SETTINGS/PING, and discards POST
    /// responses so the server's writes never stall the upload. Runs until the
    /// connection closes; `receiveH2Data` never delivers data here because
    /// `h2DownloadStreamId == .max` matches no real stream.
    func startH2UploadPump() {
        receiveH2Data { [weak self] _, _ in
            self?.markH2Closed()
        }
    }

    /// Reads frames until the server's SETTINGS is received and ACKed.
    /// Does NOT wait for the 200 OK response — that is handled later by receiveH2Data.
    /// Any non-SETTINGS frames received here (WINDOW_UPDATE, PING, etc.) are processed
    /// normally. If the response HEADERS arrives early, it is handled and we complete.
    private func processInitialServerFrames(completion: @escaping (Error?) -> Void) {
        readH2Frame { [weak self] result in
            guard let self else {
                completion(XHTTPError.connectionClosed)
                return
            }

            switch result {
            case .failure(let error):
                completion(XHTTPError.setupFailed("H2 setup read failed: \(error.localizedDescription)"))

            case .success(let frame):
                switch frame.type {
                case Self.h2FrameSettings:
                    if frame.flags & Self.h2FlagAck == 0 {
                        // Server's SETTINGS — parse and send ACK, then complete
                        self.parseH2Settings(frame.payload)
                        let ack = self.buildH2Frame(type: Self.h2FrameSettings, flags: Self.h2FlagAck, streamId: 0, payload: Data())
                        self.downloadSend(ack) { _ in }
                        completion(nil)
                    } else {
                        // SETTINGS ACK for our settings — keep reading
                        self.processInitialServerFrames(completion: completion)
                    }

                case Self.h2FrameHeaders:
                    // Early response HEADERS — process and complete
                    let isDownload = frame.streamId == 0 || frame.streamId == self.h2DownloadStreamId
                    if isDownload {
                        if let rejection = self.checkH2ResponseStatus(frame.payload) {
                            completion(XHTTPError.setupFailed("H2 response rejected: \(rejection)"))
                            return
                        }
                        self.lock.lock()
                        self.h2ResponseReceived = true
                        self.lock.unlock()
                    }
                    completion(nil)

                case Self.h2FrameWindowUpdate:
                    self.lock.lock()
                    if frame.payload.count >= 4 {
                        let raw = frame.payload.prefix(4).withUnsafeBytes {
                            $0.load(as: UInt32.self).bigEndian
                        }
                        let increment = Int(raw & 0x7FFFFFFF)
                        if frame.streamId == 0 {
                            self.h2PeerConnectionWindow += increment
                        } else if self.h2PacketStreamWindows[frame.streamId] != nil {
                            self.h2PacketStreamWindows[frame.streamId]! += increment
                        } else {
                            self.h2PeerStreamSendWindow += increment
                        }
                    }
                    let resumptions = self.h2FlowResumptions
                    self.h2FlowResumptions.removeAll()
                    self.lock.unlock()
                    for r in resumptions { r() }
                    self.processInitialServerFrames(completion: completion)

                case Self.h2FramePing:
                    let pong = self.buildH2Frame(type: Self.h2FramePing, flags: Self.h2FlagAck, streamId: 0, payload: frame.payload)
                    self.downloadSend(pong) { _ in }
                    self.processInitialServerFrames(completion: completion)

                case Self.h2FrameGoaway:
                    completion(XHTTPError.setupFailed("Server sent GOAWAY"))

                default:
                    self.processInitialServerFrames(completion: completion)
                }
            }
        }
    }

    // MARK: HTTP/2 Send

    /// Marks the H2 connection as closed so subsequent sends fail fast.
    func markH2Closed() {
        lock.lock()
        h2StreamClosed = true
        lock.unlock()
    }

    /// Sends data as HTTP/2 DATA frame(s) on the given stream, respecting peer flow control.
    /// Batches as many frames as the window allows into a single transport write.
    func sendH2Data(data: Data, streamId: UInt32, offset: Int = 0, completion: @escaping (Error?) -> Void) {
        guard offset < data.count else {
            completion(nil)
            return
        }

        lock.lock()
        if h2StreamClosed {
            lock.unlock()
            completion(XHTTPError.connectionClosed)
            return
        }
        let maxSize = h2MaxFrameSize
        let window = min(h2PeerConnectionWindow, h2PeerStreamSendWindow)

        guard window > 0 else {
            h2FlowResumptions.append { [weak self] in
                self?.sendH2Data(data: data, streamId: streamId, offset: offset, completion: completion)
            }
            lock.unlock()
            return
        }

        // Batch multiple DATA frames into a single write
        var frames = Data()
        var currentOffset = offset
        var windowRemaining = window

        while currentOffset < data.count {
            let remaining = data.count - currentOffset
            let chunkSize = min(remaining, min(maxSize, windowRemaining))
            guard chunkSize > 0 else { break }

            let chunk = Data(data[data.startIndex + currentOffset ..< data.startIndex + currentOffset + chunkSize])
            frames.append(buildH2Frame(type: Self.h2FrameData, flags: 0, streamId: streamId, payload: chunk))
            currentOffset += chunkSize
            windowRemaining -= chunkSize
        }

        let totalSent = window - windowRemaining
        h2PeerConnectionWindow -= totalSent
        h2PeerStreamSendWindow -= totalSent
        lock.unlock()

        let nextOffset = currentOffset
        downloadSend(frames) { [weak self] error in
            if let error {
                self?.markH2Closed()
                completion(error)
                return
            }
            if nextOffset < data.count {
                self?.sendH2Data(data: data, streamId: streamId, offset: nextOffset, completion: completion)
            } else {
                completion(nil)
            }
        }
    }

    /// Sends data as a packet-up POST: opens a new HTTP/2 stream with HEADERS + DATA + END_STREAM.
    ///
    /// Matches Xray-core's `scMinPostsIntervalMs` delay: the completion is deferred so that
    /// rapid writes are batched into fewer, larger POSTs by the upstream coalescing buffer
    /// (TCPConnection keeps `uploadFlushInFlight` true during the delay).
    func sendH2PacketUp(data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        if h2StreamClosed {
            lock.unlock()
            completion(XHTTPError.connectionClosed)
            return
        }
        let streamId = h2NextPacketStreamId
        h2NextPacketStreamId += 2
        let seq = nextSeq
        nextSeq += 1
        let maxSize = h2MaxFrameSize
        // Packet-up: each new stream has h2PeerInitialWindowSize; only conn window is shared.
        let streamWindow = h2PeerInitialWindowSize
        let connectionWindow = h2PeerConnectionWindow

        // Build HEADERS for this upload POST (with session ID + seq metadata)
        let headerBlock = encodeH2UploadHeaders(seq: seq, contentLength: data.count)
        let headerFlags: UInt8 = data.isEmpty
            ? (Self.h2FlagEndHeaders | Self.h2FlagEndStream)
            : Self.h2FlagEndHeaders
        var outbound = buildH2Frame(type: Self.h2FrameHeaders, flags: headerFlags, streamId: streamId, payload: headerBlock)

        guard !data.isEmpty else {
            lock.unlock()
            // Rate limiting between POSTs is handled one layer up by
            // flushPacketUpBatch; complete as soon as the HEADERS frame is on the wire.
            downloadSend(outbound) { [weak self] error in
                if let error {
                    self?.markH2Closed()
                }
                completion(error)
            }
            return
        }

        // Batch DATA frames with HEADERS into a single write when window allows
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
        // Stream window for this stream is not tracked globally (short-lived)
        let perStreamRemaining = streamWindow - totalSent
        lock.unlock()

        let nextOffset = currentOffset
        downloadSend(outbound) { [weak self] error in
            if let error {
                self?.markH2Closed()
                completion(error)
                return
            }
            if nextOffset < data.count {
                // Remaining data needs more window — continue via sendH2PacketUpData
                self?.sendH2PacketUpData(data: data, streamId: streamId, offset: nextOffset, maxSize: maxSize, streamWindow: perStreamRemaining) { [weak self] error in
                    if let error {
                        self?.markH2Closed()
                    }
                    completion(error)
                }
            } else {
                completion(nil)
            }
        }
    }

    /// Sends DATA frames for a packet-up upload stream, with END_STREAM on the last frame.
    /// Batches as many frames as the window allows into a single transport write.
    /// `streamWindow` tracks the per-stream remaining window (not stored globally since packet-up streams are short-lived).
    private func sendH2PacketUpData(data: Data, streamId: UInt32, offset: Int = 0, maxSize: Int, streamWindow: Int, completion: @escaping (Error?) -> Void) {
        guard offset < data.count else {
            completion(nil)
            return
        }

        lock.lock()
        if h2StreamClosed {
            lock.unlock()
            completion(XHTTPError.connectionClosed)
            return
        }
        // Use window updated by WINDOW_UPDATE if this send was previously blocked.
        let effectiveStreamWindow = h2PacketStreamWindows.removeValue(forKey: streamId) ?? streamWindow
        let window = min(h2PeerConnectionWindow, effectiveStreamWindow)

        guard window > 0 else {
            h2PacketStreamWindows[streamId] = effectiveStreamWindow
            h2FlowResumptions.append { [weak self] in
                self?.sendH2PacketUpData(data: data, streamId: streamId, offset: offset, maxSize: maxSize, streamWindow: effectiveStreamWindow, completion: completion)
            }
            lock.unlock()
            return
        }

        var frames = Data()
        var currentOffset = offset
        var windowRemaining = window

        while currentOffset < data.count {
            let remaining = data.count - currentOffset
            let chunkSize = min(remaining, min(maxSize, windowRemaining))
            guard chunkSize > 0 else { break }

            let isLast = (currentOffset + chunkSize) >= data.count
            let flags: UInt8 = isLast ? Self.h2FlagEndStream : 0
            let chunk = Data(data[data.startIndex + currentOffset ..< data.startIndex + currentOffset + chunkSize])
            frames.append(buildH2Frame(type: Self.h2FrameData, flags: flags, streamId: streamId, payload: chunk))
            currentOffset += chunkSize
            windowRemaining -= chunkSize
        }

        let totalSent = window - windowRemaining
        h2PeerConnectionWindow -= totalSent
        let newStreamWindow = effectiveStreamWindow - totalSent
        lock.unlock()

        let nextOffset = currentOffset
        downloadSend(frames) { [weak self] error in
            if let error {
                self?.markH2Closed()
                completion(error)
                return
            }
            if nextOffset < data.count {
                self?.sendH2PacketUpData(data: data, streamId: streamId, offset: nextOffset, maxSize: maxSize, streamWindow: newStreamWindow, completion: completion)
            } else {
                completion(nil)
            }
        }
    }

    // MARK: HTTP/2 Receive

    /// Receives data from HTTP/2 DATA frames on the download stream (stream 1).
    /// Frames for other streams (upload responses) are silently consumed.
    func receiveH2Data(completion: @escaping (Data?, Error?) -> Void) {
        // Check buffered data first
        lock.lock()
        if !h2DataBuffer.isEmpty {
            let data = h2DataBuffer
            h2DataBuffer.removeAll()
            lock.unlock()
            completion(data, nil)
            return
        }
        if h2StreamClosed {
            lock.unlock()
            completion(nil, nil)
            return
        }
        lock.unlock()

        // Read next frame
        readH2Frame { [weak self] result in
            guard let self else {
                completion(nil, XHTTPError.connectionClosed)
                return
            }

            switch result {
            case .failure(let error):
                completion(nil, error)

            case .success(let frame):
                let isDownloadStream = frame.streamId == 0 || frame.streamId == self.h2DownloadStreamId

                switch frame.type {
                case Self.h2FrameData:
                    // Batch WINDOW_UPDATEs: accumulate consumed bytes and send
                    // when >= 50% of window is consumed (matches Go http2 behavior).
                    // Only send stream-level WINDOW_UPDATE for the download stream;
                    // upload streams may already be closed, and sending WINDOW_UPDATE
                    // for a closed stream triggers RST_STREAM (STREAM_CLOSED) from
                    // the server, which would disrupt the connection.
                    if !frame.payload.isEmpty {
                        self.lock.lock()
                        self.h2ConnectionReceiveConsumed += frame.payload.count
                        if isDownloadStream {
                            self.h2StreamReceiveConsumed += frame.payload.count
                        }
                        let windowSize = self.h2LocalWindowSize
                        let connConsumed = self.h2ConnectionReceiveConsumed
                        let streamConsumed = self.h2StreamReceiveConsumed
                        let threshold = windowSize / 2
                        if connConsumed >= threshold { self.h2ConnectionReceiveConsumed = 0 }
                        if streamConsumed >= threshold { self.h2StreamReceiveConsumed = 0 }
                        self.lock.unlock()

                        var updates = Data()
                        if connConsumed >= threshold {
                            let inc = UInt32(connConsumed)
                            var p = Data(count: 4)
                            p[0] = UInt8((inc >> 24) & 0xFF); p[1] = UInt8((inc >> 16) & 0xFF)
                            p[2] = UInt8((inc >> 8) & 0xFF); p[3] = UInt8(inc & 0xFF)
                            updates.append(self.buildH2Frame(type: Self.h2FrameWindowUpdate, flags: 0, streamId: 0, payload: p))
                        }
                        if isDownloadStream && streamConsumed >= threshold {
                            let inc = UInt32(streamConsumed)
                            var p = Data(count: 4)
                            p[0] = UInt8((inc >> 24) & 0xFF); p[1] = UInt8((inc >> 16) & 0xFF)
                            p[2] = UInt8((inc >> 8) & 0xFF); p[3] = UInt8(inc & 0xFF)
                            updates.append(self.buildH2Frame(type: Self.h2FrameWindowUpdate, flags: 0, streamId: frame.streamId, payload: p))
                        }
                        if !updates.isEmpty {
                            self.downloadSend(updates) { _ in }
                        }
                    }

                    if isDownloadStream {
                        if frame.flags & Self.h2FlagEndStream != 0 {
                            self.lock.lock()
                            self.h2StreamClosed = true
                            self.lock.unlock()
                        }

                        if frame.payload.isEmpty {
                            if frame.flags & Self.h2FlagEndStream != 0 {
                                completion(nil, nil)
                            } else {
                                self.receiveH2Data(completion: completion)
                            }
                        } else {
                            completion(frame.payload, nil)
                        }
                    } else {
                        // Upload stream response data — ignore
                        self.receiveH2Data(completion: completion)
                    }

                case Self.h2FrameHeaders:
                    if isDownloadStream {
                        if frame.flags & Self.h2FlagEndStream != 0 {
                            self.lock.lock()
                            self.h2StreamClosed = true
                            self.lock.unlock()
                            completion(nil, nil)
                        } else if !self.h2ResponseReceived {
                            if self.checkH2ResponseStatus(frame.payload) == nil {
                                self.lock.lock()
                                self.h2ResponseReceived = true
                                self.lock.unlock()
                            }
                            self.receiveH2Data(completion: completion)
                        } else {
                            self.receiveH2Data(completion: completion)
                        }
                    } else {
                        // Upload stream response — ignore regardless of status.
                        // The POST data was already delivered; a non-200 reply
                        // (e.g. 500 from CDN) should not tear down the download.
                        self.receiveH2Data(completion: completion)
                    }

                case Self.h2FrameSettings:
                    if frame.flags & Self.h2FlagAck == 0 {
                        self.parseH2Settings(frame.payload)
                        let ack = self.buildH2Frame(type: Self.h2FrameSettings, flags: Self.h2FlagAck, streamId: 0, payload: Data())
                        self.downloadSend(ack) { _ in }
                    }
                    self.receiveH2Data(completion: completion)

                case Self.h2FrameWindowUpdate:
                    self.lock.lock()
                    if frame.payload.count >= 4 {
                        let raw = frame.payload.prefix(4).withUnsafeBytes {
                            $0.load(as: UInt32.self).bigEndian
                        }
                        let increment = Int(raw & 0x7FFFFFFF)
                        if frame.streamId == 0 {
                            self.h2PeerConnectionWindow += increment
                        } else if self.h2PacketStreamWindows[frame.streamId] != nil {
                            self.h2PacketStreamWindows[frame.streamId]! += increment
                        } else {
                            self.h2PeerStreamSendWindow += increment
                        }
                    }
                    let resumptions = self.h2FlowResumptions
                    self.h2FlowResumptions.removeAll()
                    self.lock.unlock()
                    for r in resumptions { r() }
                    self.receiveH2Data(completion: completion)

                case Self.h2FramePing:
                    let pong = self.buildH2Frame(type: Self.h2FramePing, flags: Self.h2FlagAck, streamId: 0, payload: frame.payload)
                    self.downloadSend(pong) { _ in }
                    self.receiveH2Data(completion: completion)

                case Self.h2FrameGoaway:
                    self.lock.lock()
                    self.h2StreamClosed = true
                    self.lock.unlock()
                    completion(nil, nil)

                case Self.h2FrameRstStream:
                    if isDownloadStream {
                        self.lock.lock()
                        self.h2StreamClosed = true
                        self.lock.unlock()
                        completion(nil, nil)
                    } else {
                        // Upload stream resets are expected after the server
                        // finishes processing the POST. Silently ignore and
                        // keep reading for download stream data.
                        self.receiveH2Data(completion: completion)
                    }

                default:
                    self.receiveH2Data(completion: completion)
                }
            }
        }
    }
}
