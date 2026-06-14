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

    /// HTTP/2 setup matching Go's http2.Transport: preface + SETTINGS + WINDOW_UPDATE
    /// + HEADERS in one write, without waiting for the server's SETTINGS first.
    func performH2Setup(completion: @escaping (Error?) -> Void) {
        var initData = h2ClientPreface()

        // Setup deliberately does not wait for the 200 response HEADERS: some CDNs
        // buffer it until the backend sees POST body data, so waiting would deadlock.
        switch role {
        case .uploadOnly:
            // Upload leg: the POST is stream 1; no stream here is the download
            // stream, so reads are only a flow-control/response drain.
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
        receiveH2Data { [weak self] _, _ in
            self?.markH2Closed()
        }
    }

    /// Reads frames until the server's SETTINGS is received and ACKed; does not
    /// wait for the 200 OK, and early HEADERS complete the setup.
    private func processInitialServerFrames(completion: @escaping (Error?) -> Void) {
        h2FrameReader.readFrame { [weak self] result in
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
                        self.parseH2Settings(frame.payload)
                        let ack = self.buildH2Frame(type: Self.h2FrameSettings, flags: Self.h2FlagAck, streamId: 0, payload: Data())
                        self.downloadSend(ack) { _ in }
                        completion(nil)
                    } else {
                        self.processInitialServerFrames(completion: completion)
                    }

                case Self.h2FrameHeaders:
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

    /// Sends DATA frames respecting peer flow control, batched into a single transport write.
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

    /// Sends a packet-up batch as a new HTTP/2 stream: HEADERS + DATA + END_STREAM.
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

        guard sendsBody else {
            lock.unlock()
            // No body frame: empty payload, or payload carried in headers/cookies.
            // Rate limiting between POSTs is handled upstream by flushPacketUpBatch.
            downloadSend(outbound) { [weak self] error in
                if error != nil {
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
                self?.sendH2PacketUpData(data: data, streamId: streamId, offset: nextOffset, maxSize: maxSize, streamWindow: perStreamRemaining) { [weak self] error in
                    if error != nil {
                        self?.markH2Closed()
                    }
                    completion(error)
                }
            } else {
                completion(nil)
            }
        }
    }

    /// Sends packet-up DATA frames with END_STREAM on the last; `streamWindow` is the
    /// per-stream remaining window (not stored globally — packet-up streams are short-lived).
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

    /// Receives DATA from the download stream; frames for other streams are silently consumed.
    func receiveH2Data(completion: @escaping (Data?, Error?) -> Void) {
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

        h2FrameReader.readFrame { [weak self] result in
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
                    // Batch WINDOW_UPDATEs at >= 50% of window consumed (matches Go http2).
                    // Stream-level updates only for the download stream — updating a
                    // possibly-closed upload stream draws RST_STREAM (STREAM_CLOSED).
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
                        // Ignore upload responses regardless of status; a non-200 must not tear down the download.
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
                        // Upload stream resets are expected after the POST completes; ignore.
                        self.receiveH2Data(completion: completion)
                    }

                default:
                    self.receiveH2Data(completion: completion)
                }
            }
        }
    }

    // MARK: Shared-H2 (xmux) session setup & send

    /// Setup over a shared multiplexing H2 connection; mirrors the H3 path but with HPACK headers.
    func performSharedH2Setup(completion: @escaping (Error?) -> Void) {
        guard let shared = sharedH2 else {
            completion(XHTTPError.setupFailed("no shared H2 connection"))
            return
        }
        switch role {
        case .downloadOnly:
            setupSharedH2Download(shared, completion: completion)
        case .uploadOnly:
            // packet-up opens a stream per batch, so only stream-up opens anything at setup.
            if mode == .streamUp {
                openSharedH2Upload(shared, completion: completion)
            } else {
                completion(nil)
            }
        case .combined:
            switch mode {
            case .streamOne:
                // Full-duplex POST on one stream; can't wait for the response (CDN buffering).
                let stream = shared.makeStream()
                lock.lock(); sharedH2Download = stream; lock.unlock()
                xmuxLease?.noteRequest()
                let headers = encodeH2RequestHeaders(method: "POST", includeMeta: false)
                stream.sendHeaders(headers, endStream: false, completion: completion)
            case .streamUp:
                setupSharedH2Download(shared) { [weak self] error in
                    if let error { completion(error); return }
                    guard let self, let shared = self.sharedH2 else { completion(XHTTPError.connectionClosed); return }
                    self.openSharedH2Upload(shared, completion: completion)
                }
            default: // packet-up (and .auto already resolved)
                setupSharedH2Download(shared, completion: completion)
            }
        }
    }

    /// Opens the GET download stream; completes on send (a CDN may withhold the 200 until upload flows).
    private func setupSharedH2Download(_ shared: XHTTPSharedH2Connection, completion: @escaping (Error?) -> Void) {
        let stream = shared.makeStream()
        lock.lock(); sharedH2Download = stream; lock.unlock()
        xmuxLease?.noteRequest()
        let headers = encodeH2RequestHeaders(method: "GET", includeMeta: true)
        stream.sendHeaders(headers, endStream: true, completion: completion)
    }

    /// Opens the persistent stream-up upload POST; its response is drained.
    private func openSharedH2Upload(_ shared: XHTTPSharedH2Connection, completion: @escaping (Error?) -> Void) {
        let stream = shared.makeStream()
        lock.lock(); sharedH2Upload = stream; lock.unlock()
        xmuxLease?.noteRequest()
        let headers = encodeH2UploadHeaders(seq: nil)
        stream.sendHeaders(headers, endStream: false) { [weak self] error in
            if error == nil { self?.sharedH2Upload?.drainResponse() }
            completion(error)
        }
    }

    /// Sends one packet-up batch as its own shared-H2 stream; the response only acks receipt.
    func sendSharedH2PacketUp(data: Data, completion: @escaping (Error?) -> Void) {
        guard let shared = sharedH2 else { completion(XHTTPError.connectionClosed); return }
        lock.lock(); let seq = nextSeq; nextSeq += 1; lock.unlock()
        xmuxLease?.noteRequest()

        // Header/cookie placement carries the payload in the HEADERS block; the body stays empty.
        let dataFields = uplinkDataFields(for: data)
        let bodyInHeaders = !dataFields.isEmpty
        let bodyLength = bodyInHeaders ? 0 : data.count
        let headers = encodeH2UploadHeaders(seq: seq, contentLength: bodyLength, uplinkData: dataFields)
        let stream = shared.makeStream()

        if bodyInHeaders || data.isEmpty {
            stream.sendHeaders(headers, endStream: true) { error in
                if let error { stream.close(); completion(error); return }
                stream.drainResponse()
                completion(nil)
            }
        } else {
            stream.sendHeaders(headers, endStream: false) { error in
                if let error { stream.close(); completion(error); return }
                stream.sendData(data, endStream: true) { sendErr in
                    if let sendErr { stream.close(); completion(sendErr); return }
                    stream.drainResponse()
                    completion(nil)
                }
            }
        }
    }
}
