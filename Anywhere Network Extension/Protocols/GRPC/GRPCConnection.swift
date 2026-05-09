//
//  GRPCConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/23/26.
//

import Foundation

// MARK: - GRPCConnection

/// gRPC transport over HTTP/2.
///
/// Opens a single bidirectional streaming RPC to `/<serviceName>/Tun` (or `/TunMulti`) and
/// tunnels raw bytes as `Hunk` protobuf messages framed with gRPC's 5-byte length prefix.
class GRPCConnection {

    // MARK: Transport closures

    private let transportSend: (Data, @escaping (Error?) -> Void) -> Void
    private let transportReceive: (@escaping (Data?, Bool, Error?) -> Void) -> Void
    private let transportCancel: () -> Void

    // MARK: Configuration

    private let configuration: GRPCConfiguration
    private let authority: String

    // MARK: State

    private let lock = UnfairLock()
    private var _isConnected = false

    /// Stream ID used for the bidirectional gRPC call. Clients must use odd IDs per
    /// RFC 7540 §5.1.1; the first client-initiated stream is always 1.
    private static let streamId: UInt32 = 1

    /// Raw HTTP/2 byte buffer (accumulates transport reads until a full frame is parseable).
    private var h2ReadBuffer = Data()
    /// gRPC message reassembly buffer (accumulates HTTP/2 DATA payloads until a full
    /// length-prefixed gRPC frame is available for decoding).
    private var grpcFrameBuffer = Data()
    /// Decoded app-layer bytes ready for the caller (one receive call may pull multiple
    /// messages off the wire; the remainder stays buffered).
    private var decodedBuffer = Data()

    /// Counts consecutive synchronous frame parses to trampoline every Nth call,
    /// preventing stack overflow on rapid back-to-back parse completions.
    private var h2ReadDepth: Int = 0

    /// Whether the gRPC response HEADERS (status 200) have been validated.
    private var h2ResponseReceived = false
    /// Whether the server has closed its side of the stream (END_STREAM flag on HEADERS or DATA).
    private var h2StreamClosed = false

    /// Peer's flow-control windows (bytes we can still send without another WINDOW_UPDATE).
    private var h2PeerConnectionWindow: Int = 65535
    private var h2PeerStreamSendWindow: Int = 65535
    private var h2PeerInitialWindowSize: Int = 65535

    /// Our local window sizes — both advertised to the peer at setup and used to decide
    /// when to emit WINDOW_UPDATE frames.
    private var h2LocalWindowSize: Int = 4_194_304 // 4 MB

    /// Maximum HTTP/2 frame payload size (SETTINGS_MAX_FRAME_SIZE default, updated by peer).
    private var h2MaxFrameSize: Int = 16384

    /// Bytes received but not yet acknowledged via WINDOW_UPDATE.
    private var h2ConnectionReceiveConsumed: Int = 0
    private var h2StreamReceiveConsumed: Int = 0

    /// Send-side continuations waiting for a WINDOW_UPDATE that re-opens flow control.
    private var h2FlowResumptions: [() -> Void] = []

    /// Keepalive ping timer (nil when idleTimeout == 0).
    private var keepaliveTimer: DispatchSourceTimer?

    /// Safety cap on the raw H2 buffer so a misbehaving peer can't grow memory without bound.
    private static let maxH2ReadBufferSize = 2_097_152 // 2 MB
    /// Safety cap on the gRPC reassembly buffer (individual messages > this are an error).
    private static let maxGRPCFrameBufferSize = 16_777_216 // 16 MB

    var isConnected: Bool {
        lock.lock()
        let v = _isConnected
        lock.unlock()
        return v
    }

    // MARK: - Initializers

    /// Designated initializer. Takes a pre-built ``TransportClosures`` and the resolved
    /// `:authority` value.
    init(transport: TransportClosures, configuration: GRPCConfiguration, authority: String) {
        self.configuration = configuration
        self.authority = authority
        self.transportSend = transport.send
        self.transportReceive = transport.receive
        self.transportCancel = transport.cancel
        self._isConnected = true

        if configuration.initialWindowsSize > 0 {
            self.h2LocalWindowSize = configuration.initialWindowsSize
        }
    }

    /// Creates a gRPC connection over a plain ``RawTCPSocket``.
    convenience init(transport: RawTCPSocket, configuration: GRPCConfiguration, authority: String) {
        self.init(transport: TransportClosures(rawTCP: transport), configuration: configuration, authority: authority)
    }

    /// Creates a gRPC connection over a ``TLSRecordConnection``.
    convenience init(tlsConnection: TLSRecordConnection, configuration: GRPCConfiguration, authority: String) {
        self.init(transport: TransportClosures(tls: tlsConnection), configuration: configuration, authority: authority)
    }

    /// Creates a gRPC connection over a proxy tunnel (for proxy chaining).
    convenience init(tunnel: ProxyConnection, configuration: GRPCConfiguration, authority: String) {
        self.init(transport: TransportClosures(tunnel: tunnel), configuration: configuration, authority: authority)
    }

    // MARK: - Setup

    /// Performs the HTTP/2 connection preface + SETTINGS exchange and opens the bidirectional
    /// gRPC stream.
    ///
    /// HEADERS is sent eagerly without waiting for the server's SETTINGS. The `:status 200`
    /// response may arrive during setup or later — some CDNs defer the response HEADERS
    /// until they see the first client DATA frame, so both orderings are accepted.
    func performSetup(completion: @escaping (Error?) -> Void) {
        var initData = Data()

        // HTTP/2 connection preface (RFC 7540 §3.5).
        initData.append(Self.h2Preface)

        // Client SETTINGS: ENABLE_PUSH=0, INITIAL_WINDOW_SIZE, MAX_HEADER_LIST_SIZE=10MB.
        var settingsPayload = Data()
        settingsPayload.append(contentsOf: [0x00, 0x02, 0x00, 0x00, 0x00, 0x00])
        let winSize = UInt32(h2LocalWindowSize)
        settingsPayload.append(contentsOf: [
            0x00, 0x04,
            UInt8((winSize >> 24) & 0xFF), UInt8((winSize >> 16) & 0xFF),
            UInt8((winSize >> 8) & 0xFF), UInt8(winSize & 0xFF),
        ])
        settingsPayload.append(contentsOf: [0x00, 0x06, 0x00, 0xA0, 0x00, 0x00])
        initData.append(buildH2Frame(type: Self.h2FrameSettings, flags: 0, streamId: 0, payload: settingsPayload))

        // Connection-level WINDOW_UPDATE (1 GB).
        let connWindowInc = Self.h2ConnectionWindowSize
        var wuPayload = Data(count: 4)
        wuPayload[0] = UInt8((connWindowInc >> 24) & 0xFF)
        wuPayload[1] = UInt8((connWindowInc >> 16) & 0xFF)
        wuPayload[2] = UInt8((connWindowInc >> 8) & 0xFF)
        wuPayload[3] = UInt8(connWindowInc & 0xFF)
        initData.append(buildH2Frame(type: Self.h2FrameWindowUpdate, flags: 0, streamId: 0, payload: wuPayload))

        // HEADERS for the bidirectional gRPC stream. END_STREAM is intentionally not set —
        // the client keeps sending DATA frames for the lifetime of the tunnel.
        let headerBlock = encodeGRPCRequestHeaders()
        initData.append(buildH2Frame(
            type: Self.h2FrameHeaders,
            flags: Self.h2FlagEndHeaders,
            streamId: Self.streamId,
            payload: headerBlock
        ))

        transportSend(initData) { [weak self] error in
            if let error {
                completion(GRPCError.setupFailed("H2 preface/HEADERS write failed: \(error.localizedDescription)"))
                return
            }
            self?.processInitialServerFrames(completion: completion)
        }
    }

    /// Reads frames until the server's SETTINGS is received and ACKed.
    ///
    /// Also handles WINDOW_UPDATE and PING frames during setup, and absorbs an early
    /// response HEADERS if one arrives before SETTINGS. Setup completes as soon as the
    /// server's SETTINGS is seen; the response body may arrive later.
    private func processInitialServerFrames(completion: @escaping (Error?) -> Void) {
        readH2Frame { [weak self] result in
            guard let self else {
                completion(GRPCError.connectionClosed)
                return
            }
            switch result {
            case .failure(let error):
                completion(GRPCError.setupFailed("H2 setup read failed: \(error.localizedDescription)"))

            case .success(let frame):
                switch frame.type {
                case Self.h2FrameSettings:
                    if frame.flags & Self.h2FlagAck == 0 {
                        self.parseH2Settings(frame.payload)
                        let ack = self.buildH2Frame(type: Self.h2FrameSettings, flags: Self.h2FlagAck, streamId: 0, payload: Data())
                        self.transportSend(ack) { _ in }
                        self.startKeepaliveIfNeeded()
                        completion(nil)
                    } else {
                        // ACK for our own SETTINGS; keep reading for the server's.
                        self.processInitialServerFrames(completion: completion)
                    }

                case Self.h2FrameHeaders:
                    if frame.streamId == Self.streamId {
                        if let rejection = self.checkH2ResponseStatus(frame.payload) {
                            completion(GRPCError.setupFailed("gRPC response rejected: \(rejection)"))
                            return
                        }
                        // Trailers-only response (END_STREAM on the first HEADERS) with
                        // `:status 200` — HTTP succeeded but the gRPC call itself failed.
                        if frame.flags & Self.h2FlagEndStream != 0 {
                            if let grpcError = Self.parseGRPCTrailer(frame.payload) {
                                self.lock.lock()
                                self.h2StreamClosed = true
                                self.lock.unlock()
                                completion(GRPCError.setupFailed(grpcError.localizedDescription))
                                return
                            }
                        }
                        self.lock.lock()
                        self.h2ResponseReceived = true
                        self.lock.unlock()
                    }
                    self.startKeepaliveIfNeeded()
                    completion(nil)

                case Self.h2FrameWindowUpdate:
                    self.handleWindowUpdate(frame: frame)
                    self.processInitialServerFrames(completion: completion)

                case Self.h2FramePing:
                    if frame.flags & Self.h2FlagAck == 0 {
                        let pong = self.buildH2Frame(type: Self.h2FramePing, flags: Self.h2FlagAck, streamId: 0, payload: frame.payload)
                        self.transportSend(pong) { _ in }
                    }
                    self.processInitialServerFrames(completion: completion)

                case Self.h2FrameGoaway:
                    let reason = Self.describeGoawayPayload(frame.payload)
                    completion(GRPCError.setupFailed("Server sent GOAWAY during setup (\(reason))"))

                case Self.h2FrameRstStream:
                    if frame.streamId == Self.streamId {
                        let reason = Self.describeRstStreamPayload(frame.payload)
                        completion(GRPCError.setupFailed("Server reset the stream during setup (\(reason))"))
                        return
                    }
                    self.processInitialServerFrames(completion: completion)

                default:
                    self.processInitialServerFrames(completion: completion)
                }
            }
        }
    }

    // MARK: - Public send / receive

    /// Sends a raw byte chunk as one gRPC `Hunk` message on the open stream.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        let message = Self.encodeHunk(data)
        let framed = Self.wrapGRPCMessage(message)
        sendH2Data(data: framed, offset: 0, completion: completion)
    }

    /// Fire-and-forget send.
    func send(data: Data) {
        send(data: data) { _ in }
    }

    /// Reads the next application payload, decoding gRPC / protobuf framing as needed.
    ///
    /// Returns `nil` on stream EOF. One call to `receive` may trigger multiple HTTP/2
    /// frame reads behind the scenes, and may return less than one gRPC message worth of
    /// bytes when decoded data has been pre-buffered from a previous read.
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        if !decodedBuffer.isEmpty {
            let out = decodedBuffer
            decodedBuffer.removeAll(keepingCapacity: true)
            lock.unlock()
            completion(out, nil)
            return
        }
        if h2StreamClosed {
            lock.unlock()
            completion(nil, nil)
            return
        }
        lock.unlock()

        readAndDecode(completion: completion)
    }

    // MARK: - Cancel

    func cancel() {
        lock.lock()
        _isConnected = false
        h2StreamClosed = true
        h2ReadBuffer.removeAll()
        grpcFrameBuffer.removeAll()
        decodedBuffer.removeAll()
        keepaliveTimer?.cancel()
        keepaliveTimer = nil
        let waiters = h2FlowResumptions
        h2FlowResumptions.removeAll()
        lock.unlock()
        for r in waiters { r() }
        transportCancel()
    }
}

// MARK: - HTTP/2 constants

extension GRPCConnection {

    /// HTTP/2 connection preface (RFC 7540 §3.5).
    static let h2Preface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    /// HTTP/2 frame header size.
    static let h2FrameHeaderSize = 9

    static let h2FrameData: UInt8 = 0x00
    static let h2FrameHeaders: UInt8 = 0x01
    static let h2FrameRstStream: UInt8 = 0x03
    static let h2FrameSettings: UInt8 = 0x04
    static let h2FramePing: UInt8 = 0x06
    static let h2FrameGoaway: UInt8 = 0x07
    static let h2FrameWindowUpdate: UInt8 = 0x08

    static let h2FlagEndStream: UInt8 = 0x01
    static let h2FlagEndHeaders: UInt8 = 0x04
    static let h2FlagAck: UInt8 = 0x01

    static let h2ConnectionWindowSize: UInt32 = 1_073_741_824 // 1 GB
}

// MARK: - Frame I/O

extension GRPCConnection {

    /// Builds an HTTP/2 frame per RFC 7540 §4.1.
    fileprivate func buildH2Frame(type: UInt8, flags: UInt8, streamId: UInt32, payload: Data) -> Data {
        var frame = Data(capacity: Self.h2FrameHeaderSize + payload.count)
        let len = UInt32(payload.count)
        frame.append(UInt8((len >> 16) & 0xFF))
        frame.append(UInt8((len >> 8) & 0xFF))
        frame.append(UInt8(len & 0xFF))
        frame.append(type)
        frame.append(flags)
        let sid = streamId & 0x7FFFFFFF
        frame.append(UInt8((sid >> 24) & 0xFF))
        frame.append(UInt8((sid >> 16) & 0xFF))
        frame.append(UInt8((sid >> 8) & 0xFF))
        frame.append(UInt8(sid & 0xFF))
        frame.append(payload)
        return frame
    }

    /// Attempts to parse one complete frame from `h2ReadBuffer`. Returns nil if the
    /// buffer doesn't yet contain a full frame. Caller must hold `lock`.
    private func parseH2FrameLocked() -> (type: UInt8, flags: UInt8, streamId: UInt32, payload: Data)? {
        guard h2ReadBuffer.count >= Self.h2FrameHeaderSize else { return nil }

        let b = h2ReadBuffer
        let length = (UInt32(b[b.startIndex]) << 16)
            | (UInt32(b[b.startIndex + 1]) << 8)
            | UInt32(b[b.startIndex + 2])
        let type = b[b.startIndex + 3]
        let flags = b[b.startIndex + 4]
        let streamId = (UInt32(b[b.startIndex + 5]) << 24)
            | (UInt32(b[b.startIndex + 6]) << 16)
            | (UInt32(b[b.startIndex + 7]) << 8)
            | UInt32(b[b.startIndex + 8])
        let sid = streamId & 0x7FFFFFFF

        let totalSize = Self.h2FrameHeaderSize + Int(length)
        guard h2ReadBuffer.count >= totalSize else { return nil }

        let payload = h2ReadBuffer.subdata(
            in: h2ReadBuffer.startIndex + Self.h2FrameHeaderSize ..< h2ReadBuffer.startIndex + totalSize
        )
        h2ReadBuffer.removeFirst(totalSize)
        if h2ReadBuffer.isEmpty {
            h2ReadBuffer = Data()
        } else {
            h2ReadBuffer = Data(h2ReadBuffer)
        }

        return (type, flags, sid, payload)
    }

    /// Reads transport data until at least one complete H2 frame is available, then returns it.
    fileprivate func readH2Frame(
        completion: @escaping (Result<(type: UInt8, flags: UInt8, streamId: UInt32, payload: Data), Error>) -> Void
    ) {
        lock.lock()
        if let frame = parseH2FrameLocked() {
            h2ReadDepth += 1
            let needsTrampoline = h2ReadDepth >= 16
            if needsTrampoline { h2ReadDepth = 0 }
            lock.unlock()
            if needsTrampoline {
                DispatchQueue.global().async { completion(.success(frame)) }
            } else {
                completion(.success(frame))
            }
            return
        }
        h2ReadDepth = 0
        lock.unlock()

        transportReceive { [weak self] data, _, error in
            guard let self else {
                completion(.failure(GRPCError.connectionClosed))
                return
            }
            if let error {
                completion(.failure(error))
                return
            }
            guard let data, !data.isEmpty else {
                completion(.failure(GRPCError.connectionClosed))
                return
            }

            self.lock.lock()
            self.h2ReadBuffer.append(data)
            if self.h2ReadBuffer.count > Self.maxH2ReadBufferSize {
                self.h2ReadBuffer.removeAll()
                self.lock.unlock()
                completion(.failure(GRPCError.connectionClosed))
                return
            }
            self.lock.unlock()

            self.readH2Frame(completion: completion)
        }
    }

    /// Parses a server SETTINGS payload and applies INITIAL_WINDOW_SIZE / MAX_FRAME_SIZE.
    fileprivate func parseH2Settings(_ payload: Data) {
        var offset = payload.startIndex
        while offset + 6 <= payload.endIndex {
            let id = (UInt16(payload[offset]) << 8) | UInt16(payload[offset + 1])
            let value = (UInt32(payload[offset + 2]) << 24)
                | (UInt32(payload[offset + 3]) << 16)
                | (UInt32(payload[offset + 4]) << 8)
                | UInt32(payload[offset + 5])
            offset += 6

            switch id {
            case 0x04: // INITIAL_WINDOW_SIZE — adjusts only stream windows (RFC 7540 §6.9.2).
                lock.lock()
                let delta = Int(value) - h2PeerInitialWindowSize
                h2PeerInitialWindowSize = Int(value)
                h2PeerStreamSendWindow += delta
                lock.unlock()
            case 0x05: // MAX_FRAME_SIZE
                lock.lock()
                h2MaxFrameSize = Int(value)
                lock.unlock()
            default:
                break
            }
        }
    }

    /// Updates our send-side view of the peer's flow-control windows. Wakes any sends
    /// that were blocked waiting for the window to re-open.
    fileprivate func handleWindowUpdate(frame: (type: UInt8, flags: UInt8, streamId: UInt32, payload: Data)) {
        lock.lock()
        if frame.payload.count >= 4 {
            let raw = frame.payload.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
            let increment = Int(raw & 0x7FFFFFFF)
            if frame.streamId == 0 {
                h2PeerConnectionWindow += increment
            } else if frame.streamId == Self.streamId {
                h2PeerStreamSendWindow += increment
            }
        }
        let resumptions = h2FlowResumptions
        h2FlowResumptions.removeAll()
        lock.unlock()
        for r in resumptions { r() }
    }
}

// MARK: - HPACK encoding for request HEADERS

extension GRPCConnection {

    /// Encodes the HEADERS block for the outgoing gRPC request.
    ///
    /// Uses HPACK static-table indexing where possible and literal-with-incremental-indexing
    /// for the remaining fields. Strings are emitted without Huffman compression.
    fileprivate func encodeGRPCRequestHeaders() -> Data {
        var block = Data()

        // Pseudo-header order required by RFC 7540 §8.1.2.1: :authority, :method, :path, :scheme.

        // :authority — literal w/ incremental indexing, static-table name index 1.
        var authBytes = Self.hpackEncodeInteger(1, prefixBits: 6)
        authBytes[0] |= 0x40
        block.append(contentsOf: authBytes)
        block.append(contentsOf: Self.hpackEncodeString(authority))

        // :method POST — static-table entry 3.
        block.append(0x83)

        // :path — literal w/ incremental indexing, static-table name index 4.
        let path = configuration.resolvedPath()
        var pathBytes = Self.hpackEncodeInteger(4, prefixBits: 6)
        pathBytes[0] |= 0x40
        block.append(contentsOf: pathBytes)
        block.append(contentsOf: Self.hpackEncodeString(path))

        // :scheme https — static-table entry 7.
        block.append(0x87)

        // content-type: application/grpc — literal w/ incremental indexing, name index 31.
        var ctBytes = Self.hpackEncodeInteger(31, prefixBits: 6)
        ctBytes[0] |= 0x40
        block.append(contentsOf: ctBytes)
        block.append(contentsOf: Self.hpackEncodeString("application/grpc"))

        // `te: trailers` is required by the gRPC protocol spec; servers reject requests
        // that omit it.
        block.append(0x40)
        block.append(contentsOf: Self.hpackEncodeString("te"))
        block.append(contentsOf: Self.hpackEncodeString("trailers"))

        // grpc-encoding: identity — outgoing messages are not compressed.
        block.append(0x40)
        block.append(contentsOf: Self.hpackEncodeString("grpc-encoding"))
        block.append(contentsOf: Self.hpackEncodeString("identity"))

        // grpc-accept-encoding: identity — only identity encoding is decodable here.
        block.append(0x40)
        block.append(contentsOf: Self.hpackEncodeString("grpc-accept-encoding"))
        block.append(contentsOf: Self.hpackEncodeString("identity"))

        // user-agent — literal w/ incremental indexing, static-table name index 58.
        let ua = configuration.userAgent.isEmpty ? defaultUserAgent : configuration.userAgent
        var uaBytes = Self.hpackEncodeInteger(58, prefixBits: 6)
        uaBytes[0] |= 0x40
        block.append(contentsOf: uaBytes)
        block.append(contentsOf: Self.hpackEncodeString(ua))

        return block
    }

    /// HPACK integer encoding (RFC 7541 §5.1).
    fileprivate static func hpackEncodeInteger(_ value: Int, prefixBits: Int) -> [UInt8] {
        let maxPrefix = (1 << prefixBits) - 1
        if value < maxPrefix {
            return [UInt8(value)]
        }
        var bytes: [UInt8] = [UInt8(maxPrefix)]
        var remaining = value - maxPrefix
        while remaining >= 128 {
            bytes.append(UInt8(remaining & 0x7F) | 0x80)
            remaining >>= 7
        }
        bytes.append(UInt8(remaining))
        return bytes
    }

    /// HPACK string encoding — plain bytes, no Huffman (RFC 7541 §5.2).
    fileprivate static func hpackEncodeString(_ string: String) -> [UInt8] {
        let bytes = Array(string.utf8)
        var result = hpackEncodeInteger(bytes.count, prefixBits: 7)
        result[0] &= 0x7F
        result.append(contentsOf: bytes)
        return result
    }
}

// MARK: - HPACK decoding for response :status

extension GRPCConnection {

    /// Returns `nil` if the HEADERS block's `:status` is `200`, or a short error string
    /// describing the response otherwise.
    ///
    /// Handles both Huffman and non-Huffman literal values and skips leading HPACK
    /// dynamic-table-size updates (which servers may emit after a SETTINGS change).
    fileprivate func checkH2ResponseStatus(_ headerBlock: Data) -> String? {
        guard !headerBlock.isEmpty else { return "empty header block" }

        var offset = headerBlock.startIndex
        // Skip HPACK dynamic-table-size updates (prefix 001xxxxx, RFC 7541 §6.3).
        while offset < headerBlock.endIndex, headerBlock[offset] & 0xE0 == 0x20 {
            let initial = headerBlock[offset] & 0x1F
            offset += 1
            if initial == 0x1F {
                while offset < headerBlock.endIndex, headerBlock[offset] & 0x80 != 0 {
                    offset += 1
                }
                offset += 1
            }
        }
        guard offset < headerBlock.endIndex else { return "empty header block (only table-size updates)" }

        let first = headerBlock[offset]
        let remaining = headerBlock[offset...]

        // Indexed representation (top bit set): 0x88=200, others are error codes.
        if first & 0x80 != 0 {
            if first == 0x88 { return nil }
            let indexedStatus: [UInt8: String] = [
                0x89: "204", 0x8a: "206", 0x8b: "304",
                0x8c: "400", 0x8d: "404", 0x8e: "500",
            ]
            if let status = indexedStatus[first] { return "status \(status)" }
            return "status (indexed \(first & 0x7F))"
        }

        // Literal :status — static table indices 8-14 all have name ":status".
        let nameIndex: UInt8
        if first & 0xF0 == 0x00 {
            nameIndex = first & 0x0F
        } else if first & 0xF0 == 0x10 {
            nameIndex = first & 0x0F
        } else if first & 0xC0 == 0x40 {
            nameIndex = first & 0x3F
        } else {
            return "unknown header representation"
        }

        guard (8...14).contains(nameIndex), remaining.count >= 2 else {
            return "unknown :status header"
        }

        let valueMeta = remaining[remaining.startIndex + 1]
        let isHuffman = (valueMeta & 0x80) != 0
        let valueLen = Int(valueMeta & 0x7F)
        let valueStart = remaining.startIndex + 2

        guard remaining.count >= 2 + valueLen, valueLen > 0 else { return "status (?)" }

        let valueData = Data(remaining[valueStart..<(valueStart + valueLen)])
        if !isHuffman {
            let status = String(data: valueData, encoding: .ascii) ?? "?"
            return status == "200" ? nil : "status \(status)"
        }
        let status = Self.huffmanDecodeDigits(valueData)
        if status.isEmpty { return "status (huffman)" }
        return status == "200" ? nil : "status \(status)"
    }

    /// Decodes a Huffman-encoded ASCII digit-only value (used for HTTP status codes).
    /// RFC 7541 Appendix B: '0'..'2' are 5-bit codes, '3'..'9' are 6-bit codes.
    private static func huffmanDecodeDigits(_ data: Data) -> String {
        var result = ""
        var bits: UInt32 = 0
        var numBits = 0
        for byte in data {
            bits = (bits << 8) | UInt32(byte)
            numBits += 8
        }
        while numBits >= 5 {
            let top5 = Int((bits >> (numBits - 5)) & 0x1F)
            if top5 <= 0x02 {
                result.append(Character(UnicodeScalar(48 + top5)!))
                numBits -= 5
                continue
            }
            guard numBits >= 6 else { break }
            let top6 = Int((bits >> (numBits - 6)) & 0x3F)
            if top6 >= 0x19 && top6 <= 0x1F {
                let digit = top6 - 0x19 + 3
                result.append(Character(UnicodeScalar(48 + digit)!))
                numBits -= 6
                continue
            }
            break
        }
        return result
    }
}

// MARK: - gRPC / protobuf framing

extension GRPCConnection {

    /// Encodes a `Hunk` protobuf message with `bytes data = 1`.
    /// Wire format: `0x0A <varint length> <bytes>`.
    fileprivate static func encodeHunk(_ data: Data) -> Data {
        var out = Data(capacity: 1 + 10 + data.count)
        out.append(0x0A) // (field 1 << 3) | wire type 2 (length-delimited)
        out.append(varintEncode(UInt64(data.count)))
        out.append(data)
        return out
    }

    /// Wraps a serialized protobuf message in the 5-byte gRPC length prefix:
    /// `[compressed=0][big-endian uint32 length][message]`.
    fileprivate static func wrapGRPCMessage(_ message: Data) -> Data {
        var out = Data(capacity: 5 + message.count)
        out.append(0x00) // No compression.
        let len = UInt32(message.count)
        out.append(UInt8((len >> 24) & 0xFF))
        out.append(UInt8((len >> 16) & 0xFF))
        out.append(UInt8((len >> 8) & 0xFF))
        out.append(UInt8(len & 0xFF))
        out.append(message)
        return out
    }

    /// Protobuf varint encoder.
    private static func varintEncode(_ value: UInt64) -> Data {
        var out = Data()
        var v = value
        while v >= 0x80 {
            out.append(UInt8((v & 0x7F) | 0x80))
            v >>= 7
        }
        out.append(UInt8(v))
        return out
    }

    /// Protobuf varint decoder. Returns `(value, bytesConsumed)` or `nil` if truncated.
    fileprivate static func varintDecode(_ data: Data, at startOffset: Int) -> (value: UInt64, consumed: Int)? {
        var value: UInt64 = 0
        var shift: UInt64 = 0
        var offset = startOffset
        while offset < data.count {
            let b = data[data.startIndex + offset]
            value |= UInt64(b & 0x7F) << shift
            offset += 1
            if b & 0x80 == 0 {
                return (value, offset - startOffset)
            }
            shift += 7
            if shift >= 64 { return nil }
        }
        return nil
    }

    /// Decodes a `Hunk` or `MultiHunk` protobuf message into concatenated raw bytes.
    ///
    /// Both messages define `data` as field 1 (wire type 2). `Hunk` has one `bytes` field,
    /// `MultiHunk` has `repeated bytes` — on the wire these look identical for a single-element
    /// MultiHunk. Any field 1 occurrence is appended; everything else (unknown fields) is
    /// skipped per proto3 forward-compat conventions.
    fileprivate static func decodeHunkPayload(_ message: Data) throws -> Data {
        var out = Data()
        var offset = 0
        while offset < message.count {
            guard let (tag, tagConsumed) = varintDecode(message, at: offset) else {
                throw GRPCError.invalidResponse("truncated protobuf tag")
            }
            offset += tagConsumed
            let fieldNumber = Int(tag >> 3)
            let wireType = Int(tag & 0x07)

            switch wireType {
            case 2: // length-delimited
                guard let (length, lenConsumed) = varintDecode(message, at: offset) else {
                    throw GRPCError.invalidResponse("truncated protobuf length")
                }
                offset += lenConsumed
                let lenInt = Int(length)
                guard offset + lenInt <= message.count else {
                    throw GRPCError.invalidResponse("truncated protobuf value")
                }
                if fieldNumber == 1 {
                    out.append(message.subdata(in: message.startIndex + offset ..< message.startIndex + offset + lenInt))
                }
                offset += lenInt
            case 0: // varint — skip
                guard let (_, vConsumed) = varintDecode(message, at: offset) else {
                    throw GRPCError.invalidResponse("truncated varint field")
                }
                offset += vConsumed
            case 5: // fixed32 — skip
                guard offset + 4 <= message.count else {
                    throw GRPCError.invalidResponse("truncated fixed32 field")
                }
                offset += 4
            case 1: // fixed64 — skip
                guard offset + 8 <= message.count else {
                    throw GRPCError.invalidResponse("truncated fixed64 field")
                }
                offset += 8
            default:
                throw GRPCError.invalidResponse("unknown protobuf wire type \(wireType)")
            }
        }
        return out
    }
}

// MARK: - HTTP/2 DATA send (respects flow control)

extension GRPCConnection {

    /// Sends `data` as one or more HTTP/2 DATA frames on the gRPC stream, batching as many
    /// frames as the peer's current flow-control window allows into a single transport
    /// write. If the window fills, the remainder waits for a WINDOW_UPDATE before resuming.
    fileprivate func sendH2Data(data: Data, offset: Int, completion: @escaping (Error?) -> Void) {
        guard offset < data.count else {
            completion(nil)
            return
        }

        lock.lock()
        if h2StreamClosed {
            lock.unlock()
            completion(GRPCError.connectionClosed)
            return
        }
        let maxSize = h2MaxFrameSize
        let window = min(h2PeerConnectionWindow, h2PeerStreamSendWindow)

        guard window > 0 else {
            h2FlowResumptions.append { [weak self] in
                self?.sendH2Data(data: data, offset: offset, completion: completion)
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
            frames.append(buildH2Frame(type: Self.h2FrameData, flags: 0, streamId: Self.streamId, payload: chunk))
            currentOffset += chunkSize
            windowRemaining -= chunkSize
        }
        let totalSent = window - windowRemaining
        h2PeerConnectionWindow -= totalSent
        h2PeerStreamSendWindow -= totalSent
        lock.unlock()

        let nextOffset = currentOffset
        transportSend(frames) { [weak self] error in
            if let error {
                self?.markClosed()
                completion(error)
                return
            }
            if nextOffset < data.count {
                self?.sendH2Data(data: data, offset: nextOffset, completion: completion)
            } else {
                completion(nil)
            }
        }
    }

    private func markClosed() {
        lock.lock()
        h2StreamClosed = true
        lock.unlock()
    }
}

// MARK: - Receive pipeline

extension GRPCConnection {

    /// Pulls H2 frames until at least one application payload is ready, then invokes
    /// `completion`. Stream/connection management frames (SETTINGS, WINDOW_UPDATE, PING,
    /// GOAWAY, RST_STREAM, trailer HEADERS) are handled inline.
    fileprivate func readAndDecode(completion: @escaping (Data?, Error?) -> Void) {
        readH2Frame { [weak self] result in
            guard let self else {
                completion(nil, GRPCError.connectionClosed)
                return
            }
            switch result {
            case .failure(let error):
                completion(nil, error)

            case .success(let frame):
                let isOurStream = frame.streamId == Self.streamId

                switch frame.type {
                case Self.h2FrameData:
                    self.handleDataFrame(frame: frame, isOurStream: isOurStream, completion: completion)

                case Self.h2FrameHeaders:
                    // Could be the initial 200 OK response or the terminal trailer HEADERS.
                    if isOurStream {
                        let endOfStream = (frame.flags & Self.h2FlagEndStream) != 0
                        if !self.markResponseReceivedIfNeeded(frame.payload, completion: completion) {
                            return
                        }
                        if endOfStream {
                            // Trailer HEADERS end the stream. A non-zero grpc-status means
                            // the gRPC call itself failed and we surface it as an error
                            // rather than a silent EOF.
                            let grpcError = Self.parseGRPCTrailer(frame.payload)
                            self.lock.lock()
                            self.h2StreamClosed = true
                            let leftover = self.decodedBuffer
                            self.decodedBuffer.removeAll(keepingCapacity: true)
                            self.lock.unlock()
                            if let grpcError {
                                completion(nil, grpcError)
                            } else if leftover.isEmpty {
                                completion(nil, nil)
                            } else {
                                completion(leftover, nil)
                            }
                            return
                        }
                    }
                    self.readAndDecode(completion: completion)

                case Self.h2FrameSettings:
                    if frame.flags & Self.h2FlagAck == 0 {
                        self.parseH2Settings(frame.payload)
                        let ack = self.buildH2Frame(type: Self.h2FrameSettings, flags: Self.h2FlagAck, streamId: 0, payload: Data())
                        self.transportSend(ack) { _ in }
                    }
                    self.readAndDecode(completion: completion)

                case Self.h2FrameWindowUpdate:
                    self.handleWindowUpdate(frame: frame)
                    self.readAndDecode(completion: completion)

                case Self.h2FramePing:
                    if frame.flags & Self.h2FlagAck == 0 {
                        let pong = self.buildH2Frame(type: Self.h2FramePing, flags: Self.h2FlagAck, streamId: 0, payload: frame.payload)
                        self.transportSend(pong) { _ in }
                    }
                    self.readAndDecode(completion: completion)

                case Self.h2FrameGoaway:
                    self.lock.lock()
                    self.h2StreamClosed = true
                    let leftover = self.decodedBuffer
                    self.decodedBuffer.removeAll(keepingCapacity: true)
                    self.lock.unlock()
                    if leftover.isEmpty {
                        completion(nil, nil)
                    } else {
                        completion(leftover, nil)
                    }

                case Self.h2FrameRstStream:
                    if isOurStream {
                        self.lock.lock()
                        self.h2StreamClosed = true
                        let leftover = self.decodedBuffer
                        self.decodedBuffer.removeAll(keepingCapacity: true)
                        self.lock.unlock()
                        if leftover.isEmpty {
                            completion(nil, nil)
                        } else {
                            completion(leftover, nil)
                        }
                    } else {
                        self.readAndDecode(completion: completion)
                    }

                default:
                    self.readAndDecode(completion: completion)
                }
            }
        }
    }

    /// Validates the first HEADERS frame on our stream. Returns `true` if decode should
    /// continue, `false` if an error was already delivered to `completion`.
    private func markResponseReceivedIfNeeded(_ payload: Data, completion: @escaping (Data?, Error?) -> Void) -> Bool {
        lock.lock()
        if h2ResponseReceived {
            lock.unlock()
            return true
        }
        lock.unlock()

        if let rejection = checkH2ResponseStatus(payload) {
            lock.lock()
            h2StreamClosed = true
            lock.unlock()
            completion(nil, GRPCError.invalidResponse("gRPC response rejected: \(rejection)"))
            return false
        }
        lock.lock()
        h2ResponseReceived = true
        lock.unlock()
        return true
    }

    /// Appends an incoming DATA frame's payload to the gRPC reassembly buffer, extracts
    /// all complete gRPC messages, decodes their Hunk payloads, and surfaces the resulting
    /// bytes to the caller. Emits a WINDOW_UPDATE when half the local window has been consumed.
    private func handleDataFrame(
        frame: (type: UInt8, flags: UInt8, streamId: UInt32, payload: Data),
        isOurStream: Bool,
        completion: @escaping (Data?, Error?) -> Void
    ) {
        let endOfStream = (frame.flags & Self.h2FlagEndStream) != 0

        // Always ack received bytes with WINDOW_UPDATEs — even for unexpected streams
        // — so the connection window stays open.
        emitWindowUpdatesIfNeeded(receivedBytes: frame.payload.count, onOurStream: isOurStream)

        guard isOurStream else {
            readAndDecode(completion: completion)
            return
        }

        var decoded = Data()
        var streamClosed = false
        var decodeError: Error?

        lock.lock()
        if !frame.payload.isEmpty {
            grpcFrameBuffer.append(frame.payload)
            if grpcFrameBuffer.count > Self.maxGRPCFrameBufferSize {
                grpcFrameBuffer.removeAll()
                lock.unlock()
                completion(nil, GRPCError.invalidResponse("gRPC frame buffer overflow"))
                return
            }
        }

        // Extract as many complete gRPC messages as the buffer allows.
        while grpcFrameBuffer.count >= 5 {
            let compressed = grpcFrameBuffer[grpcFrameBuffer.startIndex]
            let length = (UInt32(grpcFrameBuffer[grpcFrameBuffer.startIndex + 1]) << 24)
                | (UInt32(grpcFrameBuffer[grpcFrameBuffer.startIndex + 2]) << 16)
                | (UInt32(grpcFrameBuffer[grpcFrameBuffer.startIndex + 3]) << 8)
                | UInt32(grpcFrameBuffer[grpcFrameBuffer.startIndex + 4])
            let total = 5 + Int(length)
            guard grpcFrameBuffer.count >= total else { break }

            let messageData = grpcFrameBuffer.subdata(
                in: grpcFrameBuffer.startIndex + 5 ..< grpcFrameBuffer.startIndex + total
            )
            grpcFrameBuffer.removeFirst(total)
            if grpcFrameBuffer.isEmpty {
                grpcFrameBuffer = Data()
            } else {
                grpcFrameBuffer = Data(grpcFrameBuffer)
            }

            if compressed != 0 {
                decodeError = GRPCError.compressedMessageUnsupported
                break
            }
            do {
                let payload = try Self.decodeHunkPayload(messageData)
                if !payload.isEmpty {
                    decoded.append(payload)
                }
            } catch {
                decodeError = error
                break
            }
        }

        if endOfStream {
            h2StreamClosed = true
            streamClosed = true
        }
        lock.unlock()

        if let decodeError {
            completion(nil, decodeError)
            return
        }

        if decoded.isEmpty {
            if streamClosed {
                completion(nil, nil)
            } else {
                // No complete message yet; keep reading.
                readAndDecode(completion: completion)
            }
            return
        }

        completion(decoded, nil)
    }

    /// Emits connection- and stream-level WINDOW_UPDATE frames once at least half of the
    /// local window has been consumed, to batch flow-control updates.
    private func emitWindowUpdatesIfNeeded(receivedBytes: Int, onOurStream: Bool) {
        guard receivedBytes > 0 else { return }

        lock.lock()
        h2ConnectionReceiveConsumed += receivedBytes
        if onOurStream {
            h2StreamReceiveConsumed += receivedBytes
        }
        let windowSize = h2LocalWindowSize
        let threshold = windowSize / 2
        let connConsumed = h2ConnectionReceiveConsumed
        let streamConsumed = h2StreamReceiveConsumed
        if connConsumed >= threshold { h2ConnectionReceiveConsumed = 0 }
        if onOurStream, streamConsumed >= threshold { h2StreamReceiveConsumed = 0 }
        lock.unlock()

        var updates = Data()
        if connConsumed >= threshold {
            let inc = UInt32(connConsumed)
            var p = Data(count: 4)
            p[0] = UInt8((inc >> 24) & 0xFF); p[1] = UInt8((inc >> 16) & 0xFF)
            p[2] = UInt8((inc >> 8) & 0xFF); p[3] = UInt8(inc & 0xFF)
            updates.append(buildH2Frame(type: Self.h2FrameWindowUpdate, flags: 0, streamId: 0, payload: p))
        }
        if onOurStream, streamConsumed >= threshold {
            let inc = UInt32(streamConsumed)
            var p = Data(count: 4)
            p[0] = UInt8((inc >> 24) & 0xFF); p[1] = UInt8((inc >> 16) & 0xFF)
            p[2] = UInt8((inc >> 8) & 0xFF); p[3] = UInt8(inc & 0xFF)
            updates.append(buildH2Frame(type: Self.h2FrameWindowUpdate, flags: 0, streamId: Self.streamId, payload: p))
        }
        if !updates.isEmpty {
            transportSend(updates) { _ in }
        }
    }
}

// MARK: - Keepalive

extension GRPCConnection {

    /// Starts a periodic PING timer when `idleTimeout` is non-zero, keeping the tunnel
    /// alive while the proxied app is idle.
    fileprivate func startKeepaliveIfNeeded() {
        let interval = configuration.idleTimeout
        guard interval > 0 else { return }

        lock.lock()
        if keepaliveTimer != nil {
            lock.unlock()
            return
        }
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global())
        timer.schedule(deadline: .now() + .seconds(interval), repeating: .seconds(interval))
        timer.setEventHandler { [weak self] in
            self?.sendKeepalivePing()
        }
        keepaliveTimer = timer
        lock.unlock()
        timer.resume()
    }

    private func sendKeepalivePing() {
        lock.lock()
        if h2StreamClosed {
            lock.unlock()
            return
        }
        lock.unlock()
        // 8-byte opaque PING payload (RFC 7540 §6.7).
        let payload = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        let ping = buildH2Frame(type: Self.h2FramePing, flags: 0, streamId: 0, payload: payload)
        transportSend(ping) { _ in }
    }
}

// MARK: - Error-code descriptions

extension GRPCConnection {

    /// Human-readable HTTP/2 error code (RFC 7540 §7).
    fileprivate static func h2ErrorCodeName(_ code: UInt32) -> String {
        switch code {
        case 0x00: return "NO_ERROR"
        case 0x01: return "PROTOCOL_ERROR"
        case 0x02: return "INTERNAL_ERROR"
        case 0x03: return "FLOW_CONTROL_ERROR"
        case 0x04: return "SETTINGS_TIMEOUT"
        case 0x05: return "STREAM_CLOSED"
        case 0x06: return "FRAME_SIZE_ERROR"
        case 0x07: return "REFUSED_STREAM"
        case 0x08: return "CANCEL"
        case 0x09: return "COMPRESSION_ERROR"
        case 0x0A: return "CONNECT_ERROR"
        case 0x0B: return "ENHANCE_YOUR_CALM"
        case 0x0C: return "INADEQUATE_SECURITY"
        case 0x0D: return "HTTP_1_1_REQUIRED"
        default:   return "UNKNOWN(\(code))"
        }
    }

    /// Parses the HTTP/2 GOAWAY payload (RFC 7540 §6.8): 4-byte last-stream-id, 4-byte
    /// error code, optional additional debug data. Returns a short human description.
    fileprivate static func describeGoawayPayload(_ payload: Data) -> String {
        guard payload.count >= 8 else { return "truncated GOAWAY payload" }
        let base = payload.startIndex
        let lastStreamId = (UInt32(payload[base]) << 24)
            | (UInt32(payload[base + 1]) << 16)
            | (UInt32(payload[base + 2]) << 8)
            | UInt32(payload[base + 3])
        let errorCode = (UInt32(payload[base + 4]) << 24)
            | (UInt32(payload[base + 5]) << 16)
            | (UInt32(payload[base + 6]) << 8)
            | UInt32(payload[base + 7])
        let name = h2ErrorCodeName(errorCode)
        let debug: String
        if payload.count > 8, let ascii = String(data: payload.subdata(in: base + 8 ..< payload.endIndex), encoding: .utf8) {
            debug = ", debug=\(ascii)"
        } else {
            debug = ""
        }
        return "\(name), lastStreamId=\(lastStreamId & 0x7FFFFFFF)\(debug)"
    }

    /// Parses an RST_STREAM payload (RFC 7540 §6.4): 4-byte error code.
    fileprivate static func describeRstStreamPayload(_ payload: Data) -> String {
        guard payload.count >= 4 else { return "truncated RST_STREAM payload" }
        let base = payload.startIndex
        let errorCode = (UInt32(payload[base]) << 24)
            | (UInt32(payload[base + 1]) << 16)
            | (UInt32(payload[base + 2]) << 8)
            | UInt32(payload[base + 3])
        return h2ErrorCodeName(errorCode)
    }

}

// MARK: - gRPC trailer parsing

extension GRPCConnection {

    /// Parses a trailer HEADERS block looking for `grpc-status` (and optionally `grpc-message`).
    /// Returns a `GRPCError.callFailed(...)` when the status is non-zero, or `nil` on OK (status 0
    /// or grpc-status not present — treated as implicitly OK).
    fileprivate static func parseGRPCTrailer(_ payload: Data) -> GRPCError? {
        let headers = decodeHPACKHeaders(payload)
        guard let statusStr = headers["grpc-status"], let status = Int(statusStr), status != 0 else {
            return nil
        }
        let message = headers["grpc-message"]
        return .callFailed(status: status, name: grpcStatusName(status), message: message)
    }

    /// Maps a numeric gRPC status to its canonical name (from google.rpc.Code).
    fileprivate static func grpcStatusName(_ code: Int) -> String {
        switch code {
        case 0:  return "OK"
        case 1:  return "CANCELLED"
        case 2:  return "UNKNOWN"
        case 3:  return "INVALID_ARGUMENT"
        case 4:  return "DEADLINE_EXCEEDED"
        case 5:  return "NOT_FOUND"
        case 6:  return "ALREADY_EXISTS"
        case 7:  return "PERMISSION_DENIED"
        case 8:  return "RESOURCE_EXHAUSTED"
        case 9:  return "FAILED_PRECONDITION"
        case 10: return "ABORTED"
        case 11: return "OUT_OF_RANGE"
        case 12: return "UNIMPLEMENTED"
        case 13: return "INTERNAL"
        case 14: return "UNAVAILABLE"
        case 15: return "DATA_LOSS"
        case 16: return "UNAUTHENTICATED"
        default: return "UNKNOWN(\(code))"
        }
    }

    /// Minimal HPACK decoder used for server trailer HEADERS. Handles indexed / literal
    /// representations with both Huffman and plain string encodings. Decodes enough of the
    /// static table to resolve common trailer names; dynamic-table entries are decoded as
    /// "literal with incremental indexing" but aren't stored (we don't maintain a dynamic
    /// table because trailers rarely reference one).
    ///
    /// Returns a lowercase `name: value` dictionary with the *last* value wins semantics
    /// (duplicate headers aren't expected in trailers).
    fileprivate static func decodeHPACKHeaders(_ payload: Data) -> [String: String] {
        var headers: [String: String] = [:]
        var offset = payload.startIndex

        while offset < payload.endIndex {
            let b = payload[offset]

            // 1xxxxxxx — indexed header field
            if b & 0x80 != 0 {
                let (idx, consumed) = decodeHPACKInteger(payload, at: offset, prefixBits: 7)
                offset += consumed
                if let entry = staticTableEntry(at: idx), let value = entry.value {
                    headers[entry.name] = value
                }
                continue
            }

            // 01xxxxxx — literal with incremental indexing
            if b & 0xC0 == 0x40 {
                let (nameIdx, nameConsumed) = decodeHPACKInteger(payload, at: offset, prefixBits: 6)
                offset += nameConsumed
                let name: String
                if nameIdx == 0 {
                    guard let (n, c) = decodeHPACKString(payload, at: offset) else { return headers }
                    name = n
                    offset += c
                } else {
                    name = staticTableEntry(at: nameIdx)?.name ?? ""
                }
                guard let (value, vc) = decodeHPACKString(payload, at: offset) else { return headers }
                offset += vc
                if !name.isEmpty { headers[name.lowercased()] = value }
                continue
            }

            // 001xxxxx — dynamic table size update (just skip)
            if b & 0xE0 == 0x20 {
                let (_, consumed) = decodeHPACKInteger(payload, at: offset, prefixBits: 5)
                offset += consumed
                continue
            }

            // 0000xxxx — literal without indexing, 0001xxxx — literal never indexed
            if b & 0xF0 == 0x00 || b & 0xF0 == 0x10 {
                let (nameIdx, nameConsumed) = decodeHPACKInteger(payload, at: offset, prefixBits: 4)
                offset += nameConsumed
                let name: String
                if nameIdx == 0 {
                    guard let (n, c) = decodeHPACKString(payload, at: offset) else { return headers }
                    name = n
                    offset += c
                } else {
                    name = staticTableEntry(at: nameIdx)?.name ?? ""
                }
                guard let (value, vc) = decodeHPACKString(payload, at: offset) else { return headers }
                offset += vc
                if !name.isEmpty { headers[name.lowercased()] = value }
                continue
            }

            // Unknown representation; bail out.
            return headers
        }
        return headers
    }

    /// HPACK integer decoder (RFC 7541 §5.1). Returns (value, bytesConsumed).
    private static func decodeHPACKInteger(_ data: Data, at start: Int, prefixBits: Int) -> (Int, Int) {
        let maxPrefix = (1 << prefixBits) - 1
        guard start < data.endIndex else { return (0, 0) }
        let first = Int(data[start] & UInt8(maxPrefix))
        if first < maxPrefix { return (first, 1) }
        var value = maxPrefix
        var m = 0
        var offset = start + 1
        while offset < data.endIndex {
            let b = data[offset]
            value += (Int(b & 0x7F)) << m
            offset += 1
            m += 7
            if b & 0x80 == 0 { return (value, offset - start) }
            if m >= 64 { return (value, offset - start) }
        }
        return (value, offset - start)
    }

    /// HPACK string decoder (RFC 7541 §5.2). Returns (string, bytesConsumed).
    private static func decodeHPACKString(_ data: Data, at start: Int) -> (String, Int)? {
        guard start < data.endIndex else { return nil }
        let meta = data[start]
        let isHuffman = (meta & 0x80) != 0
        let (length, lenConsumed) = decodeHPACKInteger(data, at: start, prefixBits: 7)
        let bytesStart = start + lenConsumed
        guard bytesStart + length <= data.endIndex else { return nil }
        let bytes = data.subdata(in: bytesStart ..< bytesStart + length)
        let str: String
        if isHuffman {
            str = huffmanDecode(bytes) ?? ""
        } else {
            str = String(data: bytes, encoding: .utf8) ?? ""
        }
        return (str, lenConsumed + length)
    }

    /// Static-table entry for the given 1-based index (RFC 7541 Appendix A).
    /// Only the entries we expect to see in gRPC trailers / headers are returned.
    private static func staticTableEntry(at index: Int) -> (name: String, value: String?)? {
        switch index {
        case 1:  return (":authority", nil)
        case 2:  return (":method", "GET")
        case 3:  return (":method", "POST")
        case 4:  return (":path", "/")
        case 5:  return (":path", "/index.html")
        case 6:  return (":scheme", "http")
        case 7:  return (":scheme", "https")
        case 8:  return (":status", "200")
        case 9:  return (":status", "204")
        case 10: return (":status", "206")
        case 11: return (":status", "304")
        case 12: return (":status", "400")
        case 13: return (":status", "404")
        case 14: return (":status", "500")
        case 31: return ("content-type", nil)
        case 28: return ("content-length", nil)
        case 58: return ("user-agent", nil)
        default: return nil
        }
    }

    /// Decodes an HPACK Huffman-encoded byte string (RFC 7541 Appendix B).
    /// Returns `nil` on malformed input. Uses a bit-level DFA-ish walk over the table.
    private static func huffmanDecode(_ data: Data) -> String? {
        var result = [UInt8]()
        var code: UInt32 = 0
        var bits = 0

        for byte in data {
            code = (code << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                // Try code lengths from 5 up to the maximum 30, smallest first, as each
                // HPACK Huffman symbol has a unique length and prefix.
                var matched = false
                for length in 5...min(bits, 30) {
                    let candidate = (code >> (bits - length)) & ((1 << length) - 1)
                    if let symbol = huffmanLookup(code: candidate, length: length) {
                        if symbol == 256 { return String(bytes: result, encoding: .utf8) }
                        result.append(UInt8(symbol & 0xFF))
                        bits -= length
                        matched = true
                        break
                    }
                }
                if !matched { break }
            }
        }

        // Any remaining bits must be the EOS prefix (all ones).
        if bits > 0 {
            let trailing = code & ((1 << bits) - 1)
            let allOnes: UInt32 = (1 << bits) - 1
            if trailing != allOnes { return nil }
        }

        return String(bytes: result, encoding: .utf8)
    }

    /// Looks up an HPACK Huffman symbol by its bit pattern and code length.
    /// Returns the symbol (byte value, or 256 for EOS) or `nil` if no match.
    private static func huffmanLookup(code: UInt32, length: Int) -> Int? {
        return huffmanTable[HuffmanKey(code: code, length: length)]
    }

    private struct HuffmanKey: Hashable { let code: UInt32; let length: Int }

    /// HPACK Huffman code table (RFC 7541 Appendix B). Symbol `256` is EOS.
    private static let huffmanTable: [HuffmanKey: Int] = {
        let entries: [(code: UInt32, length: Int, symbol: Int)] = [
            (0x1ff8, 13, 0), (0x7fffd8, 23, 1), (0xfffffe2, 28, 2), (0xfffffe3, 28, 3),
            (0xfffffe4, 28, 4), (0xfffffe5, 28, 5), (0xfffffe6, 28, 6), (0xfffffe7, 28, 7),
            (0xfffffe8, 28, 8), (0xffffea, 24, 9), (0x3ffffffc, 30, 10), (0xfffffe9, 28, 11),
            (0xfffffea, 28, 12), (0x3ffffffd, 30, 13), (0xfffffeb, 28, 14), (0xfffffec, 28, 15),
            (0xfffffed, 28, 16), (0xfffffee, 28, 17), (0xfffffef, 28, 18), (0xffffff0, 28, 19),
            (0xffffff1, 28, 20), (0xffffff2, 28, 21), (0x3ffffffe, 30, 22), (0xffffff3, 28, 23),
            (0xffffff4, 28, 24), (0xffffff5, 28, 25), (0xffffff6, 28, 26), (0xffffff7, 28, 27),
            (0xffffff8, 28, 28), (0xffffff9, 28, 29), (0xffffffa, 28, 30), (0xffffffb, 28, 31),
            (0x14, 6, 32), (0x3f8, 10, 33), (0x3f9, 10, 34), (0xffa, 12, 35),
            (0x1ff9, 13, 36), (0x15, 6, 37), (0xf8, 8, 38), (0x7fa, 11, 39),
            (0x3fa, 10, 40), (0x3fb, 10, 41), (0xf9, 8, 42), (0x7fb, 11, 43),
            (0xfa, 8, 44), (0x16, 6, 45), (0x17, 6, 46), (0x18, 6, 47),
            (0x0, 5, 48), (0x1, 5, 49), (0x2, 5, 50), (0x19, 6, 51),
            (0x1a, 6, 52), (0x1b, 6, 53), (0x1c, 6, 54), (0x1d, 6, 55),
            (0x1e, 6, 56), (0x1f, 6, 57), (0x5c, 7, 58), (0xfb, 8, 59),
            (0x7ffc, 15, 60), (0x20, 6, 61), (0xffb, 12, 62), (0x3fc, 10, 63),
            (0x1ffa, 13, 64), (0x21, 6, 65), (0x5d, 7, 66), (0x5e, 7, 67),
            (0x5f, 7, 68), (0x60, 7, 69), (0x61, 7, 70), (0x62, 7, 71),
            (0x63, 7, 72), (0x64, 7, 73), (0x65, 7, 74), (0x66, 7, 75),
            (0x67, 7, 76), (0x68, 7, 77), (0x69, 7, 78), (0x6a, 7, 79),
            (0x6b, 7, 80), (0x6c, 7, 81), (0x6d, 7, 82), (0x6e, 7, 83),
            (0x6f, 7, 84), (0x70, 7, 85), (0x71, 7, 86), (0x72, 7, 87),
            (0xfc, 8, 88), (0x73, 7, 89), (0xfd, 8, 90), (0x1ffb, 13, 91),
            (0x7fff0, 19, 92), (0x1ffc, 13, 93), (0x3ffc, 14, 94), (0x22, 6, 95),
            (0x7ffd, 15, 96), (0x3, 5, 97), (0x23, 6, 98), (0x4, 5, 99),
            (0x24, 6, 100), (0x5, 5, 101), (0x25, 6, 102), (0x26, 6, 103),
            (0x27, 6, 104), (0x6, 5, 105), (0x74, 7, 106), (0x75, 7, 107),
            (0x28, 6, 108), (0x29, 6, 109), (0x2a, 6, 110), (0x7, 5, 111),
            (0x2b, 6, 112), (0x76, 7, 113), (0x2c, 6, 114), (0x8, 5, 115),
            (0x9, 5, 116), (0x2d, 6, 117), (0x77, 7, 118), (0x78, 7, 119),
            (0x79, 7, 120), (0x7a, 7, 121), (0x7b, 7, 122), (0x7ffe, 15, 123),
            (0x7fc, 11, 124), (0x3ffd, 14, 125), (0x1ffd, 13, 126), (0xffffffc, 28, 127),
            (0xfffe6, 20, 128), (0x3fffd2, 22, 129), (0xfffe7, 20, 130), (0xfffe8, 20, 131),
            (0x3fffd3, 22, 132), (0x3fffd4, 22, 133), (0x3fffd5, 22, 134), (0x7fffd9, 23, 135),
            (0x3fffd6, 22, 136), (0x7fffda, 23, 137), (0x7fffdb, 23, 138), (0x7fffdc, 23, 139),
            (0x7fffdd, 23, 140), (0x7fffde, 23, 141), (0xffffeb, 24, 142), (0x7fffdf, 23, 143),
            (0xffffec, 24, 144), (0xffffed, 24, 145), (0x3fffd7, 22, 146), (0x7fffe0, 23, 147),
            (0xffffee, 24, 148), (0x7fffe1, 23, 149), (0x7fffe2, 23, 150), (0x7fffe3, 23, 151),
            (0x7fffe4, 23, 152), (0x1fffdc, 21, 153), (0x3fffd8, 22, 154), (0x7fffe5, 23, 155),
            (0x3fffd9, 22, 156), (0x7fffe6, 23, 157), (0x7fffe7, 23, 158), (0xffffef, 24, 159),
            (0x3fffda, 22, 160), (0x1fffdd, 21, 161), (0xfffe9, 20, 162), (0x3fffdb, 22, 163),
            (0x3fffdc, 22, 164), (0x7fffe8, 23, 165), (0x7fffe9, 23, 166), (0x1fffde, 21, 167),
            (0x7fffea, 23, 168), (0x3fffdd, 22, 169), (0x3fffde, 22, 170), (0xfffff0, 24, 171),
            (0x1fffdf, 21, 172), (0x3fffdf, 22, 173), (0x7fffeb, 23, 174), (0x7fffec, 23, 175),
            (0x1fffe0, 21, 176), (0x1fffe1, 21, 177), (0x3fffe0, 22, 178), (0x1fffe2, 21, 179),
            (0x7fffed, 23, 180), (0x3fffe1, 22, 181), (0x7fffee, 23, 182), (0x7fffef, 23, 183),
            (0xfffea, 20, 184), (0x3fffe2, 22, 185), (0x3fffe3, 22, 186), (0x3fffe4, 22, 187),
            (0x7ffff0, 23, 188), (0x3fffe5, 22, 189), (0x3fffe6, 22, 190), (0x7ffff1, 23, 191),
            (0x3ffffe0, 26, 192), (0x3ffffe1, 26, 193), (0xfffeb, 20, 194), (0x7fff1, 19, 195),
            (0x3fffe7, 22, 196), (0x7ffff2, 23, 197), (0x3fffe8, 22, 198), (0x1ffffec, 25, 199),
            (0x3ffffe2, 26, 200), (0x3ffffe3, 26, 201), (0x3ffffe4, 26, 202), (0x7ffffde, 27, 203),
            (0x7ffffdf, 27, 204), (0x3ffffe5, 26, 205), (0xfffff1, 24, 206), (0x1ffffed, 25, 207),
            (0x7fff2, 19, 208), (0x1fffe3, 21, 209), (0x3ffffe6, 26, 210), (0x7ffffe0, 27, 211),
            (0x7ffffe1, 27, 212), (0x3ffffe7, 26, 213), (0x7ffffe2, 27, 214), (0xfffff2, 24, 215),
            (0x1fffe4, 21, 216), (0x1fffe5, 21, 217), (0x3ffffe8, 26, 218), (0x3ffffe9, 26, 219),
            (0xffffffd, 28, 220), (0x7ffffe3, 27, 221), (0x7ffffe4, 27, 222), (0x7ffffe5, 27, 223),
            (0xfffec, 20, 224), (0xfffff3, 24, 225), (0xfffed, 20, 226), (0x1fffe6, 21, 227),
            (0x3fffe9, 22, 228), (0x1fffe7, 21, 229), (0x1fffe8, 21, 230), (0x7ffff3, 23, 231),
            (0x3fffea, 22, 232), (0x3fffeb, 22, 233), (0x1ffffee, 25, 234), (0x1ffffef, 25, 235),
            (0xfffff4, 24, 236), (0xfffff5, 24, 237), (0x3ffffea, 26, 238), (0x7ffff4, 23, 239),
            (0x3ffffeb, 26, 240), (0x7ffffe6, 27, 241), (0x3ffffec, 26, 242), (0x3ffffed, 26, 243),
            (0x7ffffe7, 27, 244), (0x7ffffe8, 27, 245), (0x7ffffe9, 27, 246), (0x7ffffea, 27, 247),
            (0x7ffffeb, 27, 248), (0xffffffe, 28, 249), (0x7ffffec, 27, 250), (0x7ffffed, 27, 251),
            (0x7ffffee, 27, 252), (0x7ffffef, 27, 253), (0x7fffff0, 27, 254), (0x3ffffee, 26, 255),
            (0x3fffffff, 30, 256),
        ]
        var table: [HuffmanKey: Int] = [:]
        table.reserveCapacity(entries.count)
        for entry in entries {
            table[HuffmanKey(code: entry.code, length: entry.length)] = entry.symbol
        }
        return table
    }()
}
