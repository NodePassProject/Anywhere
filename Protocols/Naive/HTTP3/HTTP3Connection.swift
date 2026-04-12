//
//  HTTP3Connection.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation

// MARK: - Error

enum HTTP3Error: Error, LocalizedError {
    case notReady
    case connectionFailed(String)
    case tunnelFailed(statusCode: String)
    case authenticationRequired
    case streamClosed

    var errorDescription: String? {
        switch self {
        case .notReady: return "HTTP/3 connection not ready"
        case .connectionFailed(let msg): return "HTTP/3 connection failed: \(msg)"
        case .tunnelFailed(let code): return "HTTP/3 CONNECT tunnel failed with status \(code)"
        case .authenticationRequired: return "HTTP/3 proxy authentication required (407)"
        case .streamClosed: return "HTTP/3 stream closed"
        }
    }
}

// MARK: - HTTP3Connection

class HTTP3Connection: NaiveTunnel {

    enum State {
        case idle, quicConnecting, settingsSent, connectSent, tunnelOpen, closed
    }

    private let quic: QUICConnection
    private let configuration: NaiveConfiguration
    private let destination: String

    private var state: State = .idle
    private let queue = DispatchQueue(label: "com.argsment.Anywhere.http3")

    private var controlStreamId: Int64 = -1
    private var requestStreamId: Int64 = -1

    private var receiveBuffer = Data()
    private var pendingReceiveCompletion: ((Data?, Error?) -> Void)?
    private var headersReceived = false
    private var pendingQuicBytes = 0

    /// Server control stream ID and in-flight frame buffer.
    private var serverControlStreamId: Int64?
    private var serverControlBuffer = Data()
    private var pendingServerStreams: [Int64: Data] = [:]
    private var serverSettingsReceived = false
    /// Peer-advertised MAX_FIELD_SECTION_SIZE; UInt64.max until SETTINGS arrives.
    private var peerMaxFieldSectionSize: UInt64 = UInt64.max

    private(set) var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType = .none

    var isConnected: Bool { state == .tunnelOpen }

    private var tunnelCompletion: ((Error?) -> Void)?

    init(configuration: NaiveConfiguration, destination: String) {
        self.configuration = configuration
        self.destination = destination
        self.quic = QUICConnection(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            serverName: configuration.effectiveSNI,
            alpn: ["h3"]
        )
    }

    // MARK: - NaiveTunnel

    func openTunnel(completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self, self.state == .idle else {
                completion(HTTP3Error.notReady)
                return
            }

            self.state = .quicConnecting
            self.tunnelCompletion = completion

            // React immediately when the QUIC connection closes
            self.quic.connectionClosedHandler = { [weak self] error in
                guard let self else { return }
                self.queue.async {
                    guard self.state != .closed else { return }
                    self.state = .closed
                    self.pendingReceiveCompletion?(nil, error)
                    self.pendingReceiveCompletion = nil
                    if let cb = self.tunnelCompletion {
                        self.tunnelCompletion = nil
                        cb(error)
                    }
                }
            }

            self.quic.connect { [weak self] error in
                guard let self else { return }
                if let error {
                    self.queue.async { self.state = .closed; completion(error) }
                    return
                }

                self.queue.async {
                    self.openControlStream()
                    self.quic.streamDataHandler = { [weak self] streamId, data, fin in
                        self?.queue.async {
                            self?.handleStreamData(streamId: streamId, data: data, fin: fin)
                        }
                    }
                    self.sendConnect()
                }
            }
        }
    }

    func sendData(_ data: Data, completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else {
                completion(HTTP3Error.streamClosed)
                return
            }
            guard self.state == .tunnelOpen else {
                completion(self.state == .closed ? HTTP3Error.streamClosed : HTTP3Error.notReady)
                return
            }
            let frame = HTTP3Framer.dataFrame(payload: data)
            self.quic.writeStream(self.requestStreamId, data: frame) { [weak self] error in
                if let error {
                    self?.queue.async { self?.state = .closed }
                    completion(error)
                } else {
                    completion(nil)
                }
            }
        }
    }

    func receiveData(completion: @escaping (Data?, Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else {
                completion(nil, HTTP3Error.streamClosed)
                return
            }
            if !self.receiveBuffer.isEmpty {
                self.ackConsumedBytes()
                let data = self.receiveBuffer
                self.receiveBuffer.removeAll()
                completion(data, nil)
                return
            }
            if self.state == .closed {
                completion(nil, nil)
                return
            }
            self.pendingReceiveCompletion = completion
        }
    }

    func close() {
        queue.async { [weak self] in
            guard let self else { return }
            self.state = .closed
            self.quic.close()
            self.pendingReceiveCompletion?(nil, HTTP3Error.streamClosed)
            self.pendingReceiveCompletion = nil
        }
    }

    // MARK: - Control Stream

    private func openControlStream() {
        guard let streamId = quic.openUniStream() else {
            tunnelCompletion?(HTTP3Error.connectionFailed("Failed to open control stream"))
            tunnelCompletion = nil
            return
        }
        controlStreamId = streamId

        var payload = Data()
        payload.append(0x00)
        payload.append(HTTP3Framer.clientSettingsFrame())
        quic.writeStream(streamId, data: payload) { _ in }

        if let enc = quic.openUniStream() {
            quic.writeStream(enc, data: Data([0x02])) { _ in }
        }
        if let dec = quic.openUniStream() {
            quic.writeStream(dec, data: Data([0x03])) { _ in }
        }

        state = .settingsSent
    }

    // MARK: - CONNECT Request

    private func sendConnect() {
        guard let streamId = quic.openBidiStream() else {
            tunnelCompletion?(HTTP3Error.connectionFailed("Failed to open QUIC stream"))
            tunnelCompletion = nil
            return
        }
        requestStreamId = streamId

        var extraHeaders: [(name: String, value: String)] = []
        extraHeaders.append((name: "user-agent", value: "Chrome/128.0.0.0"))
        if let auth = configuration.basicAuth {
            extraHeaders.append((name: "proxy-authorization", value: "Basic \(auth)"))
        }
        let cachedType = NaivePaddingNegotiator.cachedPaddingType(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.effectiveSNI
        )
        extraHeaders.append(contentsOf: NaivePaddingNegotiator.requestHeaders(
            fastOpen: cachedType != nil
        ))

        var allHeaders = extraHeaders
        allHeaders.insert((name: ":method", value: "CONNECT"), at: 0)
        allHeaders.insert((name: ":authority", value: destination), at: 1)
        guard isWithinPeerFieldSectionLimit(allHeaders) else {
            tunnelCompletion?(HTTP3Error.connectionFailed("Request headers exceed peer MAX_FIELD_SECTION_SIZE"))
            tunnelCompletion = nil
            return
        }

        let headerBlock = QPACKEncoder.encodeConnectHeaders(
            authority: destination, extraHeaders: extraHeaders
        )
        let headersFrame = HTTP3Framer.headersFrame(headerBlock: headerBlock)

        state = .connectSent
        quic.writeStream(streamId, data: headersFrame) { [weak self] error in
            if let error {
                self?.queue.async {
                    self?.tunnelCompletion?(error)
                    self?.tunnelCompletion = nil
                }
            }
        }
    }

    // MARK: - Stream Data Handling

    private func handleStreamData(streamId: Int64, data: Data, fin: Bool) {
        if streamId == requestStreamId {
            handleRequestStreamData(data, fin: fin)
            return
        }

        // Server-initiated unidirectional stream (bits 0x03).
        guard (streamId & 0x03) == 0x03, !data.isEmpty else { return }

        // Consume immediately so connection-level flow control isn't leaked.
        quic.extendStreamOffset(streamId, count: data.count)

        if streamId == serverControlStreamId {
            serverControlBuffer.append(data)
            processServerControlFrames()
            return
        }

        var buf = pendingServerStreams.removeValue(forKey: streamId) ?? Data()
        buf.append(data)
        guard !buf.isEmpty else { return }
        let streamType = buf[buf.startIndex]
        switch streamType {
        case 0x00:
            guard serverControlStreamId == nil else {
                tunnelCompletion?(HTTP3Error.connectionFailed("Duplicate server control stream"))
                tunnelCompletion = nil
                state = .closed
                return
            }
            serverControlStreamId = streamId
            serverControlBuffer = Data(buf.dropFirst())
            processServerControlFrames()
        case 0x01:
            tunnelCompletion?(HTTP3Error.connectionFailed("Server opened push stream without MAX_PUSH_ID"))
            tunnelCompletion = nil
            state = .closed
        case 0x02, 0x03:
            break // QPACK encoder/decoder — dynamic table disabled, discard.
        default:
            if !(streamType >= 0x21 && (UInt64(streamType) - 0x21) % 0x1f == 0) {
                quic.shutdownStream(streamId)
            }
        }
    }

    private func processServerControlFrames() {
        while !serverControlBuffer.isEmpty {
            guard let (frame, consumed) = HTTP3Framer.parseFrame(from: serverControlBuffer) else { break }
            serverControlBuffer = Data(serverControlBuffer.dropFirst(consumed))

            if !serverSettingsReceived {
                guard frame.type == HTTP3FrameType.settings.rawValue else {
                    tunnelCompletion?(HTTP3Error.connectionFailed("First control-stream frame was not SETTINGS"))
                    tunnelCompletion = nil
                    state = .closed
                    return
                }
                serverSettingsReceived = true
                if !parseServerSettings(frame.payload) {
                    tunnelCompletion?(HTTP3Error.connectionFailed("Malformed SETTINGS frame"))
                    tunnelCompletion = nil
                    state = .closed
                    return
                }
                continue
            }

            switch frame.type {
            case HTTP3FrameType.goaway.rawValue:
                state = .closed
            case HTTP3FrameType.settings.rawValue:
                tunnelCompletion?(HTTP3Error.connectionFailed("Duplicate SETTINGS frame"))
                tunnelCompletion = nil
                state = .closed
                return
            case HTTP3FrameType.data.rawValue,
                 HTTP3FrameType.headers.rawValue,
                 HTTP3FrameType.pushPromise.rawValue:
                tunnelCompletion?(HTTP3Error.connectionFailed("Forbidden frame on control stream"))
                tunnelCompletion = nil
                state = .closed
                return
            default:
                break
            }
        }
    }

    private func parseServerSettings(_ payload: Data) -> Bool {
        var offset = 0
        var seen = Set<UInt64>()
        while offset < payload.count {
            guard let (id, idLen) = HTTP3Framer.decodeVarInt(from: payload, offset: offset) else { return false }
            offset += idLen
            guard let (value, valLen) = HTTP3Framer.decodeVarInt(from: payload, offset: offset) else { return false }
            offset += valLen
            if !seen.insert(id).inserted { return false }
            if id == HTTP3SettingsID.maxFieldSectionSize.rawValue {
                peerMaxFieldSectionSize = value
            }
        }
        return true
    }

    private func isWithinPeerFieldSectionLimit(_ headers: [(name: String, value: String)]) -> Bool {
        let limit = peerMaxFieldSectionSize
        if limit == UInt64.max { return true }
        var total: UInt64 = 0
        for h in headers {
            total = total &+ UInt64(h.name.utf8.count) &+ UInt64(h.value.utf8.count) &+ 32
            if total > limit { return false }
        }
        return true
    }

    private func handleRequestStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty {
            pendingQuicBytes += data.count
            if !headersReceived {
                processResponseHeaders(data)
            } else {
                processDataFrames(data)
            }
        }

        if fin {
            state = .closed
            if let completion = pendingReceiveCompletion {
                pendingReceiveCompletion = nil
                completion(nil, nil)
            }
        }
    }

    private func processResponseHeaders(_ data: Data) {
        guard let (frame, consumed) = HTTP3Framer.parseFrame(from: data) else {
            tunnelCompletion?(HTTP3Error.connectionFailed("Invalid response frame"))
            tunnelCompletion = nil
            return
        }

        guard frame.type == HTTP3FrameType.headers.rawValue else {
            tunnelCompletion?(HTTP3Error.connectionFailed("Unexpected frame type"))
            tunnelCompletion = nil
            return
        }

        guard let headers = QPACKEncoder.decodeHeaders(from: frame.payload) else {
            tunnelCompletion?(HTTP3Error.connectionFailed("Malformed QPACK header block"))
            tunnelCompletion = nil
            return
        }

        let statusHeader = headers.first(where: { $0.name == ":status" })
        guard let status = statusHeader?.value, status == "200" else {
            let code = statusHeader?.value ?? "unknown"
            if code == "407" {
                tunnelCompletion?(HTTP3Error.authenticationRequired)
            } else {
                tunnelCompletion?(HTTP3Error.tunnelFailed(statusCode: code))
            }
            tunnelCompletion = nil
            return
        }

        let paddingTuples = headers.map { (name: $0.name, value: $0.value) }
        negotiatedPaddingType = NaivePaddingNegotiator.parseResponse(headers: paddingTuples)

        NaivePaddingNegotiator.cachePaddingType(
            negotiatedPaddingType,
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.effectiveSNI
        )

        headersReceived = true
        state = .tunnelOpen

        tunnelCompletion?(nil)
        tunnelCompletion = nil

        if consumed < data.count {
            processDataFrames(Data(data[consumed...]))
        }
    }

    private func processDataFrames(_ data: Data) {
        var offset = 0

        while offset < data.count {
            guard let (frame, consumed) = HTTP3Framer.parseFrame(from: data, offset: offset) else {
                receiveBuffer.append(Data(data[offset...]))
                break
            }

            offset += consumed

            if frame.type == HTTP3FrameType.data.rawValue {
                deliverData(frame.payload)
            }
        }
    }

    private func deliverData(_ data: Data) {
        if let completion = pendingReceiveCompletion {
            pendingReceiveCompletion = nil
            ackConsumedBytes()
            completion(data, nil)
        } else {
            receiveBuffer.append(data)
        }
    }

    private func ackConsumedBytes() {
        let count = pendingQuicBytes
        guard count > 0 else { return }
        pendingQuicBytes = 0
        quic.extendStreamOffset(requestStreamId, count: count)
    }
}
