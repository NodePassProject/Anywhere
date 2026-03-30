//
//  LWIPTCPConnection.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

private let logger = TunnelLogger(category: "LWIP-TCP")

class LWIPTCPConnection {
    let pcb: UnsafeMutableRawPointer
    let dstHost: String
    let dstPort: UInt16
    let configuration: ProxyConfiguration
    let lwipQueue: DispatchQueue

    private var proxyClient: ProxyClient?
    private var proxyConnection: ProxyConnection?
    private var proxyConnecting = false
    private var directRelay: DirectTCPRelay?
    private var directConnecting = false
    private let bypass: Bool
    private var pendingData = Data()
    private var closed = false

    // MARK: Backpressure State

    /// Data that couldn't fit in lwIP's TCP send buffer.
    /// Acts as the equivalent of Xray-core's pipe buffer between reader and writer.
    private var overflowBuffer = Data()
    
    /// When the buffer exceeds this size, `receivePaused` is set to `true` to
    /// stop reading from the remote side, applying backpressure. The buffer is
    /// NOT hard-capped: a single in-flight receive may push it slightly over.
    ///
    /// **CAUTION — do NOT abort when this limit is exceeded.**
    /// Aborting causes unnecessary RSTs under heavy load (e.g. speed tests)
    /// where `ERR_MEM` is transient. The backpressure mechanism
    /// (`receivePaused` + `drainOverflowBuffer`) is the correct recovery path.
    private static let maxOverflowBufferSize = 512 * 1024  // 512 KB

    /// Maximum bytes per tcp_write call. Limits pbuf/segment allocation pressure:
    /// 16 KB ≈ 12 TCP segments (TCP_MSS=1360). With MEMP_NUM_TCP_SEG=4096 globally,
    /// this allows many concurrent connections to make progress without exhausting
    /// the segment pool (a 65 KB write would need ~49 segments — all-or-nothing).
    /// See also: MEMP_NUM_TCP_SEG in lwipopts.h (must stay in sync).
    private static let maxWriteSize = 16 * 1024

    /// Whether the proxy receive loop is paused due to a full lwIP send buffer.
    private var receivePaused = false

    // MARK: Upload Coalescing

    /// Accumulates segments from lwIP callbacks within a single processing batch.
    /// Flushed via `lwipQueue.async` after the current `lwip_bridge_input` loop,
    /// so all segments in one batch are encrypted and sent as a single chunk.
    /// This reduces AES-GCM operations from 2×N (per-segment) to 2×ceil(total/16383).
    private var uploadCoalesceBuffer = Data()
    private var uploadCoalesceRecvLen: Int = 0
    private var uploadCoalesceScheduled = false
    private var uploadFlushInFlight = false

    /// Maximum coalesce buffer size. Capped at UInt16.max because downstream
    /// protocols (Vision padding) use 2-byte content length fields.
    private static let maxCoalesceSize = Int(UInt16.max)

    // MARK: Activity Timeout (matches Xray-core policy defaults)

    /// Inactivity timeout for the connection (Xray-core `connIdle`, default 300s).
    private static let connectionIdleTimeout: TimeInterval = 300

    /// Timeout after uplink (local → remote) finishes (Xray-core `downlinkOnly`, default 1s).
    private static let downlinkOnlyTimeout: TimeInterval = 1

    /// Timeout after downlink (remote → local) finishes (Xray-core `uplinkOnly`, default 1s).
    private static let uplinkOnlyTimeout: TimeInterval = 1

    /// Handshake timeout matching Xray-core's `Timeout.Handshake` (60 seconds).
    /// Bounds the entire connection setup phase (TCP + TLS + WS/HTTPUpgrade + VLESS header).
    private static let handshakeTimeout: TimeInterval = 60

    private var activityTimer: ActivityTimer?
    private var handshakeTimer: DispatchWorkItem?
    private var uplinkDone = false
    private var downlinkDone = false

    // MARK: Lifecycle

    init(pcb: UnsafeMutableRawPointer, dstHost: String, dstPort: UInt16,
         configuration: ProxyConfiguration, forceBypass: Bool = false,
         lwipQueue: DispatchQueue) {
        self.pcb = pcb
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.configuration = configuration
        self.lwipQueue = lwipQueue
        self.bypass = forceBypass || (LWIPStack.shared?.shouldBypass(host: dstHost) == true)

        // Start handshake timeout (Xray-core Timeout.Handshake = 60s)
        let timer = DispatchWorkItem { [weak self] in
            guard let self, !self.closed else { return }
            if self.proxyConnecting || self.directConnecting {
                logger.error("[TCP] Handshake timeout for \(self.dstHost):\(self.dstPort)")
                self.abort()
            }
        }
        handshakeTimer = timer
        lwipQueue.asyncAfter(deadline: .now() + Self.handshakeTimeout, execute: timer)

        if bypass {
            connectDirect()
        } else {
            connectProxy()
        }
    }

    // MARK: - lwIP Callbacks (called on lwipQueue)

    /// Handles data received from the local app via lwIP (upload path).
    ///
    /// Coalesces segments within a single lwIP processing batch (all the
    /// `lwip_bridge_input` calls from one `readPackets` batch run synchronously
    /// on lwipQueue). A deferred flush encrypts and sends the accumulated data
    /// as one chunk, reducing per-segment crypto and dispatch overhead.
    ///
    /// When a previous flush is still in-flight, falls back to per-segment
    /// sends to provide natural backpressure via `tcp_recved`.
    func handleReceivedData(_ data: Data) {
        guard !closed else { return }
        activityTimer?.update()

        if proxyConnecting || directConnecting {
            pendingData.append(data)
            return
        }

        guard directRelay != nil || proxyConnection != nil else {
            pendingData.append(data)
            if bypass { connectDirect() } else { connectProxy() }
            return
        }

        // Buffer would overflow — flush accumulated data first to
        // maintain stream ordering, then fall back to per-segment sends.
        if uploadCoalesceRecvLen + data.count > Self.maxCoalesceSize {
            if uploadCoalesceRecvLen > 0 && !uploadFlushInFlight {
                flushUploadBuffer()
            }
            if uploadCoalesceRecvLen == 0 {
                // Buffer is empty (was empty or just flushed) — safe to
                // send per-segment for backpressure without reordering.
                sendSegmentDirect(data)
            } else {
                // A flush is in-flight and the buffer has unsent data.
                // Coalesce to preserve ordering; the chain-flush on
                // completion will send it after the in-flight data.
                uploadCoalesceBuffer.append(data)
                uploadCoalesceRecvLen += data.count
            }
            return
        }

        // Always coalesce — even while a flush is in-flight. This matches
        // Xray-core's buffered-pipe design where data accumulates during the
        // scMinPostsIntervalMs sleep and is sent as one large POST.
        // Without this, each individual TCP segment (~1-2 KB) would become its
        // own POST request during the delay, causing massive HTTP overhead.
        uploadCoalesceBuffer.append(data)
        uploadCoalesceRecvLen += data.count

        // Schedule flush only when no send is in-flight (data accumulated
        // during an in-flight send will be flushed when it completes).
        if !uploadFlushInFlight && !uploadCoalesceScheduled {
            uploadCoalesceScheduled = true
            lwipQueue.async { [weak self] in
                self?.flushUploadBuffer()
            }
        }
    }

    /// Sends a single segment directly (no coalescing), with tcp_recved in the completion.
    private func sendSegmentDirect(_ data: Data) {
        let recvLen = UInt16(data.count)
        let completion: (Error?) -> Void = { [weak self] error in
            guard let self else { return }
            self.lwipQueue.async {
                guard !self.closed else { return }
                if let error {
                    self.logTransportFailure("Send", error: error)
                    self.abort()
                    return
                }
                lwip_bridge_tcp_recved(self.pcb, recvLen)
            }
        }
        if let relay = directRelay {
            relay.send(data: data, completion: completion)
        } else if let connection = proxyConnection {
            connection.send(data: data, completion: completion)
        }
    }

    /// Flushes the coalesced upload buffer — encrypts and sends all accumulated
    /// segments as a single chunk, then acknowledges to lwIP on completion.
    private func flushUploadBuffer() {
        uploadCoalesceScheduled = false
        guard !closed else {
            uploadCoalesceBuffer.removeAll()
            uploadCoalesceRecvLen = 0
            return
        }

        let data = uploadCoalesceBuffer
        let recvLen = uploadCoalesceRecvLen
        uploadCoalesceBuffer = Data()
        uploadCoalesceRecvLen = 0

        guard !data.isEmpty else { return }

        uploadFlushInFlight = true

        let completion: (Error?) -> Void = { [weak self] error in
            guard let self else { return }
            self.lwipQueue.async {
                self.uploadFlushInFlight = false
                guard !self.closed else { return }
                if let error {
                    self.logTransportFailure("Send", error: error)
                    self.abort()
                    return
                }
                // Acknowledge all coalesced bytes to lwIP (uint16_t chunks)
                var remaining = recvLen
                while remaining > 0 {
                    let chunk = UInt16(min(remaining, Int(UInt16.max)))
                    remaining -= Int(chunk)
                    lwip_bridge_tcp_recved(self.pcb, chunk)
                }
                // Immediately flush data that accumulated during the in-flight send.
                // This is the key to matching Xray-core's batched upload behavior:
                // data coalesces while the previous POST + delay runs, then flushes
                // as one large POST instead of many small per-segment POSTs.
                if self.uploadCoalesceRecvLen > 0 {
                    self.flushUploadBuffer()
                }
            }
        }

        if let relay = directRelay {
            relay.send(data: data, completion: completion)
        } else if let connection = proxyConnection {
            connection.send(data: data, completion: completion)
        }
    }

    /// Called when the local app acknowledges receipt of data sent via lwIP.
    ///
    /// Drains the overflow buffer into the now-available send buffer space,
    /// and resumes the VLESS receive loop once overflow is fully drained.
    /// This mirrors Xray-core's pipe read-signal mechanism.
    func handleSent(len: UInt16) {
        guard !closed else { return }
        drainOverflowBuffer()
    }

    func handleRemoteClose() {
        guard !closed else { return }
        uplinkDone = true
        if downlinkDone {
            close()
        } else {
            activityTimer?.setTimeout(Self.downlinkOnlyTimeout)
        }
    }

    func handleError(err: Int32) {
        closed = true
        releaseProxy()
    }

    private var endpointDescription: String {
        "\(dstHost):\(dstPort)"
    }

    private static func conciseErrorDescription(_ error: Error) -> String {
        var message = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        let redundantPrefixes = [
            "Connection failed: ",
            "Send failed: ",
            "Receive failed: ",
            "DNS resolution failed: "
        ]

        for prefix in redundantPrefixes where message.hasPrefix(prefix) {
            message.removeFirst(prefix.count)
            break
        }

        return message
    }

    private func logTransportFailure(_ operation: String, error: Error) {
        let errorDescription = Self.conciseErrorDescription(error)

        if error is HTTP2Error {
            logger.debug("[TCP] \(operation) error: \(endpointDescription): \(errorDescription)")
            return
        }

        if let interruption = LWIPStack.shared?.recentTunnelInterruptionContext() {
            if interruption.level == .info {
                logger.debug("[TCP] \(operation) ended after \(interruption.summary): \(endpointDescription): \(errorDescription)")
            } else {
                logger.warning("[TCP] \(operation) interrupted after \(interruption.summary): \(endpointDescription) (\(errorDescription))")
            }
            return
        }

        logger.error("[TCP] \(operation) failed: \(endpointDescription): \(errorDescription)")
    }

    // MARK: - Direct Connection (bypass)

    private func connectDirect() {
        guard !directConnecting && directRelay == nil && !closed else { return }
        directConnecting = true

        let initialData = pendingData.isEmpty ? nil : pendingData
        if initialData != nil {
            pendingData.removeAll(keepingCapacity: true)
        }

        let relay = DirectTCPRelay()
        self.directRelay = relay
        relay.connect(host: dstHost, port: dstPort, queue: lwipQueue) { [weak self] error in
            guard let self else { return }

            self.lwipQueue.async {
                self.directConnecting = false
                guard !self.closed else { return }

                if let error {
                    self.logTransportFailure("Connect", error: error)
                    self.abort()
                    return
                }
                self.handshakeTimer?.cancel()
                self.handshakeTimer = nil
                self.activityTimer = ActivityTimer(
                    queue: self.lwipQueue,
                    timeout: Self.connectionIdleTimeout
                ) { [weak self] in
                    guard let self, !self.closed else { return }
                    self.close()
                }

                if let initialData {
                    let totalReceiveLength = initialData.count
                    relay.send(data: initialData) { [weak self] error in
                        guard let self else { return }
                        if let error {
                            self.logTransportFailure("Send", error: error)
                            self.lwipQueue.async { self.abort() }
                        } else {
                            self.lwipQueue.async {
                                guard !self.closed else { return }
                                var remaining = totalReceiveLength
                                while remaining > 0 {
                                    let chunk = UInt16(min(remaining, Int(UInt16.max)))
                                    remaining -= Int(chunk)
                                    lwip_bridge_tcp_recved(self.pcb, chunk)
                                }
                            }
                        }
                    }
                }

                if !self.pendingData.isEmpty {
                    let dataToSend = self.pendingData
                    self.pendingData.removeAll(keepingCapacity: true)
                    let totalReceiveLength = dataToSend.count
                    relay.send(data: dataToSend) { [weak self] error in
                        guard let self else { return }
                        if let error {
                            self.logTransportFailure("Send", error: error)
                            self.lwipQueue.async { self.abort() }
                        } else {
                            self.lwipQueue.async {
                                guard !self.closed else { return }
                                var remaining = totalReceiveLength
                                while remaining > 0 {
                                    let chunk = UInt16(min(remaining, Int(UInt16.max)))
                                    remaining -= Int(chunk)
                                    lwip_bridge_tcp_recved(self.pcb, chunk)
                                }
                            }
                        }
                    }
                }

                self.requestNextReceive()
            }
        }
    }

    // MARK: - Proxy Connection

    private func connectProxy() {
        guard !proxyConnecting && proxyConnection == nil && !closed else { return }
        proxyConnecting = true

        // For VLESS, initial data is appended to the protocol header and sent in one packet.
        // For Shadowsocks and NaiveProxy, data flows through send() after connection,
        // so we keep it in pendingData to be sent after connection succeeds.
        let initialData: Data?
        if configuration.outboundProtocol == .shadowsocks || configuration.outboundProtocol.isNaive {
            initialData = nil
        } else {
            initialData = pendingData.isEmpty ? nil : pendingData
            if initialData != nil {
                pendingData.removeAll(keepingCapacity: true)
            }
        }

        let client = ProxyClient(configuration: configuration)
        self.proxyClient = client

        client.connect(to: dstHost, port: dstPort, initialData: initialData) { [weak self] result in
            guard let self else { return }

            self.lwipQueue.async {
                self.proxyConnecting = false
                guard !self.closed else { return }

                switch result {
                case .success(let proxyConnection):
                    self.proxyConnection = proxyConnection
                    self.handshakeTimer?.cancel()
                    self.handshakeTimer = nil
                    self.activityTimer = ActivityTimer(
                        queue: self.lwipQueue,
                        timeout: Self.connectionIdleTimeout
                    ) { [weak self] in
                        guard let self, !self.closed else { return }
                        self.close()
                    }

                    if !self.pendingData.isEmpty {
                        let dataToSend = self.pendingData
                        self.pendingData.removeAll(keepingCapacity: true)
                        let totalReceiveLength = dataToSend.count
                        proxyConnection.send(data: dataToSend) { [weak self] error in
                            guard let self else { return }
                            if let error {
                                self.logTransportFailure("Send", error: error)
                                self.lwipQueue.async { self.abort() }
                            } else {
                                self.lwipQueue.async {
                                    guard !self.closed else { return }
                                    var remaining = totalReceiveLength
                                    while remaining > 0 {
                                        let chunk = UInt16(min(remaining, Int(UInt16.max)))
                                        remaining -= Int(chunk)
                                        lwip_bridge_tcp_recved(self.pcb, chunk)
                                    }
                                }
                            }
                        }
                    }

                    self.requestNextReceive()

                case .failure(let error):
                    self.logTransportFailure("Connect", error: error)
                    self.abort()
                }
            }
        }
    }

    // MARK: - Proxy Receive Loop

    /// Requests the next chunk of data from the proxy connection.
    ///
    /// Manages the receive loop manually (instead of `startReceiving`) to
    /// support pause/resume for backpressure. Only issues a receive when
    /// not paused and the connection is active.
    private func requestNextReceive() {
        guard !closed, !receivePaused else { return }

        if let relay = directRelay {
            relay.receive { [weak self] data, error in
                guard let self else { return }

                self.lwipQueue.async {
                    guard !self.closed else { return }

                    if let error {
                        self.logTransportFailure("Recv", error: error)
                        self.abort()
                        return
                    }

                    guard let data, !data.isEmpty else {
                        self.downlinkDone = true
                        if self.uplinkDone {
                            self.close()
                        } else {
                            self.activityTimer?.setTimeout(Self.uplinkOnlyTimeout)
                        }
                        return
                    }

                    self.activityTimer?.update()
                    self.writeToLWIP(data)
                }
            }
            return
        }

        guard let connection = proxyConnection else { return }

        connection.receive { [weak self] data, error in
            guard let self else { return }

            self.lwipQueue.async {
                guard !self.closed else { return }

                if let error {
                    self.logTransportFailure("Recv", error: error)
                    self.abort()
                    return
                }

                guard let data, !data.isEmpty else {
                    self.downlinkDone = true
                    if self.uplinkDone {
                        self.close()
                    } else {
                        self.activityTimer?.setTimeout(Self.uplinkOnlyTimeout)
                    }
                    return
                }

                self.activityTimer?.update()
                self.writeToLWIP(data)
            }
        }
    }

    // MARK: - lwIP Write Helper

    /// Writes as many bytes as possible from buffer to lwIP's TCP send buffer.
    /// Returns bytes written. Returns -1 on fatal (non-transient) tcp_write error.
    ///
    /// When `retryOnEmpty` is true, calls `tcp_output` once to flush if the send
    /// buffer is initially full, then retries — used by the initial write path.
    private func feedLWIP(_ base: UnsafeRawPointer, count: Int, retryOnEmpty: Bool = false) -> Int {
        var offset = 0
        while offset < count {
            var sndbuf = Int(lwip_bridge_tcp_sndbuf(pcb))
            if sndbuf <= 0 {
                if retryOnEmpty {
                    lwip_bridge_tcp_output(pcb)
                    sndbuf = Int(lwip_bridge_tcp_sndbuf(pcb))
                }
                guard sndbuf > 0 else { break }
            }
            let chunkSize = min(min(sndbuf, count - offset), Self.maxWriteSize)
            let err = lwip_bridge_tcp_write(pcb, base + offset, UInt16(chunkSize))
            if err != 0 {
                if err == -1 { break }  // ERR_MEM: transient
                return -1               // fatal error
            }
            offset += chunkSize
        }
        return offset
    }

    /// Writes data from proxy to the lwIP TCP send buffer.
    ///
    /// Writes as much data as the lwIP send buffer can accept. Any remainder
    /// is stored in ``overflowBuffer`` and the receive loop pauses until
    /// ``handleSent(len:)`` drains the overflow and resumes receiving.
    private func writeToLWIP(_ data: Data) {
        guard !closed else { return }

        // If overflow already queued, append to preserve ordering.
        if !overflowBuffer.isEmpty {
            overflowBuffer.append(data)
            drainOverflowBuffer()
            guard !closed else { return }
            if overflowBuffer.count < Self.maxOverflowBufferSize {
                requestNextReceive()
            } else {
                receivePaused = true
            }
            return
        }

        data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            let written = feedLWIP(base, count: data.count, retryOnEmpty: true)
            if written == -1 {
                logger.error("[TCP] Write failed: \(self.dstHost):\(self.dstPort)")
                self.abort()
                return
            }
            if written < data.count {
                overflowBuffer.append(Data(bytes: base + written, count: data.count - written))
            }
        }

        guard !closed else { return }

        lwip_bridge_tcp_output(pcb)

        // Backpressure gate: if overflow has accumulated beyond the soft limit,
        // pause receives so the remote side stops sending.
        if overflowBuffer.count < Self.maxOverflowBufferSize {
            requestNextReceive()
        } else {
            receivePaused = true
        }
    }

    /// Drains the overflow buffer into lwIP's TCP send buffer.
    ///
    /// Called from ``handleSent(len:)`` when the local app acknowledges data,
    /// freeing space in the lwIP send buffer. Resumes the proxy receive loop
    /// as soon as any data is drained (mirroring Xray-core's instant-resume).
    private func drainOverflowBuffer() {
        guard !closed, !overflowBuffer.isEmpty else { return }

        let count = overflowBuffer.count
        let offset = overflowBuffer.withUnsafeBytes { buffer -> Int in
            guard let base = buffer.baseAddress else { return 0 }
            let written = feedLWIP(base, count: count)
            if written == -1 {
                logger.error("[TCP] Write failed: \(self.dstHost):\(self.dstPort)")
                self.abort()
                return 0
            }
            return written
        }

        guard !closed else { return }

        if offset > 0 {
            if offset >= count {
                overflowBuffer.removeAll(keepingCapacity: true)
            } else {
                overflowBuffer.removeSubrange(0..<offset)
            }
            lwip_bridge_tcp_output(pcb)
        } else if !overflowBuffer.isEmpty {
            // Nothing drained (ERR_MEM with empty send buffer) — no handleSent will
            // fire for this connection, so schedule a delayed retry.
            lwipQueue.asyncAfter(deadline: .now() + .milliseconds(100)) { [weak self] in
                guard let self, !self.closed else { return }
                self.drainOverflowBuffer()
            }
        }

        if receivePaused && overflowBuffer.count < Self.maxOverflowBufferSize {
            receivePaused = false
            requestNextReceive()
        }
    }

    // MARK: - Close / Abort

    /// Best-effort flush of overflow data into lwIP send buffer before close.
    /// Data written here will be delivered before the FIN segment.
    private func flushOverflowToLWIP() {
        guard !overflowBuffer.isEmpty else { return }

        let count = overflowBuffer.count
        let offset = overflowBuffer.withUnsafeBytes { buffer -> Int in
            guard let base = buffer.baseAddress else { return 0 }
            let written = feedLWIP(base, count: count)
            return max(written, 0)  // treat fatal as 0 (best-effort)
        }

        if offset > 0 {
            lwip_bridge_tcp_output(pcb)
        }
    }

    func close() {
        guard !closed else { return }
        closed = true
        flushOverflowToLWIP()
        lwip_bridge_tcp_close(pcb)
        releaseProxy()
        Unmanaged.passUnretained(self).release()
    }

    func abort() {
        guard !closed else { return }
        closed = true
        lwip_bridge_tcp_abort(pcb)
        releaseProxy()
        Unmanaged.passUnretained(self).release()
    }

    private func releaseProxy() {
        handshakeTimer?.cancel()
        handshakeTimer = nil
        activityTimer?.cancel()
        activityTimer = nil
        let relay = directRelay
        let connection = proxyConnection
        let client = proxyClient
        directRelay = nil
        directConnecting = false
        proxyConnection = nil
        proxyClient = nil
        proxyConnecting = false
        pendingData = Data()
        overflowBuffer = Data()
        uploadCoalesceBuffer = Data()
        uploadCoalesceRecvLen = 0
        uploadFlushInFlight = false
        receivePaused = false
        relay?.cancel()
        connection?.cancel()
        client?.cancel()
    }

    deinit {
        directRelay?.cancel()
        proxyConnection?.cancel()
        proxyClient?.cancel()
    }
}
