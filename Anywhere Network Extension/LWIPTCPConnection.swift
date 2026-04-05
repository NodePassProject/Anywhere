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

    /// Remainder of the current receive that couldn't fit in lwIP's TCP send
    /// buffer. Bounded to at most one receive chunk — no new receives are
    /// issued until this is fully drained.
    private var pendingWrite = Data()

    // MARK: Upload Coalescing

    /// Accumulates segments from lwIP callbacks within a single processing batch.
    /// Flushed via `lwipQueue.async` after the current `lwip_bridge_input` loop,
    /// so all segments in one batch are encrypted and sent as a single chunk.
    /// This reduces AES-GCM operations from 2×N (per-segment) to 2×ceil(total/16383).
    private var uploadCoalesceBuffer = Data()
    private var uploadCoalesceRecvLen: Int = 0
    private var uploadCoalesceScheduled = false
    private var uploadFlushInFlight = false

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
        lwipQueue.asyncAfter(deadline: .now() + TunnelConstants.handshakeTimeout, execute: timer)

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
        if uploadCoalesceRecvLen + data.count > TunnelConstants.tcpMaxCoalesceSize {
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
    /// Drains pending data into the now-available send buffer space,
    /// and resumes the receive loop once fully drained.
    func handleSent(len: UInt16) {
        guard !closed else { return }
        drainPendingWrite()
    }

    func handleRemoteClose() {
        guard !closed else { return }
        uplinkDone = true
        if downlinkDone {
            close()
        } else {
            activityTimer?.setTimeout(TunnelConstants.downlinkOnlyTimeout)
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
                    timeout: TunnelConstants.connectionIdleTimeout
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
                        timeout: TunnelConstants.connectionIdleTimeout
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
    ///
    /// Issues the next receive on the proxy transport.
    ///
    /// The next receive is only issued **after** ``writeToLWIP(_:)`` confirms
    /// all data was consumed (pull model). If a remainder exists in
    /// ``pendingWrite``, no receive is issued until ``handleSent(len:)``
    /// drains it completely.
    private func requestNextReceive() {
        guard !closed else { return }

        if let relay = directRelay {
            relay.receive { [weak self] data, error in
                guard let self else { return }

                self.lwipQueue.async {
                    guard !self.closed else { return }

                    if let error {
                        self.logTransportFailure("Receive", error: error)
                        self.abort()
                        return
                    }

                    guard let data, !data.isEmpty else {
                        self.downlinkDone = true
                        if self.uplinkDone {
                            self.close()
                        } else {
                            self.activityTimer?.setTimeout(TunnelConstants.uplinkOnlyTimeout)
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
                    self.logTransportFailure("Receive", error: error)
                    self.abort()
                    return
                }

                guard let data, !data.isEmpty else {
                    self.downlinkDone = true
                    if self.uplinkDone {
                        self.close()
                    } else {
                        self.activityTimer?.setTimeout(TunnelConstants.uplinkOnlyTimeout)
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
            let chunkSize = min(min(sndbuf, count - offset), TunnelConstants.tcpMaxWriteSize)
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
    /// Feeds as much as possible to lwIP. Any remainder is saved in
    /// ``pendingWrite`` and no further receives are issued until
    /// ``handleSent(len:)`` drains it completely.
    private func writeToLWIP(_ data: Data) {
        guard !closed else { return }

        var written = 0
        data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            let fed = feedLWIP(base, count: data.count, retryOnEmpty: true)
            if fed == -1 {
                logger.error("[TCP] Write failed: \(self.dstHost):\(self.dstPort)")
                self.abort()
                return
            }
            written = fed
        }

        guard !closed else { return }

        lwip_bridge_tcp_output(pcb)
        LWIPStack.shared?.flushOutputInline()

        if written < data.count {
            // Save remainder — no more receives until this is drained.
            pendingWrite.append(data[written...])
        } else {
            // All consumed — pull the next chunk.
            requestNextReceive()
        }
    }

    /// Drains ``pendingWrite`` into lwIP's TCP send buffer.
    ///
    /// Called from ``handleSent(len:)`` when the local app acknowledges data,
    /// freeing space in the send buffer. Once fully drained, resumes the
    /// receive loop.
    private func drainPendingWrite() {
        guard !closed, !pendingWrite.isEmpty else { return }

        let count = pendingWrite.count
        let offset = pendingWrite.withUnsafeBytes { buffer -> Int in
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
                pendingWrite.removeAll(keepingCapacity: true)
            } else {
                pendingWrite.removeSubrange(0..<offset)
            }
            lwip_bridge_tcp_output(pcb)
            LWIPStack.shared?.flushOutputInline()
        } else if !pendingWrite.isEmpty {
            // Nothing drained (ERR_MEM) — schedule a delayed retry.
            logger.warning("[TCP] Drain stalled (\(self.pendingWrite.count) bytes pending), retrying in \(TunnelConstants.drainRetryDelayMs)ms: \(self.dstHost):\(self.dstPort)")
            lwipQueue.asyncAfter(deadline: .now() + .milliseconds(TunnelConstants.drainRetryDelayMs)) { [weak self] in
                guard let self, !self.closed else { return }
                self.drainPendingWrite()
            }
            return
        }

        // Fully drained — resume receiving.
        if pendingWrite.isEmpty {
            requestNextReceive()
        }
    }

    // MARK: - Close / Abort

    /// Best-effort flush of pending data into lwIP send buffer before close.
    /// Data written here will be delivered before the FIN segment.
    private func flushPendingToLWIP() {
        guard !pendingWrite.isEmpty else { return }

        let count = pendingWrite.count
        let offset = pendingWrite.withUnsafeBytes { buffer -> Int in
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
        flushPendingToLWIP()
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
        pendingWrite = Data()
        uploadCoalesceBuffer = Data()
        uploadCoalesceRecvLen = 0
        uploadFlushInFlight = false
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
