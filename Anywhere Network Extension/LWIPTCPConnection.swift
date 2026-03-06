//
//  LWIPTCPConnection.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "LWIP-TCP")

class LWIPTCPConnection {
    let pcb: UnsafeMutableRawPointer
    let dstHost: String
    let dstPort: UInt16
    let configuration: VLESSConfiguration
    let lwipQueue: DispatchQueue

    private var vlessClient: VLESSClient?
    private var vlessConnection: VLESSConnection?
    private var vlessConnecting = false
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

    /// Whether the VLESS receive loop is paused due to a full lwIP send buffer.
    private var receivePaused = false

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
         configuration: VLESSConfiguration, forceBypass: Bool = false,
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
            if self.vlessConnecting || self.directConnecting {
                logger.error("[TCP] Handshake timeout for \(self.dstHost, privacy: .public):\(self.dstPort)")
                self.abort()
            }
        }
        handshakeTimer = timer
        lwipQueue.asyncAfter(deadline: .now() + Self.handshakeTimeout, execute: timer)

        if bypass {
            connectDirect()
        } else {
            connectVLESS()
        }
    }

    // MARK: - lwIP Callbacks (called on lwipQueue)

    /// Handles data received from the local app via lwIP (upload path).
    ///
    /// Sends each segment immediately to the proxy connection (matching
    /// Xray-core's tight read→write copy loop). tcp_recved is called
    /// upfront to keep the receive window open (pipelined). BSDSocket
    /// queues sends internally and drains via a write dispatch source.
    ///
    /// **IMPORTANT**: tcp_recved must ONLY be called when data is handed to an
    /// active connection — never for data buffered in `pendingData`. The
    /// pending-data path defers tcp_recved to the connect-completion handler
    /// to avoid double-advancing the receive window.
    func handleReceivedData(_ data: Data) {
        guard !closed else { return }
        activityTimer?.update()

        // Buffer data while the outbound connection is being established.
        // Do NOT call tcp_recved here — the connect-completion handler will
        // advance the window when pendingData is actually sent.
        if vlessConnecting || directConnecting {
            pendingData.append(data)
            return
        }

        if let relay = directRelay {
            lwip_bridge_tcp_recved(pcb, UInt16(data.count))
            relay.send(data: data) { [weak self] error in
                guard let self, let error else { return }
                logger.error("[TCP] Direct send error for \(self.dstHost, privacy: .public):\(self.dstPort): \(error.localizedDescription, privacy: .public)")
                self.lwipQueue.async { self.abort() }
            }
        } else if let connection = vlessConnection {
            lwip_bridge_tcp_recved(pcb, UInt16(data.count))
            connection.send(data: data) { [weak self] error in
                guard let self, let error else { return }
                logger.error("[TCP] VLESS send error for \(self.dstHost, privacy: .public):\(self.dstPort): \(error.localizedDescription, privacy: .public)")
                self.lwipQueue.async { self.abort() }
            }
        } else {
            // No connection yet — buffer without advancing window.
            pendingData.append(data)
            if bypass {
                connectDirect()
            } else {
                connectVLESS()
            }
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
        releaseVLESS()
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
                    logger.error("[TCP] Direct connect failed: \(self.dstHost, privacy: .public):\(self.dstPort): \(error.localizedDescription, privacy: .public)")
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

                // Flush data that arrived before/during connect
                if let initialData {
                    lwip_bridge_tcp_recved(self.pcb, UInt16(clamping: initialData.count))
                    relay.send(data: initialData) { [weak self] error in
                        guard let self, let error else { return }
                        logger.error("[TCP] Direct initial send error for \(self.dstHost, privacy: .public): \(error.localizedDescription, privacy: .public)")
                        self.lwipQueue.async { self.abort() }
                    }
                }

                if !self.pendingData.isEmpty {
                    let dataToSend = self.pendingData
                    self.pendingData.removeAll(keepingCapacity: true)
                    lwip_bridge_tcp_recved(self.pcb, UInt16(clamping: dataToSend.count))
                    relay.send(data: dataToSend) { [weak self] error in
                        guard let self, let error else { return }
                        logger.error("[TCP] Direct pending send error for \(self.dstHost, privacy: .public): \(error.localizedDescription, privacy: .public)")
                        self.lwipQueue.async { self.abort() }
                    }
                }

                self.requestNextReceive()
            }
        }
    }

    // MARK: - VLESS Connection

    private func connectVLESS() {
        guard !vlessConnecting && vlessConnection == nil && !closed else { return }
        vlessConnecting = true

        let initialData = pendingData.isEmpty ? nil : pendingData
        if initialData != nil {
            pendingData.removeAll(keepingCapacity: true)
        }

        let client = VLESSClient(configuration: configuration)
        self.vlessClient = client

        client.connect(to: dstHost, port: dstPort, initialData: initialData) { [weak self] result in
            guard let self else { return }

            self.lwipQueue.async {
                self.vlessConnecting = false
                guard !self.closed else { return }

                switch result {
                case .success(let vlessConnection):
                    self.vlessConnection = vlessConnection
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
                        lwip_bridge_tcp_recved(self.pcb, UInt16(clamping: dataToSend.count))
                        vlessConnection.send(data: dataToSend) { [weak self] error in
                            guard let self, let error else { return }
                            logger.error("[TCP] VLESS pending send error for \(self.dstHost, privacy: .public): \(error.localizedDescription, privacy: .public)")
                            self.lwipQueue.async { self.abort() }
                        }
                    }

                    self.requestNextReceive()

                case .failure(let error):
                    logger.error("[TCP] connect failed: \(self.dstHost, privacy: .public):\(self.dstPort): \(error.localizedDescription, privacy: .public)")
                    self.abort()
                }
            }
        }
    }

    // MARK: - VLESS Receive Loop

    /// Requests the next chunk of data from the VLESS connection.
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
                        logger.error("[TCP] Direct recv error: \(self.dstHost, privacy: .public):\(self.dstPort): \(error.localizedDescription, privacy: .public)")
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

        guard let connection = vlessConnection else { return }

        connection.receive { [weak self] data, error in
            guard let self else { return }

            self.lwipQueue.async {
                guard !self.closed else { return }

                if let error {
                    logger.error("[TCP] VLESS recv error: \(self.dstHost, privacy: .public):\(self.dstPort): \(error.localizedDescription, privacy: .public)")
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

    /// Writes data from VLESS to the lwIP TCP send buffer.
    ///
    /// Writes as much data as the lwIP send buffer can accept. Any remainder
    /// is stored in ``overflowBuffer`` and the receive loop pauses until
    /// ``handleSent(len:)`` drains the overflow and resumes receiving.
    private func writeToLWIP(_ data: Data) {
        guard !closed else { return }

        // If overflow already queued, append to preserve ordering.
        // Always accept the data — do NOT reject/abort here. The buffer may
        // temporarily exceed maxOverflowBufferSize by up to one chunk, but
        // backpressure (receivePaused) prevents further growth. Draining via
        // handleSent will bring it back under the limit.
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

        var offset = 0
        data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            while offset < data.count {
                var sndbuf = Int(lwip_bridge_tcp_sndbuf(pcb))
                if sndbuf <= 0 {
                    lwip_bridge_tcp_output(pcb)
                    sndbuf = Int(lwip_bridge_tcp_sndbuf(pcb))
                    if sndbuf <= 0 {
                        // Send buffer still full after flush — spill remainder to overflow.
                        // Do NOT abort: backpressure (receivePaused) at the end of this
                        // method will stop further receives until the buffer drains.
                        overflowBuffer.append(Data(bytes: base + offset, count: data.count - offset))
                        offset = data.count
                        break
                    }
                }
                let chunkSize = min(min(sndbuf, data.count - offset), Self.maxWriteSize)
                let writeLen = UInt16(chunkSize)
                let err = lwip_bridge_tcp_write(pcb, base + offset, writeLen)
                if err != 0 {
                    if err == -1 {
                        // ERR_MEM: global pbuf/segment pool exhausted — treat like full
                        // send buffer. Spill to overflow and let backpressure handle it.
                        // Do NOT abort: ERR_MEM is transient under load (e.g. speed tests).
                        // Other connections' ACKs will free segments, drainOverflowBuffer
                        // retries on handleSent / delayed timer, and this connection recovers.
                        overflowBuffer.append(Data(bytes: base + offset, count: data.count - offset))
                        offset = data.count
                        break
                    }
                    logger.error("[TCP] tcp_write error: \(err) for \(self.dstHost, privacy: .public):\(self.dstPort)")
                    self.abort()
                    return
                }
                offset += chunkSize
            }
        }

        guard !closed else { return }

        lwip_bridge_tcp_output(pcb)

        // Backpressure gate: if overflow has accumulated beyond the soft limit,
        // pause receives so the remote side stops sending. drainOverflowBuffer()
        // will resume receives once the buffer drops back under the limit.
        // This is the ONLY mechanism that bounds memory — do not add an abort here.
        if overflowBuffer.count < Self.maxOverflowBufferSize {
            requestNextReceive()
        } else {
            receivePaused = true
        }
    }

    /// Drains the overflow buffer into lwIP's TCP send buffer.
    ///
    /// Called from ``handleSent(len:)`` when the local app acknowledges data,
    /// freeing space in the lwIP send buffer. Resumes the VLESS receive loop
    /// as soon as any data is drained (mirroring Xray-core's instant-resume).
    private func drainOverflowBuffer() {
        guard !closed, !overflowBuffer.isEmpty else { return }

        var offset = 0
        let count = overflowBuffer.count
        overflowBuffer.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            while offset < count {
                let sndbuf = Int(lwip_bridge_tcp_sndbuf(pcb))
                guard sndbuf > 0 else { break }
                let chunkSize = min(min(sndbuf, count - offset), Self.maxWriteSize)
                let writeLen = UInt16(chunkSize)
                let err = lwip_bridge_tcp_write(pcb, base + offset, writeLen)
                if err != 0 {
                    if err == -1 { break }  // ERR_MEM: retry on next handleSent or delayed retry
                    logger.error("[TCP] tcp_write error: \(err) for \(self.dstHost, privacy: .public):\(self.dstPort)")
                    self.abort()
                    return
                }
                offset += chunkSize
            }
        }

        guard !closed else { return }

        if offset > 0 {
            if offset >= count {
                overflowBuffer.removeAll(keepingCapacity: true)
            } else {
                // Single COW reference here — removeSubrange does in-place
                // memmove without allocating a new buffer.
                overflowBuffer.removeSubrange(0..<offset)
            }
            lwip_bridge_tcp_output(pcb)
        } else if !overflowBuffer.isEmpty {
            // Nothing drained (ERR_MEM with empty send buffer) — no handleSent will
            // fire for this connection, so schedule a delayed retry to catch when the
            // global pbuf pool frees up from other connections.
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

        var offset = 0
        let count = overflowBuffer.count
        overflowBuffer.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            while offset < count {
                let sndbuf = Int(lwip_bridge_tcp_sndbuf(pcb))
                guard sndbuf > 0 else { break }
                let chunkSize = min(min(sndbuf, count - offset), Self.maxWriteSize)
                let writeLen = UInt16(chunkSize)
                let err = lwip_bridge_tcp_write(pcb, base + offset, writeLen)
                if err != 0 { break }
                offset += chunkSize
            }
        }

        if offset > 0 {
            if offset < count {
                logger.debug("[TCP] Flushed \(offset)/\(count) overflow bytes on close for \(self.dstHost, privacy: .public):\(self.dstPort)")
            }
            lwip_bridge_tcp_output(pcb)
        }
    }

    func close() {
        guard !closed else { return }
        closed = true
        flushOverflowToLWIP()
        lwip_bridge_tcp_close(pcb)
        releaseVLESS()
        Unmanaged.passUnretained(self).release()
    }

    func abort() {
        guard !closed else { return }
        closed = true
        lwip_bridge_tcp_abort(pcb)
        releaseVLESS()
        Unmanaged.passUnretained(self).release()
    }

    private func releaseVLESS() {
        handshakeTimer?.cancel()
        handshakeTimer = nil
        activityTimer?.cancel()
        activityTimer = nil
        let relay = directRelay
        let connection = vlessConnection
        let client = vlessClient
        directRelay = nil
        directConnecting = false
        vlessConnection = nil
        vlessClient = nil
        vlessConnecting = false
        pendingData = Data()
        overflowBuffer = Data()
        receivePaused = false
        relay?.cancel()
        connection?.cancel()
        client?.cancel()
    }

    deinit {
        directRelay?.cancel()
        vlessConnection?.cancel()
        vlessClient?.cancel()
    }
}
