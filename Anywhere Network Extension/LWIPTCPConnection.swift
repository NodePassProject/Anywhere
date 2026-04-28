//
//  LWIPTCPConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

private let logger = AnywhereLogger(category: "LWIP-TCP")

class LWIPTCPConnection {
    let pcb: UnsafeMutableRawPointer
    let dstPort: UInt16
    let lwipQueue: DispatchQueue

    /// The destination the proxy will be asked to connect to. Initialized
    /// from the tcp_accept signal and may be replaced with the SNI hostname
    /// once sniffing resolves.
    private(set) var dstHost: String

    /// The routing configuration for this connection. Mutable because a
    /// successful SNI sniff can re-match a domain rule that points to a
    /// different proxy.
    private(set) var configuration: ProxyConfiguration

    private var proxyClient: ProxyClient?
    private var proxyConnection: ProxyConnection?
    private var proxyConnecting = false
    private var bypass: Bool
    private var pendingData = Data()
    private var closed = false

    // MARK: SNI Sniffing
    //
    // When present, the connection is in the "sniff" phase: inbound bytes are
    // buffered (in `pendingData`) and fed to the sniffer before the proxy is
    // dialed. The first terminal state (.found / .notTLS / .unavailable)
    // commits the route and kicks off the proxy connect. Cleared to nil once
    // the route is committed.
    private var sniffer: TLSClientHelloSniffer?

    // MARK: Backpressure State

    /// Downlink backlog: proxy-received bytes queued for lwIP's TCP send
    /// buffer. Receives are issued whenever this drops below
    /// `TunnelConstants.drainLowWaterMark` and no receive is in flight, so
    /// the next chunk lands ready to push as lwIP's snd_buf frees up.
    ///
    /// Head-offset layout: bytes in `[0, pendingWriteOffset)` have been handed
    /// to `tcp_write` and are no longer needed, bytes in
    /// `[pendingWriteOffset, pendingWrite.count)` are still waiting. We advance
    /// the offset instead of `removeSubrange(0..<offset)` on every partial
    /// drain — that memmove is O(tail) per cycle and gets expensive when the
    /// backlog is large. Compaction happens only when the dead prefix outgrows
    /// the live suffix (see ``drainPendingWrite``), which keeps amortized cost
    /// O(1) per byte with at most ~2× memory overhead.
    private var pendingWrite = Data()
    private var pendingWriteOffset = 0

    /// Bytes still waiting to be handed to lwIP.
    private var pendingWriteCount: Int {
        pendingWrite.count - pendingWriteOffset
    }

    /// True from the moment `tryArmReceive` dispatches a proxy receive until
    /// its completion runs on `lwipQueue`. Guarantees at most one outstanding
    /// receive at a time (the proxy transports require serial receives).
    private var receiveInFlight = false

    // MARK: Upload Pipeline
    //
    // FIFO buffer of bytes received from lwIP, drained by ``pumpUploadSends``
    // through `proxyConnection.send` one chunk at a time.
    //
    // Single-flight is mandatory: several proxy transports (Vision over
    // HTTP/2, gRPC, others) can split one logical `send` internally when a
    // flow-control window is exhausted, then resume the remainder later
    // when a window update arrives. With two LWIP chunks in flight, the
    // later chunk's bytes can interleave with the earlier chunk's
    // remainder, corrupting the byte stream the proxy sees. Even
    // transports that look like a plain TCP stream (NWConnection.send
    // preserves enqueue order) sit under framing layers that may reorder
    // around backpressure. Until every transport guarantees strict
    // serialisation of overlapping `send` calls, we serialise here.
    //
    // Ordering invariants:
    // - Bytes are appended at the tail by ``handleReceivedData`` and consumed
    //   at the head by ``pumpUploadSends`` in order. ``bufferOffset`` is the
    //   live-data head; ``buffer[bufferOffset..<buffer.count]`` is the unsent
    //   suffix. The dead prefix is compacted lazily when it grows past the
    //   live suffix (matches the downlink's ``pendingWrite`` strategy).
    // - At most one `proxyConnection.send` call is outstanding at a time.
    //   The next chunk is issued only after the previous completion runs.
    //
    // Backpressure: ``lwip_bridge_tcp_recved`` runs only on send completion
    // (one ack per send for that send's bytes), so the local TCP receive
    // window naturally caps total bytes in the pipeline at lwIP's TCP_WND.
    private struct UploadPipeline {
        var buffer = Data()
        var bufferOffset = 0
        var sendInFlight = false
        var isPumpScheduled = false
    }
    private var uploadPipeline = UploadPipeline()

    private var uploadBufferCount: Int {
        uploadPipeline.buffer.count - uploadPipeline.bufferOffset
    }

    private var activityTimer: ActivityTimer?
    private var handshakeTimer: DispatchWorkItem?
    /// Fires if the sniff phase doesn't resolve within
    /// `TunnelConstants.sniffDeadline` — commits the IP-based route so
    /// server-speaks-first protocols don't stall waiting for a ClientHello.
    private var sniffDeadline: DispatchWorkItem?
    private var uplinkDone = false
    private var downlinkDone = false

    // MARK: Lifecycle

    init(pcb: UnsafeMutableRawPointer, dstHost: String, dstPort: UInt16,
         configuration: ProxyConfiguration, forceBypass: Bool = false,
         sniffSNI: Bool = false,
         lwipQueue: DispatchQueue) {
        self.pcb = pcb
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.configuration = configuration
        self.lwipQueue = lwipQueue
        self.bypass = forceBypass || (LWIPStack.shared?.shouldBypass(host: dstHost) == true)
        if sniffSNI {
            self.sniffer = TLSClientHelloSniffer()
        }

        // Handshake timeout (Xray-core Timeout.Handshake = 60s) — covers both
        // the SNI-sniff wait and the proxy dial, so a stalled client can't
        // hold a connection open indefinitely before we ever call connect.
        let timer = DispatchWorkItem { [weak self] in
            guard let self, !self.closed else { return }
            if self.isEstablishing {
                let phase = self.sniffer != nil ? "TLS ClientHello sniff" : "proxy dial"
                logger.error("[TCP] Handshake timeout during \(phase): \(self.dstHost):\(self.dstPort)")
                self.abort()
            }
        }
        handshakeTimer = timer
        lwipQueue.asyncAfter(deadline: .now() + TunnelConstants.handshakeTimeout, execute: timer)

        // If we're sniffing, wait for the first ClientHello bytes in
        // `handleReceivedData` before choosing a route. Otherwise commit
        // immediately using the IP-derived configuration.
        if sniffer == nil {
            beginConnecting()
        } else {
            // Safety net: non-TLS protocols where the server speaks first
            // (SSH, SMTP, FTP) never send client bytes of their own accord.
            // If we haven't decided by `sniffDeadline`, commit the IP-based
            // route and proceed.
            let deadline = DispatchWorkItem { [weak self] in
                guard let self, !self.closed, self.sniffer != nil else { return }
                self.sniffer = nil
                self.beginConnecting()
            }
            sniffDeadline = deadline
            lwipQueue.asyncAfter(deadline: .now() + TunnelConstants.sniffDeadline, execute: deadline)
        }
    }

    /// Cancels the sniff deadline timer. Called whenever the sniff phase
    /// resolves (successful SNI, fast reject, cap reached, close, abort).
    private func cancelSniffDeadline() {
        sniffDeadline?.cancel()
        sniffDeadline = nil
    }

    /// Appends to `pendingData` and enforces ``TunnelConstants/tcpMaxPendingDataSize``.
    /// Aborts the connection if the cap would be exceeded and returns `false`
    /// so callers can bail out early.
    @discardableResult
    private func appendPendingData(bytes ptr: UnsafePointer<UInt8>, count: Int) -> Bool {
        if pendingData.count + count > TunnelConstants.tcpMaxPendingDataSize {
            logger.warning("[TCP] pendingData cap exceeded for \(dstHost):\(dstPort) (\(pendingData.count) + \(count) > \(TunnelConstants.tcpMaxPendingDataSize)), aborting")
            abort()
            return false
        }
        pendingData.append(ptr, count: count)
        return true
    }

    /// True while the connection is still establishing — either waiting for
    /// SNI bytes or dialing the proxy. Used by the handshake timer.
    private var isEstablishing: Bool {
        proxyConnecting || sniffer != nil
    }

    // MARK: - lwIP Callbacks (called on lwipQueue)

    /// Handles data received from the local app via lwIP (upload path).
    ///
    /// Appends the segment to the upload pipeline buffer and schedules a pump
    /// (deferred via `lwipQueue.async` so all segments from one
    /// `lwip_bridge_input` batch coalesce into the next pump invocation).
    /// The pump ships a single chunk per `proxyConnection.send` call and
    /// waits for its completion before issuing the next; bytes that arrive
    /// during that window pile up in the buffer and ride out as the next
    /// chunk, preserving the proxy-level byte stream order.
    func handleReceivedData(bytes ptr: UnsafeRawPointer, count: Int) {
        guard !closed, count > 0 else { return }
        activityTimer?.update()

        let bytePtr = ptr.assumingMemoryBound(to: UInt8.self)

        // SNI sniff phase: buffer bytes and feed the sniffer before dialing.
        // The sniffer and appendPendingData both copy eagerly, so a bytesNoCopy
        // wrapper is safe here — the Data never outlives this function.
        if sniffer != nil {
            let data = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: ptr), count: count, deallocator: .none)
            if let state = sniffer?.feed(data) {
                guard appendPendingData(bytes: bytePtr, count: count) else { return }
                switch state {
                case .needMore:
                    return
                case .found(let sni):
                    sniffer = nil
                    cancelSniffDeadline()
                    applySNI(sni)
                    guard !closed else { return }  // rule may have rejected
                    beginConnecting()
                    return
                case .notTLS, .unavailable:
                    sniffer = nil
                    cancelSniffDeadline()
                    beginConnecting()
                    return
                }
            }
        }

        if proxyConnecting {
            _ = appendPendingData(bytes: bytePtr, count: count)
            return
        }

        guard proxyConnection != nil else {
            guard appendPendingData(bytes: bytePtr, count: count) else { return }
            beginConnecting()
            return
        }

        uploadPipeline.buffer.append(bytePtr, count: count)
        schedulePumpIfNeeded()
    }

    /// Schedules a pump on `lwipQueue.async` if one isn't already pending and
    /// the pipeline is idle. The async hop deliberately defers the pump
    /// until after the current synchronous batch of `lwip_bridge_input`
    /// callbacks finishes — this coalesces a burst of TCP segments into
    /// one large send.
    ///
    /// While a send is in flight, scheduling a new pump is a no-op: bytes
    /// keep accumulating in the buffer and the completion's tail call to
    /// ``pumpUploadSends`` ships them as the next chunk. This is what
    /// keeps steady-state sends fat (the buffer fills during the network
    /// round-trip) and avoids fragmenting the stream into per-segment
    /// sends.
    private func schedulePumpIfNeeded() {
        guard !uploadPipeline.isPumpScheduled,
              !uploadPipeline.sendInFlight,
              uploadBufferCount > 0 else { return }
        uploadPipeline.isPumpScheduled = true
        lwipQueue.async { [weak self] in
            self?.pumpUploadSends(fromSchedule: true)
        }
    }

    /// Issues a single `proxyConnection.send` call carrying the head slice
    /// of the pipeline buffer (up to ``TunnelConstants/uploadChunkSize``
    /// bytes), if no send is already in flight. Called from the deferred
    /// async after a batch of incoming bytes (``schedulePumpIfNeeded``)
    /// and synchronously from each completion to drain whatever
    /// accumulated meanwhile.
    ///
    /// Strict single-flight: several proxy transports (Vision over HTTP/2,
    /// gRPC, …) can split one logical `send` internally on flow-control
    /// exhaustion and resume the remainder later. Issuing a second send
    /// while the first's remainder is still pending would let the second
    /// chunk's bytes interleave with the first's tail at the proxy.
    private func pumpUploadSends(fromSchedule: Bool = false) {
        if fromSchedule {
            uploadPipeline.isPumpScheduled = false
        }

        guard !closed, !uploadPipeline.sendInFlight, uploadBufferCount > 0,
              let proxyConnection else { return }

        let take = min(uploadBufferCount, TunnelConstants.uploadChunkSize)
        let chunk = sliceUploadBuffer(take)

        uploadPipeline.sendInFlight = true
        let chunkSize = take

        let completion: (Error?) -> Void = { [weak self] error in
            guard let self else { return }
            self.lwipQueue.async {
                self.uploadPipeline.sendInFlight = false
                guard !self.closed else { return }
                if let error {
                    self.logTransportFailure("Send", error: error)
                    self.abort()
                    return
                }
                // Acknowledge this chunk to lwIP and flush any resulting
                // window update so the local TCP peer can feed us the next
                // batch without an extra output-queue hop.
                self.acknowledgeReceivedBytes(chunkSize)
                // Drain the next chunk synchronously: bytes accumulated
                // during the in-flight window can ship without another
                // async hop, recovering the chained-flush behaviour that
                // keeps per-send chunks fat.
                self.pumpUploadSends()
            }
        }

        proxyConnection.send(data: chunk, completion: completion)
    }

    /// Acknowledges local-app bytes to lwIP once they have been accepted by
    /// the proxy transport. Also flushes the resulting window update packet so
    /// the local TCP peer can resume sending without waiting for the deferred
    /// output callback.
    private func acknowledgeReceivedBytes(_ byteCount: Int) {
        guard byteCount > 0 else { return }
        var remaining = byteCount
        while remaining > 0 {
            let part = UInt16(min(remaining, Int(UInt16.max)))
            remaining -= Int(part)
            lwip_bridge_tcp_recved(pcb, part)
        }
        lwip_bridge_tcp_output(pcb)
        LWIPStack.shared?.flushOutputInline()
    }

    /// Removes and returns a `take`-byte head slice of the pipeline buffer.
    /// Advances ``UploadPipeline/bufferOffset`` for partial slices and lazily
    /// compacts when the dead prefix outgrows the live suffix, matching the
    /// downlink ``pendingWrite`` strategy. Whole-buffer consumption hands off
    /// the existing storage and replaces the buffer with a fresh `Data`, so
    /// the in-flight chunk's backing isn't mutated under it.
    private func sliceUploadBuffer(_ take: Int) -> Data {
        if take == uploadBufferCount {
            let chunk: Data
            if uploadPipeline.bufferOffset == 0 {
                chunk = uploadPipeline.buffer
            } else {
                chunk = uploadPipeline.buffer.subdata(in: uploadPipeline.bufferOffset..<uploadPipeline.buffer.count)
            }
            uploadPipeline.buffer = Data()
            uploadPipeline.bufferOffset = 0
            return chunk
        }

        let start = uploadPipeline.bufferOffset
        let end = start + take
        let chunk = uploadPipeline.buffer.subdata(in: start..<end)
        uploadPipeline.bufferOffset = end
        if uploadPipeline.bufferOffset > uploadPipeline.buffer.count - uploadPipeline.bufferOffset {
            uploadPipeline.buffer.removeSubrange(0..<uploadPipeline.bufferOffset)
            uploadPipeline.bufferOffset = 0
        }
        return chunk
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

        // Client FIN'd before we finished sniffing. If we never received any
        // bytes, there's nothing to forward — drop the connection. Otherwise
        // commit the tentative IP-based route and forward what we have.
        if sniffer != nil {
            sniffer = nil
            cancelSniffDeadline()
            if pendingData.isEmpty {
                close()
                return
            }
            beginConnecting()
        }

        uplinkDone = true
        if downlinkDone {
            close()
        } else {
            activityTimer?.setTimeout(TunnelConstants.downlinkOnlyTimeout)
        }
    }

    /// Surfaces why lwIP tore this connection down. Without this log the
    /// connection simply vanishes from the user's perspective — no send/receive
    /// error fires because the PCB has already been freed by the time
    /// `tcp_err` runs.
    func handleError(err: Int32) {
        let reason = TransportErrorLogger.describeLwIPError(err)
        if err == -15 { // ERR_CLSD — orderly close, not a failure
            logger.debug("[TCP] lwIP closed connection: \(endpointDescription): \(reason)")
        } else if err == -14 { // ERR_RST — always local-app-initiated in TUN mode
            logger.debug("[TCP] lwIP peer reset: \(endpointDescription): \(reason)")
        } else if err == -13, LWIPStack.shared?.isTearingDown == true {
            // ERR_ABRT during a deliberate stack teardown (shutdown/restart/wake).
            // Outside teardown, ERR_ABRT indicates lwIP's own pressure aborts
            // (tcp_kill_prio / tcp_kill_timewait) — those stay at warning below.
            logger.debug("[TCP] lwIP aborted connection (tunnel teardown): \(endpointDescription): \(reason)")
        } else {
            logger.warning("[TCP] lwIP aborted connection: \(endpointDescription): \(reason)")
        }
        closed = true
        releaseProxy()
    }

    private var endpointDescription: String {
        "\(dstHost):\(dstPort)"
    }

    private func logTransportFailure(_ operation: String, error: Error) {
        TransportErrorLogger.log(
            operation: operation,
            endpoint: endpointDescription,
            error: error,
            logger: logger,
            prefix: "[TCP]"
        )
    }

    // MARK: - Route Commit

    /// Kicks off the outbound connection using the currently committed
    /// routing (`configuration`, `bypass`, `dstHost`). Idempotent — no-op
    /// once the connect has started or completed.
    private func beginConnecting() {
        guard !closed, !proxyConnecting, proxyConnection == nil else { return }
        if bypass {
            connectDirect()
        } else {
            connectProxy()
        }
    }

    /// Re-evaluates routing using the hostname extracted from the TLS
    /// ClientHello. Updates `dstHost`, `configuration`, and `bypass` in place
    /// so the subsequent ``beginConnecting()`` sees the SNI-based decision.
    ///
    /// Behavior:
    ///   - Found a matching domain rule: apply it (may switch proxy, flip
    ///     bypass, or reject the connection) and swap `dstHost` to the SNI so
    ///     the new route resolves the name itself.
    ///   - No rule matches: keep the IP-derived `dstHost` and configuration.
    ///     Rewriting to the SNI hostname would force the outbound proxy to
    ///     re-resolve via its own DNS, which can land on a different CDN IP
    ///     than the one the caller already chose (breaks latency tests that
    ///     pre-resolve a specific server, and risks cert/host mismatches).
    ///
    /// Must be called only while in sniff phase (sniffer has just cleared).
    private func applySNI(_ sni: String) {
        guard let stack = LWIPStack.shared else { return }
        let router = stack.domainRouter

        guard let action = router.matchDomain(sni) else {
            // No domain rule — keep the IP-derived route as-is.
            return
        }

        // Rule matched: the sniffed hostname is what drives the new route,
        // so forward the proxy CONNECT to the name rather than the tentative
        // IP.
        dstHost = sni

        switch action {
        case .direct:
            bypass = true
        case .reject:
            logger.debug("[TCP] SNI rejected by routing rule: \(sni) (\(dstHost):\(dstPort))")
            rejectGracefully()
        case .proxy:
            if var resolved = router.resolveConfiguration(action: action) {
                // Preserve the ambient chain from the default configuration
                // if the rule-targeted configuration didn't specify one.
                if let defaultChain = configuration.chain,
                   !defaultChain.isEmpty,
                   resolved.chain == nil {
                    resolved = resolved.withChain(defaultChain)
                }
                configuration = resolved
            } else {
                logger.warning("[TCP] SNI routing configuration not found for \(sni)")
            }
            bypass = stack.shouldBypass(host: sni)
        }
    }

    // MARK: - Direct Connection (bypass)

    private func connectDirect() {
        guard !proxyConnecting && proxyConnection == nil && !closed else { return }
        proxyConnecting = true

        let initialData = pendingData.isEmpty ? nil : pendingData
        if initialData != nil {
            pendingData.removeAll(keepingCapacity: true)
        }

        let transport = RawTCPSocket()
        let connection = DirectProxyConnection(connection: transport)
        self.proxyConnection = connection
        transport.connect(host: dstHost, port: dstPort) { [weak self] error in
            guard let self else { return }

            self.lwipQueue.async {
                self.proxyConnecting = false
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
                    self.uploadPipeline.buffer.append(initialData)
                }
                if !self.pendingData.isEmpty {
                    self.uploadPipeline.buffer.append(self.pendingData)
                    self.pendingData.removeAll(keepingCapacity: true)
                }
                self.pumpUploadSends()
                self.tryArmReceive()
            }
        }
    }

    // MARK: - Proxy Connection

    private func connectProxy() {
        guard !proxyConnecting && proxyConnection == nil && !closed else { return }
        proxyConnecting = true

        // If the protocol can accept the caller's first bytes before connect
        // completion (VLESS handshake payload, Sudoku early send), extract
        // pendingData into initialData here.
        // Otherwise leave pendingData intact so the post-connect send path
        // below forwards it — ``ProxyClient.connectWithCommand`` drops the
        // `initialData` argument for those protocols.
        let initialData: Data?
        if configuration.outboundProtocol.handshakeCarriesInitialData {
            initialData = pendingData.isEmpty ? nil : pendingData
            if initialData != nil {
                pendingData.removeAll(keepingCapacity: true)
            }
        } else {
            initialData = nil
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

                    if let initialData {
                        // ProxyClient reports success only after VLESS
                        // handshake-carried initialData has been accepted.
                        self.acknowledgeReceivedBytes(initialData.count)
                    }
                    if !self.pendingData.isEmpty {
                        self.uploadPipeline.buffer.append(self.pendingData)
                        self.pendingData.removeAll(keepingCapacity: true)
                    }
                    self.pumpUploadSends()
                    self.tryArmReceive()

                case .failure(let error):
                    self.logTransportFailure("Connect", error: error)
                    self.abort()
                }
            }
        }
    }

    // MARK: - Proxy Receive Loop

    /// Issues the next proxy receive if the downlink backlog is below the
    /// low-water mark and no receive is already in flight.
    ///
    /// Overlapping the next receive with the ongoing drain keeps the lwIP
    /// send buffer saturated: by the time a client ACK frees space, a fresh
    /// chunk is already queued in `pendingWrite` ready to push. Without this
    /// overlap, a big receive (e.g. a speed-test server pushing >1 MB per
    /// read) forces stop-and-wait — the proxy socket's receive window stays
    /// closed for the entire drain, and upstream throttles.
    ///
    /// Backpressure still applies: when `pendingWrite.count` is at or above
    /// `drainLowWaterMark`, this is a no-op, so receives naturally pause
    /// whenever lwIP can't keep up.
    private func tryArmReceive() {
        guard !closed,
              !receiveInFlight,
              pendingWriteCount < TunnelConstants.drainLowWaterMark,
              let connection = proxyConnection else { return }

        receiveInFlight = true
        connection.receive { [weak self] data, error in
            guard let self else { return }

            self.lwipQueue.async {
                self.receiveInFlight = false
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

    /// Appends data received from the proxy onto the downlink backlog, then
    /// drains as much as lwIP will accept. All order-preservation lives in
    /// `pendingWrite`, so a concurrently prefetched receive can land without
    /// racing ahead of the chunk currently being drained.
    private func writeToLWIP(_ data: Data) {
        guard !closed, !data.isEmpty else { return }
        pendingWrite.append(data)
        drainPendingWrite()
    }

    /// Drains ``pendingWrite`` into lwIP's TCP send buffer and, on progress,
    /// arms the next proxy receive if we've dropped below the low-water mark.
    ///
    /// Called from ``handleSent(len:)`` on every client ACK, from
    /// ``writeToLWIP(_:)`` after new proxy data is appended, and from a
    /// 250 ms fallback timer when `tcp_write` couldn't place any bytes (snd_buf
    /// full / zero window). That fallback is rare in practice — `handleSent`
    /// drives nearly all progress — but bounds recovery time if no ACKs arrive.
    private func drainPendingWrite() {
        guard !closed else { return }

        let live = pendingWriteCount
        if live > 0 {
            let head = pendingWriteOffset
            let written = pendingWrite.withUnsafeBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return 0 }
                let n = feedLWIP(base + head, count: live, retryOnEmpty: true)
                if n == -1 {
                    let sndbuf = Int(lwip_bridge_tcp_sndbuf(self.pcb))
                    let queuelen = Int(lwip_bridge_tcp_snd_queuelen(self.pcb))
                    logger.error("[TCP] tcp_write fatal: \(self.dstHost):\(self.dstPort) (pending=\(live), sndbuf=\(sndbuf), queuelen=\(queuelen))")
                    self.abort()
                    return 0
                }
                return n
            }

            guard !closed else { return }

            if written > 0 {
                pendingWriteOffset += written
                if pendingWriteOffset >= pendingWrite.count {
                    // Fully drained — reset to keep the backing allocation
                    // and clear both ends in one O(1) step.
                    pendingWrite.removeAll(keepingCapacity: true)
                    pendingWriteOffset = 0
                } else if pendingWriteOffset > pendingWrite.count - pendingWriteOffset {
                    // Dead prefix larger than live suffix: compact now so the
                    // buffer never balloons past ~2× the live backlog.
                    pendingWrite.removeSubrange(0..<pendingWriteOffset)
                    pendingWriteOffset = 0
                }
                lwip_bridge_tcp_output(pcb)
                LWIPStack.shared?.flushOutputInline()
            } else {
                // Nothing drained (ERR_MEM / zero window) — schedule a delayed
                // retry. Skip `tryArmReceive` on purpose: piling more upstream
                // bytes onto a stalled connection only grows `pendingWrite`.
                // Once the retry makes progress, the tail call rearms.
                lwipQueue.asyncAfter(deadline: .now() + .milliseconds(TunnelConstants.drainRetryDelayMs)) { [weak self] in
                    guard let self, !self.closed else { return }
                    self.drainPendingWrite()
                }
                return
            }
        }

        // Made progress (or nothing was pending): prefetch the next chunk if
        // the backlog is below the low-water mark.
        tryArmReceive()
    }

    // MARK: - Close / Abort

    /// Best-effort flush of pending data into lwIP send buffer before close.
    /// Data written here will be delivered before the FIN segment.
    private func flushPendingToLWIP() {
        let live = pendingWriteCount
        guard live > 0 else { return }

        let head = pendingWriteOffset
        let written = pendingWrite.withUnsafeBytes { buffer -> Int in
            guard let base = buffer.baseAddress else { return 0 }
            return max(feedLWIP(base + head, count: live), 0)  // treat fatal as 0 (best-effort)
        }

        if written > 0 {
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

    /// Tears the connection down with a clean FIN instead of a RST.
    ///
    /// `tcp_close` in lwIP downgrades to RST whenever the receive window is
    /// below `TCP_WND_MAX` — i.e. when bytes were delivered via `tcp_recv_cb`
    /// but never acknowledged via `tcp_recved`. The sniffed ClientHello in
    /// `pendingData` is exactly that: received but unacknowledged because we
    /// never forwarded it upstream. A mid-handshake RST is widely interpreted
    /// by TLS stacks as a transient failure, which drives browsers and HTTP
    /// clients to retry aggressively — defeating the point of the reject
    /// rule. Advancing the window first lets `close()` send a real FIN, which
    /// clients treat as a deliberate peer close and don't retry.
    private func rejectGracefully() {
        guard !closed else { return }
        var remaining = pendingData.count
        while remaining > 0 {
            let chunk = UInt16(min(remaining, Int(UInt16.max)))
            remaining -= Int(chunk)
            lwip_bridge_tcp_recved(pcb, chunk)
        }
        close()
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
        sniffDeadline?.cancel()
        sniffDeadline = nil
        sniffer = nil
        activityTimer?.cancel()
        activityTimer = nil
        let connection = proxyConnection
        let client = proxyClient
        proxyConnection = nil
        proxyClient = nil
        proxyConnecting = false
        pendingData = Data()
        pendingWrite = Data()
        pendingWriteOffset = 0
        uploadPipeline = UploadPipeline()
        connection?.cancel()
        client?.cancel()
    }

    deinit {
        proxyConnection?.cancel()
        proxyClient?.cancel()
    }
}
