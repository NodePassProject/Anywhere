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
    private var pendingWrite = Data()

    /// True from the moment `tryArmReceive` dispatches a proxy receive until
    /// its completion runs on `lwipQueue`. Guarantees at most one outstanding
    /// receive at a time (the proxy transports require serial receives).
    private var receiveInFlight = false

    // MARK: Upload Coalescing

    /// Segments from lwIP callbacks within one `lwip_bridge_input` batch,
    /// accumulated and flushed as a single encrypted chunk via `lwipQueue.async`.
    /// Reduces AES-GCM operations from 2×N (per-segment) to 2×ceil(total/16383).
    ///
    /// Invariants:
    /// - `recvLen == buffer.count` at all times outside `flushUploadBuffer`.
    /// - `isScheduled` implies an async flush is queued; cleared at the start of `flushUploadBuffer`.
    /// - `isFlushInFlight` is true from the `proxyConnection.send` call until its completion runs.
    /// - New scheduled flushes are only enqueued when neither flag is set; the in-flight completion
    ///   chains a follow-up flush to preserve order.
    private struct UploadCoalesceState {
        var buffer = Data()
        var recvLen: Int = 0
        var isScheduled = false
        var isFlushInFlight = false
    }
    private var uploadCoalesce = UploadCoalesceState()

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
    private func appendPendingData(_ data: Data) -> Bool {
        if pendingData.count + data.count > TunnelConstants.tcpMaxPendingDataSize {
            logger.warning("[TCP] pendingData cap exceeded for \(dstHost):\(dstPort) (\(pendingData.count) + \(data.count) > \(TunnelConstants.tcpMaxPendingDataSize)), aborting")
            abort()
            return false
        }
        pendingData.append(data)
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

        // SNI sniff phase: buffer bytes and feed the sniffer before dialing.
        // Once a terminal state is reached we re-evaluate routing (if SNI
        // was found) and then kick off the proxy/direct connect.
        if let state = sniffer?.feed(data) {
            guard appendPendingData(data) else { return }
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

        if proxyConnecting {
            _ = appendPendingData(data)
            return
        }

        guard proxyConnection != nil else {
            guard appendPendingData(data) else { return }
            beginConnecting()
            return
        }

        // Buffer would overflow — flush accumulated data first to
        // maintain stream ordering, then fall back to per-segment sends.
        if uploadCoalesce.recvLen + data.count > TunnelConstants.tcpMaxCoalesceSize {
            if uploadCoalesce.recvLen > 0 && !uploadCoalesce.isFlushInFlight {
                flushUploadBuffer()
            }
            if uploadCoalesce.recvLen == 0 {
                // Buffer is empty (was empty or just flushed) — safe to
                // send per-segment for backpressure without reordering.
                sendSegmentDirect(data)
            } else {
                // A flush is in-flight and the buffer has unsent data.
                // Coalesce to preserve ordering; the chain-flush on
                // completion will send it after the in-flight data.
                uploadCoalesce.buffer.append(data)
                uploadCoalesce.recvLen += data.count
            }
            return
        }

        // Always coalesce — even while a flush is in-flight. This matches
        // Xray-core's buffered-pipe design where data accumulates during the
        // scMinPostsIntervalMs sleep and is sent as one large POST.
        // Without this, each individual TCP segment (~1-2 KB) would become its
        // own POST request during the delay, causing massive HTTP overhead.
        uploadCoalesce.buffer.append(data)
        uploadCoalesce.recvLen += data.count

        // Schedule flush only when no send is in-flight (data accumulated
        // during an in-flight send will be flushed when it completes).
        if !uploadCoalesce.isFlushInFlight && !uploadCoalesce.isScheduled {
            uploadCoalesce.isScheduled = true
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
        proxyConnection?.send(data: data, completion: completion)
    }

    /// Flushes the coalesced upload buffer — encrypts and sends all accumulated
    /// segments as a single chunk, then acknowledges to lwIP on completion.
    private func flushUploadBuffer() {
        uploadCoalesce.isScheduled = false
        guard !closed else {
            uploadCoalesce.buffer.removeAll()
            uploadCoalesce.recvLen = 0
            return
        }

        let data = uploadCoalesce.buffer
        let recvLen = uploadCoalesce.recvLen
        uploadCoalesce.buffer = Data()
        uploadCoalesce.recvLen = 0

        guard !data.isEmpty else { return }

        uploadCoalesce.isFlushInFlight = true

        let completion: (Error?) -> Void = { [weak self] error in
            guard let self else { return }
            self.lwipQueue.async {
                self.uploadCoalesce.isFlushInFlight = false
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
                if self.uploadCoalesce.recvLen > 0 {
                    self.flushUploadBuffer()
                }
            }
        }

        proxyConnection?.send(data: data, completion: completion)
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
        } else if let interruption = LWIPStack.shared?.recentTunnelInterruptionContext() {
            logger.warning("[TCP] lwIP aborted after \(interruption.summary): \(endpointDescription): \(reason)")
        } else if err == -14 { // ERR_RST — always local-app-initiated in TUN mode
            logger.debug("[TCP] lwIP peer reset: \(endpointDescription): \(reason)")
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
            logger.info("[TCP] SNI rejected by routing rule: \(sni) (\(dstHost):\(dstPort))")
            abort()
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
                    let totalReceiveLength = initialData.count
                    connection.send(data: initialData) { [weak self] error in
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
                    connection.send(data: dataToSend) { [weak self] error in
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

                self.tryArmReceive()
            }
        }
    }

    // MARK: - Proxy Connection

    private func connectProxy() {
        guard !proxyConnecting && proxyConnection == nil && !closed else { return }
        proxyConnecting = true

        // If the protocol can embed the caller's first bytes in its handshake
        // (VLESS + its transports), extract pendingData into initialData here.
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
              pendingWrite.count < TunnelConstants.drainLowWaterMark,
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

        if !pendingWrite.isEmpty {
            let count = pendingWrite.count
            let offset = pendingWrite.withUnsafeBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return 0 }
                let written = feedLWIP(base, count: count, retryOnEmpty: true)
                if written == -1 {
                    let sndbuf = Int(lwip_bridge_tcp_sndbuf(self.pcb))
                    let queuelen = Int(lwip_bridge_tcp_snd_queuelen(self.pcb))
                    logger.error("[TCP] tcp_write fatal: \(self.dstHost):\(self.dstPort) (pending=\(count), sndbuf=\(sndbuf), queuelen=\(queuelen))")
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
            } else {
                // Nothing drained (ERR_MEM / zero window) — schedule a delayed
                // retry. Skip `tryArmReceive` on purpose: piling more upstream
                // bytes onto a stalled connection only grows `pendingWrite`.
                // Once the retry makes progress, the tail call rearms.
                let sndbuf = Int(lwip_bridge_tcp_sndbuf(pcb))
                let queuelen = Int(lwip_bridge_tcp_snd_queuelen(pcb))
                let outputBacklog = LWIPStack.shared?.outputPackets.count ?? -1
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
        uploadCoalesce = UploadCoalesceState()
        connection?.cancel()
        client?.cancel()
    }

    deinit {
        proxyConnection?.cancel()
        proxyClient?.cancel()
    }
}
