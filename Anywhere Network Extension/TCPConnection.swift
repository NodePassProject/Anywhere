//
//  TCPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

private let logger = AnywhereLogger(category: "TCPConnection")

private struct HandshakeTimeoutError: LocalizedError {
    let phase: String
    var errorDescription: String? { "Handshake timed out during \(phase)" }
}

private struct LWIPWriteFatalError: LocalizedError {
    let pending: Int
    let sndbuf: Int
    let queuelen: Int
    var errorDescription: String? {
        "tcp_write fatal (pending=\(pending), sndbuf=\(sndbuf), queuelen=\(queuelen))"
    }
}

class TCPConnection {
    let pcb: UnsafeMutableRawPointer
    let dstPort: UInt16
    let lwipQueue: DispatchQueue

    /// Dial destination, fixed at accept time; an SNI re-route deliberately
    /// keeps the caller's own DNS choice.
    private(set) var dstHost: String

    /// Routing configuration; an SNI re-match may swap it to a different proxy.
    private(set) var configuration: ProxyConfiguration

    private var proxyClient: ProxyClient?
    private var proxyConnection: ProxyConnection?
    private var proxyConnecting = false

    /// Committed routing identity for traffic accounting and the dial path; an SNI re-match can change it.
    private var routeTarget: RouteTarget

    private var bypass: Bool {
        if case .direct = routeTarget { return true }
        return false
    }

    private var pendingData = Data()
    private var closed = false

    // MARK: MITM

    private var mitmEnabled = false
    /// SNI captured at MITM-decision time; inner TLS server name and rewrite-match host.
    private var mitmSNI: String?
    private var mitmSession: MITMSession?

    // MARK: SNI Sniffing

    /// Non-nil during the sniff phase; inbound bytes buffer in `pendingData` until the route commits.
    private var sniffer: TLSClientHelloSniffer?

    // MARK: Backpressure State

    /// Downlink backlog awaiting lwIP's send buffer. `[0, pendingWriteOffset)` is already
    /// written; compaction is deferred until the dead prefix outgrows the live suffix.
    private var pendingWrite = Data()
    private var pendingWriteOffset = 0

    /// Bytes still waiting to be handed to lwIP.
    private var pendingWriteCount: Int {
        pendingWrite.count - pendingWriteOffset
    }

    /// At most one outstanding proxy receive; the transports require serial receives.
    private var receiveInFlight = false

    // MARK: Upload Pipeline
    //
    // Single-flight is mandatory: transports can split a logical send and resume it later,
    // so two in-flight chunks would interleave; deferred tcp_recved makes TCP_WND the cap.
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
    /// Commits the IP-based route if the sniff doesn't resolve in time.
    private var sniffDeadline: DispatchWorkItem?
    private var uplinkDone = false
    private var downlinkDone = false

    /// Logs this connection's terminal failure at most once.
    private let failureReporter = ConnectionFailureReporter(prefix: "[TCP]", logger: logger)

    // MARK: Lifecycle

    init(pcb: UnsafeMutableRawPointer, dstHost: String, dstPort: UInt16,
         configuration: ProxyConfiguration, routeTarget: RouteTarget,
         sniffSNI: Bool = false,
         lwipQueue: DispatchQueue) {
        self.pcb = pcb
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.configuration = configuration
        self.lwipQueue = lwipQueue
        self.routeTarget = routeTarget
        if sniffSNI {
            self.sniffer = TLSClientHelloSniffer()
        }

        // Covers both the sniff wait and the proxy dial so a stalled client can't hold the connection open.
        let timer = DispatchWorkItem { [weak self] in
            guard let self, !self.closed else { return }
            if self.isEstablishing {
                let phase = self.sniffer != nil ? "TLS ClientHello sniff" : "proxy dial"
                self.failureReporter.report(
                    operation: "Handshake",
                    endpoint: self.endpointDescription,
                    error: HandshakeTimeoutError(phase: phase)
                )
                self.abort()
            }
        }
        handshakeTimer = timer
        lwipQueue.asyncAfter(deadline: .now() + TunnelConstants.handshakeTimeout, execute: timer)

        if sniffer == nil {
            beginConnecting()
        } else {
            // Server-speaks-first protocols (SSH, SMTP, FTP) never send client
            // bytes; commit the IP-based route at the deadline.
            let deadline = DispatchWorkItem { [weak self] in
                guard let self, !self.closed, self.sniffer != nil else { return }
                self.sniffer = nil
                self.beginConnecting()
            }
            sniffDeadline = deadline
            lwipQueue.asyncAfter(deadline: .now() + TunnelConstants.sniffDeadline, execute: deadline)
        }
    }

    private func cancelSniffDeadline() {
        sniffDeadline?.cancel()
        sniffDeadline = nil
    }

    /// Appends to `pendingData`; aborts and returns `false` if the cap would be exceeded.
    @discardableResult
    private func appendPendingData(bytes ptr: UnsafePointer<UInt8>, count: Int) -> Bool {
        if pendingData.count + count > TunnelConstants.tcpMaxPendingDataSize {
            logger.warning("[TCP] pendingData cap exceeded for \(dstHost):\(dstPort) (\(pendingData.count) + \(count) > \(TunnelConstants.tcpMaxPendingDataSize)), aborting")
            PerformanceMonitor.event(.pendingDataCapAbort)
            // The warning above already covers this abort; suppress duplicates.
            failureReporter.markReported()
            abort()
            return false
        }
        pendingData.append(ptr, count: count)
        return true
    }

    /// Still waiting for SNI bytes or dialing the proxy; drives the handshake timer.
    private var isEstablishing: Bool {
        proxyConnecting || sniffer != nil
    }

    // MARK: - lwIP Callbacks (called on lwipQueue)

    /// Upload path: data from the local app via lwIP.
    func handleReceivedData(bytes ptr: UnsafeRawPointer, count: Int) {
        guard !closed, count > 0 else { return }
        activityTimer?.update()

        let bytePtr = ptr.assumingMemoryBound(to: UInt8.self)

        // The sniffer and appendPendingData both copy eagerly, so a bytesNoCopy
        // wrapper is safe — the Data never outlives this function.
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

        // MITM: client bytes feed the inner TLS leg; the upload pipeline stays untouched.
        if let mitmSession {
            let chunk = Data(bytes: bytePtr, count: count)
            // Count client→inner-leg bytes as uplink activity. A long upload with no server response
            // yet (a large POST/PUT, or a slow upstream) produces no downlink to refresh the idle
            // timer, so without this it looks idle and is torn down mid-stream — the non-MITM upload
            // path refreshes the timer on every accepted chunk for the same reason.
            activityTimer?.update()
            // Ack to lwIP up-front; MITMSession owns inner-leg flow control.
            acknowledgeReceivedBytes(count)
            mitmSession.feedClientBytes(chunk)
            return
        }

        guard proxyConnection != nil else {
            guard appendPendingData(bytes: bytePtr, count: count) else { return }
            beginConnecting()
            return
        }

        uploadPipeline.buffer.append(bytePtr, count: count)
        PerformanceMonitor.gauge(.tcpUploadBacklog, uploadBufferCount)
        schedulePumpIfNeeded()
    }

    /// The async hop coalesces a synchronous burst of lwIP callbacks into one large
    /// send; while a send is in flight, the completion's tail call ships what accumulated.
    private func schedulePumpIfNeeded() {
        guard !uploadPipeline.isPumpScheduled,
              !uploadPipeline.sendInFlight,
              uploadBufferCount > 0 else { return }
        uploadPipeline.isPumpScheduled = true
        lwipQueue.async { [weak self] in
            self?.pumpUploadSends(fromSchedule: true)
        }
    }

    /// Issues one `proxyConnection.send` with the head slice of the pipeline buffer; strict single-flight.
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
                    self.reportFailure("Send", error: error)
                    self.abort()
                    return
                }
                // Count proxy-side accepts as uplink activity; a long upload that
                // backpressures the app would otherwise look idle and close mid-stream.
                self.activityTimer?.update()
                self.acknowledgeReceivedBytes(chunkSize)
                // Drain synchronously so bytes accumulated in-flight ship without another hop.
                self.pumpUploadSends()
            }
        }

        proxyConnection.send(data: chunk, completion: completion)
    }

    /// Acks local-app bytes to lwIP once the proxy leg accepted them, then
    /// flushes the window update so the peer can resume sending promptly.
    private func acknowledgeReceivedBytes(_ byteCount: Int) {
        guard byteCount > 0 else { return }
        // Single uplink tally point; rejects call tcp_recved directly, uncounted.
        TunnelStack.shared?.addBytesOut(Int64(byteCount), target: routeTarget)
        var remaining = byteCount
        while remaining > 0 {
            let part = UInt16(min(remaining, Int(UInt16.max)))
            remaining -= Int(part)
            lwip_bridge_tcp_recved(pcb, part)
        }
        // tcp_output synchronously fires the output callback and kicks the drain loop.
        lwip_bridge_tcp_output(pcb)
    }

    /// Removes and returns the `take`-byte head slice; whole-buffer consumption hands
    /// off the storage so the in-flight chunk's backing isn't mutated under it.
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

    /// Client ACK freed lwIP send-buffer space; drain more downlink backlog.
    func handleSent(len: UInt16) {
        guard !closed else { return }
        drainPendingWrite()
    }

    func handleRemoteClose() {
        guard !closed else { return }

        // Client FIN'd mid-sniff: nothing buffered → drop; otherwise commit
        // the IP-based route and forward what we have.
        if sniffer != nil {
            sniffer = nil
            cancelSniffDeadline()
            if pendingData.isEmpty {
                close()
                return
            }
            beginConnecting()
        }

        // Propagate the orderly close through the inner TLS leg.
        mitmSession?.clientDidClose()

        uplinkDone = true
        if downlinkDone {
            close()
        } else {
            activityTimer?.setTimeout(TunnelConstants.downlinkOnlyTimeout)
        }
    }

    /// Logs why lwIP tore this connection down — by the time `tcp_err` runs
    /// the PCB is already freed, so no other error path fires.
    func handleError(err: Int32) {
        let reason = TransportErrorLogger.describeLwIPError(err)
        if err == -15 { // ERR_CLSD — orderly close, not a failure
            logger.debug("[TCP] lwIP closed connection: \(endpointDescription): \(reason)")
        } else if err == -14 { // ERR_RST — always local-app-initiated in TUN mode
            logger.debug("[TCP] lwIP peer reset: \(endpointDescription): \(reason)")
        } else if err == -13, TunnelStack.shared?.isTearingDown == true {
            // ERR_ABRT during deliberate teardown; otherwise it's an lwIP pressure abort and warns below.
            logger.debug("[TCP] lwIP aborted connection (tunnel teardown): \(endpointDescription): \(reason)")
        } else {
            logger.warning("[TCP] lwIP aborted connection: \(endpointDescription): \(reason)")
        }
        // Suppress spurious error logs as in-flight callbacks unwind.
        failureReporter.markReported()
        closed = true
        releaseProxy()
    }

    private var endpointDescription: String {
        "\(dstHost):\(dstPort)"
    }

    private func reportFailure(_ operation: String, error: Error) {
        failureReporter.report(operation: operation, endpoint: endpointDescription, error: error)
    }

    /// Terminal handler for a failed dial; restores `bufferedClientData` ahead of
    /// later arrivals so the whole unacknowledged run is covered.
    private func handleConnectFailure(_ error: Error, bufferedClientData: Data?) {
        reportFailure("Connect", error: error)
        guard case SocketError.resolutionFailed = error else {
            abort()
            return
        }
        if let bufferedClientData, !bufferedClientData.isEmpty {
            pendingData = bufferedClientData + pendingData
        }
        if bufferedBytesAreTLSHandshake() {
            rejectWithTLSAlert()
        } else {
            rejectGracefully()
        }
    }

    /// True when `pendingData` starts with a TLS handshake record (0x16, 0x03);
    /// iterates rather than subscripts so it is index-offset safe on sliced `Data`.
    private func bufferedBytesAreTLSHandshake() -> Bool {
        var iterator = pendingData.makeIterator()
        return iterator.next() == 0x16 && iterator.next() == 0x03
    }

    // MARK: - Route Commit

    /// Kicks off the outbound connection on the committed route. Idempotent.
    private func beginConnecting() {
        guard !closed, !proxyConnecting, proxyConnection == nil, mitmSession == nil else { return }
        // MITM defers the dial into the session: a rewrite may change the host,
        // and a 302 / reject answers without dialing at all.
        if mitmEnabled {
            startMITMSession()
            return
        }
        if bypass {
            connectDirect()
        } else {
            connectProxy()
        }
    }

    /// Re-evaluates routing from the sniffed SNI; call only after the sniffer is cleared.
    /// `dstHost` is never rewritten — the caller's own DNS resolution is authoritative.
    private func applySNI(_ sni: String) {
        guard let stack = TunnelStack.shared else { return }
        let router = stack.domainRouter

        // MITM (intercept TLS?) is decided independently of routing (which leg).
        if stack.mitmEnabled, stack.mitmPolicy.matches(sni) {
            mitmEnabled = true
            mitmSNI = sni
        }

        guard let action = router.matchDomain(sni) else {
            // No domain rule — keep the IP-derived route.
            return
        }

        switch action {
        case .direct:
            routeTarget = .direct
            stack.requestLog.record(proto: "TCP", host: sni, port: dstPort, routeTarget: .direct)
        case .reject:
            routeTarget = .reject
            stack.requestLog.record(proto: "TCP", host: sni, port: dstPort, routeTarget: .reject)
            logger.debug("[TCP] SNI rejected by routing rule: \(sni) (\(dstHost):\(dstPort))")
            rejectWithTLSAlert()
        case .proxy(let id):
            // The domain rule wins over any IP-CIDR route set at accept time.
            routeTarget = .proxy(id)
            if let resolved = router.resolveConfiguration(action: action) {
                configuration = resolved
            } else {
                logger.warning("[TCP] SNI routing configuration not found for \(sni)")
            }
            stack.requestLog.record(proto: "TCP", host: sni, port: dstPort, routeTarget: .proxy(id))
        }
    }

    // MARK: - Direct Connection (bypass)

    private func connectDirect() {
        guard !proxyConnecting && proxyConnection == nil && !closed else { return }
        proxyConnecting = true

        let initialData: Data? = pendingData.isEmpty ? nil : pendingData
        if initialData != nil {
            pendingData.removeAll(keepingCapacity: true)
        }

        let transport = RawTCPSocket()
        // Direct/bypass — not a proxied connection, so exclude it from the Dial stat.
        transport.dialTimer.enabled = false
        let connection = DirectProxyConnection(connection: transport)
        self.proxyConnection = connection
        transport.connect(host: dstHost, port: dstPort) { [weak self] error in
            guard let self else { return }

            self.lwipQueue.async {
                self.proxyConnecting = false
                guard !self.closed else { return }

                if let error {
                    self.handleConnectFailure(error, bufferedClientData: initialData)
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

        // Protocols whose handshake carries a payload take pendingData as
        // initialData so the first bytes ride the handshake.
        let initialData: Data?
        if configuration.outboundProtocol.handshakeCarriesInitialData {
            initialData = pendingData.isEmpty ? nil : pendingData
            if initialData != nil {
                pendingData.removeAll(keepingCapacity: true)
            }
        } else {
            initialData = nil
        }
        
        let client = ProxyClient(
            configuration: configuration,
            isDefaultProxy: TunnelStack.shared?.isDefaultConfiguration(configuration.id) ?? false
        )
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
                        // Connect success implies handshake-carried initialData was accepted.
                        self.acknowledgeReceivedBytes(initialData.count)
                    }
                    if !self.pendingData.isEmpty {
                        self.uploadPipeline.buffer.append(self.pendingData)
                        self.pendingData.removeAll(keepingCapacity: true)
                    }
                    self.pumpUploadSends()
                    self.tryArmReceive()

                case .failure(let error):
                    self.handleConnectFailure(error, bufferedClientData: initialData)
                }
            }
        }
    }

    // MARK: - MITM Session

    /// Starts a deferred-dial MITM session: the inner TLS handshake runs first and
    /// the upstream dial waits until the first request resolves the destination.
    private func startMITMSession() {
        guard let stack = TunnelStack.shared else { abort(); return }
        let sni = mitmSNI ?? dstHost

        let cache: MITMLeafCertCache
        if let existing = stack.mitmLeafCache {
            cache = existing
        } else {
            do {
                let made = try MITMLeafCertCache(store: stack.mitmCertificateStore)
                stack.mitmLeafCache = made
                cache = made
            } catch {
                reportFailure("MITM leaf cache", error: error)
                abort()
                return
            }
        }

        handshakeTimer?.cancel()
        handshakeTimer = nil
        activityTimer = ActivityTimer(
            queue: lwipQueue,
            timeout: TunnelConstants.connectionIdleTimeout
        ) { [weak self] in
            guard let self, !self.closed else { return }
            self.close()
        }

        let initialClientHello = pendingData
        pendingData.removeAll(keepingCapacity: true)

        // Pass the SNI, not the IP-derived host, so rewrite rules match by hostname.
        let session = MITMSession(
            dstHost: sni,
            dstPort: dstPort,
            clientHello: initialClientHello,
            leafCache: cache,
            policy: stack.mitmPolicy,
            dialer: makeMITMDialer(),
            lwipQueue: lwipQueue
        )
        // Inner-leg downlink: inner TLS server output goes straight to lwIP.
        session.onSendToClient = { [weak self] data, completion in
            guard let self else { completion?(SocketError.notConnected); return }
            self.lwipQueue.async {
                if self.closed {
                    completion?(SocketError.notConnected)
                    return
                }
                self.activityTimer?.update()
                self.writeToLWIP(data)
                completion?(nil)
            }
        }
        session.onTeardown = { [weak self] error in
            guard let self else { return }
            self.lwipQueue.async {
                guard !self.closed else { return }
                if let error {
                    self.reportFailure("MITM", error: error)
                    self.abort()
                } else {
                    self.close()
                }
            }
        }
        mitmSession = session

        // Ack the consumed ClientHello so the client can keep sending.
        if !initialClientHello.isEmpty {
            acknowledgeReceivedBytes(initialClientHello.count)
        }

        session.start(sni: sni)
    }

    /// Builds the dialer for the session's deferred dial on the committed route; the
    /// session owns the resulting connection, and completion runs on `lwipQueue`.
    private func makeMITMDialer() -> MITMDialer {
        return { [weak self] host, port, completion in
            guard let self else { completion(.failure(SocketError.notConnected)); return }
            self.lwipQueue.async {
                guard !self.closed else { completion(.failure(SocketError.notConnected)); return }
                if self.bypass {
                    let transport = RawTCPSocket()
                    // Direct/bypass — not a proxied connection, exclude from Dial.
                    transport.dialTimer.enabled = false
                    let connection = DirectProxyConnection(connection: transport)
                    transport.connect(host: host, port: port) { [weak self] error in
                        guard let self else {
                            connection.cancel()
                            completion(.failure(error ?? SocketError.notConnected))
                            return
                        }
                        self.lwipQueue.async {
                            if let error {
                                // onTeardown reports the failure; don't double-report.
                                completion(.failure(error))
                            } else {
                                completion(.success(MITMDialResult(connection: connection, proxyClient: nil)))
                            }
                        }
                    }
                } else {
                    let client = ProxyClient(
                        configuration: self.configuration,
                        isDefaultProxy: TunnelStack.shared?.isDefaultConfiguration(self.configuration.id) ?? false
                    )
                    client.connect(to: host, port: port, initialData: nil) { [weak self] result in
                        guard let self else {
                            if case .success(let conn) = result { conn.cancel() }
                            client.cancel()
                            completion(.failure(SocketError.notConnected))
                            return
                        }
                        self.lwipQueue.async {
                            switch result {
                            case .success(let conn):
                                completion(.success(MITMDialResult(connection: conn, proxyClient: client)))
                            case .failure(let error):
                                // onTeardown reports the failure; don't double-report.
                                completion(.failure(error))
                            }
                        }
                    }
                }
            }
        }
    }

    // MARK: - Proxy Receive Loop

    /// Issues the next proxy receive when the backlog is below `drainLowWaterMark`
    /// and none is in flight; overlapping receive with drain avoids stop-and-wait.
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
                    self.reportFailure("Receive", error: error)
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

    /// Writes as much as lwIP's send buffer accepts; returns bytes written, or -1 on a
    /// fatal tcp_write error. `retryOnEmpty` flushes a full buffer once so ACKs free snd_buf.
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

    /// Appends proxy data to the downlink backlog and drains what lwIP accepts;
    /// ordering lives in `pendingWrite`, so a prefetched receive can't race the drain.
    private func writeToLWIP(_ data: Data) {
        guard !closed, !data.isEmpty else { return }
        TunnelStack.shared?.addBytesIn(Int64(data.count), target: routeTarget)
        pendingWrite.append(data)
        PerformanceMonitor.gauge(.tcpDownlinkBacklog, pendingWriteCount, highWater: TunnelConstants.drainLowWaterMark)
        drainPendingWrite()
    }

    /// Drains `pendingWrite` into lwIP and re-arms the proxy receive on progress;
    /// driven by client ACKs, with a fallback retry timer when nothing was placed.
    private func drainPendingWrite() {
        guard !closed else { return }

        let live = pendingWriteCount
        if live > 0 {
            let head = pendingWriteOffset
            let written = pendingWrite.withUnsafeBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return 0 }
                let n = feedLWIP(base + head, count: live, retryOnEmpty: true)
                if n == -1 {
                    PerformanceMonitor.event(.lwipWriteFatal)
                    let sndbuf = Int(lwip_bridge_tcp_sndbuf(self.pcb))
                    let queuelen = Int(lwip_bridge_tcp_snd_queuelen(self.pcb))
                    self.reportFailure(
                        "Write",
                        error: LWIPWriteFatalError(pending: live, sndbuf: sndbuf, queuelen: queuelen)
                    )
                    self.abort()
                    return 0
                }
                return n
            }

            guard !closed else { return }

            if written > 0 {
                pendingWriteOffset += written
                if pendingWriteOffset >= pendingWrite.count {
                    // Fully drained — keep the backing allocation.
                    pendingWrite.removeAll(keepingCapacity: true)
                    pendingWriteOffset = 0
                } else if pendingWriteOffset > pendingWrite.count - pendingWriteOffset {
                    // Compact once the dead prefix outgrows the live suffix (~2× cap).
                    pendingWrite.removeSubrange(0..<pendingWriteOffset)
                    pendingWriteOffset = 0
                }
                lwip_bridge_tcp_output(pcb)
            } else {
                // Nothing drained (ERR_MEM / zero window) — retry after a delay;
                // don't rearm the receive while stalled.
                PerformanceMonitor.event(.downlinkStallRetry)
                lwipQueue.asyncAfter(deadline: .now() + .milliseconds(TunnelConstants.drainRetryDelayMs)) { [weak self] in
                    guard let self, !self.closed else { return }
                    self.drainPendingWrite()
                }
                return
            }
        }

        // Prefetch the next chunk now that the backlog shrank.
        tryArmReceive()
    }

    // MARK: - Close / Abort

    /// Best-effort flush before close so drained bytes precede the FIN.
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

    /// Tears down with a clean FIN: lwIP's `tcp_close` downgrades to RST while
    /// un-recved bytes hold the window down, and a mid-handshake RST makes clients retry.
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

    /// Writes a fatal `access_denied` alert before the FIN — the protocol-level "do not
    /// retry" signal; it precedes key negotiation, so it goes out as plaintext.
    private func rejectWithTLSAlert() {
        guard !closed else { return }
        // type=21 (alert), legacy_record_version=0x0303 (TLS 1.2),
        // length=2, level=2 (fatal), description=49 (access_denied)
        let alert: [UInt8] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x31]
        alert.withUnsafeBufferPointer { buf in
            guard let base = buf.baseAddress else { return }
            _ = feedLWIP(UnsafeRawPointer(base), count: alert.count, retryOnEmpty: true)
            lwip_bridge_tcp_output(pcb)
        }
        rejectGracefully()
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
        let session = mitmSession
        proxyConnection = nil
        proxyClient = nil
        proxyConnecting = false
        pendingData = Data()
        pendingWrite = Data()
        pendingWriteOffset = 0
        uploadPipeline = UploadPipeline()
        mitmSession = nil
        session?.cancel(error: nil)
        connection?.cancel()
        client?.cancel()
    }
}
