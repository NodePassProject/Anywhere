//
//  TCPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "TCPConnection")

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

actor TCPConnection {

    nonisolated var unownedExecutor: UnownedSerialExecutor {
        bridge.executor.asUnownedSerialExecutor()
    }

    /// The owning stack, for traffic accounting, MITM state, and teardown
    /// coordination. Weak: the stack can stop while late completions on this
    /// connection are still in flight.
    private weak var stack: TunnelStack?

    let pcb: UnsafeMutableRawPointer
    let dstPort: UInt16

    /// The lwIP concurrency boundary: the connection's serial executor, every `tcp_*`
    /// call, and this connection's PCB-token lifetime all go through it.
    let bridge: LWIPConcurrencyBridge
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

    /// Whether the accept-time route is the default outbound.
    private let acceptedViaDefault: Bool

    /// Rule set behind the committed route, mirroring `routeTarget`'s mutations;
    /// nil while the route is the default outbound.
    private var ruleSetName: String?

    private var bypass: Bool {
        if case .direct = routeTarget { return true }
        return false
    }

    private var pendingData = Data()
    private var closed = false

    // MARK: MITM

    private var mitmEnabled = false
    private var mitmPlaintext = false
    /// SNI (TLS) or resolved authority (cleartext) captured at MITM-decision time; the inner server
    /// name and rewrite-match host.
    private var mitmSNI: String?
    private var mitmSession: MITMSession?

    /// True when `dstHost` is a DNS-resolved domain (fake-IP), false when it is a raw IP (real-IP).
    private let hostIsResolvedDomain: Bool

    // MARK: SNI / HTTP Sniffing

    /// Non-nil during the TLS sniff phase; inbound bytes buffer in `pendingData` until the route commits.
    private var sniffer: TLSClientHelloSniffer?
    /// Non-nil during the cleartext HTTP sniff phase; resolves the authority that gates plain-HTTP interception.
    private var httpSniffer: HTTPRequestSniffer?

    // MARK: Backpressure State

    /// Downlink backlog awaiting lwIP's send buffer. `[0, pendingWriteOffset)` is already
    /// written; compaction is deferred until the dead prefix outgrows the live suffix.
    private var pendingWrite = Data()
    private var pendingWriteOffset = 0

    /// Bytes still waiting to be handed to lwIP.
    private var pendingWriteCount: Int {
        pendingWrite.count - pendingWriteOffset
    }

    // MARK: Relay Drivers
    //
    // The upload and download copy loops run as two long-lived, actor-isolated `Task`s over
    // the proxy connection's async surface: `await send` / `await receive` are the ordering
    // and the single-flight, so there is no manual pump, pending-completion FIFO, or
    // in-flight bookkeeping. Because the drivers are actor-isolated, the code between awaits
    // runs on the lwIP executor with no hop; two `AsyncStream` wakeups nudge each driver
    // when upload work appears (new bytes / the app's FIN) or download capacity opens
    // (backlog drained below the low-water mark).
    private let uploadWake: AsyncStream<Void>
    private let uploadWakeContinuation: AsyncStream<Void>.Continuation
    private let downloadWake: AsyncStream<Void>
    private let downloadWakeContinuation: AsyncStream<Void>.Continuation

    /// True only while the upload driver is awaiting a `send`; gates the graceful deferred
    /// close so it can't truncate an in-flight chunk.
    private var uploadSending = false

    // MARK: Upload Buffer
    //
    // Coalesces a synchronous burst of lwIP callbacks so the driver ships one large send;
    // `tcp_recved` stays deferred until the proxy accepts a chunk, so TCP_WND caps how far
    // ahead the buffer can run.
    private struct UploadPipeline {
        var buffer = Data()
        var bufferOffset = 0
    }
    private var uploadPipeline = UploadPipeline()

    private var uploadBufferCount: Int {
        uploadPipeline.buffer.count - uploadPipeline.bufferOffset
    }

    private var activityTimer: ActivityTimer?
    private var handshakeTimer: DispatchWorkItem?
    /// Per-dial state (deadline, transport-cancel, settled flag, MITM completion), one instance per
    /// in-flight dial rather than single-valued so the bridge's concurrent per-stream dials don't
    /// cross-wire timeouts or cancels.
    private final class InFlightDial {
        var deadline: DispatchWorkItem?
        var cancel: (() -> Void)?
        var settled = false
        /// The MITM session's completion, invoked exactly once by ``settleDial(_:_:)``.
        var completion: ((Result<MITMDialResult, Error>) -> Void)?
    }
    /// Dials awaiting resolution; `releaseProxy` cancels every one on teardown.
    private var inFlightDials: [InFlightDial] = []
    /// Commits the IP-based route if the sniff doesn't resolve in time.
    private var sniffDeadline: DispatchWorkItem?
    private var uplinkDone = false
    private var downlinkDone = false
    private var closePending = false

    private enum UplinkCloseState { case open, closing, closed }
    private var uplinkCloseState: UplinkCloseState = .open
    private var downlinkShutdownSent = false

    /// Logs this connection's terminal failure at most once.
    private let failureReporter = ConnectionFailureReporter(prefix: "[TCP]", logger: logger)

    /// Whether this connection is counted in `FlowGauge.pendingTCP`; settled
    /// exactly once by `settlePendingAdmission()`.
    private var pendingAdmissionCounted = true

    // MARK: Lifecycle

    init(stack: TunnelStack,
         pcb: UnsafeMutableRawPointer, dstHost: String, dstPort: UInt16,
         configuration: ProxyConfiguration, routeTarget: RouteTarget,
         viaDefault: Bool,
         ruleSetName: String? = nil,
         sniffSNI: Bool = false,
         hostIsResolvedDomain: Bool = false,
         bridge: LWIPConcurrencyBridge) {
        FlowGauge.incrementPendingTCP()
        self.stack = stack
        self.pcb = pcb
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.configuration = configuration
        self.bridge = bridge
        self.lwipQueue = bridge.queue
        self.routeTarget = routeTarget
        self.acceptedViaDefault = viaDefault
        self.ruleSetName = ruleSetName
        self.hostIsResolvedDomain = hostIsResolvedDomain

        let (uploadStream, uploadContinuation) = AsyncStream<Void>.makeStream()
        self.uploadWake = uploadStream
        self.uploadWakeContinuation = uploadContinuation
        let (downloadStream, downloadContinuation) = AsyncStream<Void>.makeStream()
        self.downloadWake = downloadStream
        self.downloadWakeContinuation = downloadContinuation

        if sniffSNI {
            self.sniffer = TLSClientHelloSniffer()
        }
    }

    /// Arms the handshake timer and either begins dialing or waits for the sniff deadline.
    /// The bridge's accept trampoline calls this once, on the lwIP queue, right after `init`.
    func start() {
        let timer = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.assumeIsolated { me in
                guard !me.closed else { return }
                if me.isEstablishing {
                    let phase = me.isSniffing ? "protocol sniff" : (me.bypass ? "direct dial" : "proxy dial")
                    me.failureReporter.report(
                        operation: "Handshake",
                        endpoint: me.endpointDescription,
                        error: HandshakeTimeoutError(phase: phase),
                        context: DialDiagnostics.snapshot()
                    )
                    me.abort()
                }
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
                guard let self else { return }
                self.assumeIsolated { me in
                    guard !me.closed, me.isSniffing else { return }
                    me.sniffer = nil
                    me.httpSniffer = nil
                    me.beginConnecting()
                }
            }
            sniffDeadline = deadline
            lwipQueue.asyncAfter(deadline: .now() + TunnelConstants.sniffDeadline, execute: deadline)
        }
    }

    deinit {
        guard pendingAdmissionCounted else { return }
        FlowGauge.decrementPendingTCP()
        logger.error("[TCP] Connection deallocated with its admission still counted — teardown never ran. Recovered the FlowGauge count in deinit; a teardown path has regressed.")
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
            // The warning above already covers this abort; suppress duplicates.
            failureReporter.markReported()
            abort()
            return false
        }
        pendingData.append(ptr, count: count)
        return true
    }

    /// Still sniffing or dialing the proxy; drives the handshake timer.
    private var isEstablishing: Bool {
        proxyConnecting || isSniffing
    }

    private var isSniffing: Bool {
        sniffer != nil || httpSniffer != nil
    }

    /// Starts on the tighter response-wait timeout when the app FIN'd during setup.
    private var initialIdleTimeout: TimeInterval {
        uplinkDone ? TunnelConstants.downlinkOnlyTimeout : TunnelConstants.connectionIdleTimeout
    }

    private var mitmCanInterceptPlaintext: Bool {
        stack?.mitmEnabled == true
    }

    // MARK: - lwIP Callbacks (entered from the bridge via assumeIsolated, on the lwIP queue)

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
                case .notTLS:
                    sniffer = nil
                    if mitmCanInterceptPlaintext {
                        var http = HTTPRequestSniffer()
                        let httpState = http.feed(pendingData)
                        httpSniffer = http
                        handleHTTPSniff(httpState)
                    } else {
                        cancelSniffDeadline()
                        beginConnecting()
                    }
                    return
                case .unavailable:
                    sniffer = nil
                    cancelSniffDeadline()
                    beginConnecting()
                    return
                }
            }
        }

        if httpSniffer != nil {
            let data = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: ptr), count: count, deallocator: .none)
            guard appendPendingData(bytes: bytePtr, count: count) else { return }
            if let state = httpSniffer?.feed(data) {
                handleHTTPSniff(state)
            }
            return
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
        uploadWakeContinuation.yield(())
    }

    // MARK: - Relay Drivers
    
    private func startRelayDrivers(_ connection: ProxyConnection) {
        Task { [weak self] in await self?.runUploadDriver(connection) }
        Task { [weak self] in await self?.runDownloadDriver(connection) }
        uploadWakeContinuation.yield(())
    }

    private enum UploadStep {
        case send(Data)
        case finish
        case idle
        case stop
    }

    /// Computes the next upload action against the coalescing buffer and close state; runs
    /// synchronously on the actor between the driver's `await`s.
    private func nextUploadStep() -> UploadStep {
        if closed { return .stop }
        if uploadBufferCount > 0 {
            let take = min(uploadBufferCount, TunnelConstants.uploadChunkSize)
            uploadSending = true
            return .send(sliceUploadBuffer(take))
        }
        // Buffer drained: forward the app's FIN as an ordered half-close.
        if uplinkDone, uplinkCloseState == .open {
            uplinkCloseState = .closing
            return .finish
        }
        return .idle
    }

    /// Uplink copy loop: drains the coalescing buffer to the proxy leg one `await send` at
    /// a time (natural single-flight), then forwards the app's FIN as an ordered half-close.
    /// `tcp_recved` is deferred to each send's completion, so the app is throttled to TCP_WND.
    private func runUploadDriver(_ connection: ProxyConnection) async {
        for await _ in uploadWake {
            drain: while true {
                switch nextUploadStep() {
                case .stop:
                    return
                case .idle:
                    break drain  // park until the next wakeup
                case .send(let chunk):
                    do {
                        try await connection.send(chunk)
                    } catch {
                        uploadSending = false
                        if !closed {
                            reportFailure("Send", error: error)
                            abort()
                        }
                        return
                    }
                    uploadSending = false
                    if !closed {
                        // Count proxy-side accepts as uplink activity; a long backpressured
                        // upload would otherwise look idle and close mid-stream.
                        activityTimer?.update()
                        acknowledgeReceivedBytes(chunk.count)
                        attemptDeferredClose()
                    }
                case .finish:
                    do {
                        try await connection.closeWrite()
                    } catch {
                        if !closed {
                            uplinkCloseState = .closed
                            reportFailure("Close write", error: error)
                            abort()
                        }
                        return
                    }
                    if !closed {
                        uplinkCloseState = .closed
                        attemptDeferredClose()
                    }
                }
            }
        }
    }

    private enum DownloadStep {
        case receive
        case waitDrain
        case stop
    }

    /// Computes the next download action against the backlog and close state; runs
    /// synchronously on the actor between the driver's `await`s.
    private func nextDownloadStep() -> DownloadStep {
        if closed || downlinkDone { return .stop }
        if pendingWriteCount >= TunnelConstants.drainLowWaterMark { return .waitDrain }
        return .receive
    }

    /// Handles one received chunk (or EOF) on the actor; returns `true` to stop the driver.
    private func handleDownloaded(_ data: Data?) -> Bool {
        guard !closed else { return true }
        // nil and empty both mean EOF; transports never deliver zero-byte data.
        guard let data, !data.isEmpty else {
            downlinkDone = true
            if uplinkDone {
                closeWhenDrained()
            } else {
                activityTimer?.setTimeout(TunnelConstants.uplinkOnlyTimeout)
                propagateDownlinkCloseIfReady()
            }
            return true
        }
        activityTimer?.update()
        writeToLWIP(data)
        return false
    }

    /// Downlink copy loop: pulls from the proxy leg and hands each chunk to lwIP,
    /// prefetching only while the downlink backlog is below the low-water mark so the peer
    /// is throttled to what the app drains. Stops for good once the downlink EOF'd.
    private func runDownloadDriver(_ connection: ProxyConnection) async {
        var drainSignals = downloadWake.makeAsyncIterator()
        while true {
            switch nextDownloadStep() {
            case .stop:
                return
            case .waitDrain:
                // Suspend until a drain frees capacity (or teardown finishes the stream).
                if await drainSignals.next() == nil { return }
            case .receive:
                let data: Data?
                do {
                    data = try await connection.receive()
                } catch {
                    if !closed {
                        reportFailure("Receive", error: error)
                        abort()
                    }
                    return
                }
                if handleDownloaded(data) { return }
            }
        }
    }

    /// Forwards the remote's EOF to the app as a FIN once the downlink backlog
    /// has drained, leaving the app's uplink open (half-close) so read-until-close
    /// protocols finish promptly; the full-close path supersedes this.
    private func propagateDownlinkCloseIfReady() {
        guard downlinkDone,
              !downlinkShutdownSent,
              !closed,
              !closePending,
              pendingWriteCount == 0 else { return }
        downlinkShutdownSent = true
        bridge.tcpShutdownTx(pcb)
    }

    /// Acks local-app bytes to lwIP once the proxy leg accepted them, then
    /// flushes the window update so the peer can resume sending promptly.
    private func acknowledgeReceivedBytes(_ byteCount: Int) {
        guard byteCount > 0 else { return }
        // Single uplink tally point; rejects call tcp_recved directly, uncounted.
        stack?.addBytesOut(Int64(byteCount), target: routeTarget)
        var remaining = byteCount
        while remaining > 0 {
            let part = UInt16(min(remaining, Int(UInt16.max)))
            remaining -= Int(part)
            bridge.tcpRecved(pcb, part)
        }
        // tcp_output synchronously fires the output callback and kicks the drain loop.
        bridge.tcpOutput(pcb)
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
        if isSniffing {
            sniffer = nil
            httpSniffer = nil
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
        // Wake the upload driver so it drains the buffer, then forwards the FIN.
        uploadWakeContinuation.yield(())
        if downlinkDone {
            closeWhenDrained()
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
        } else if err == -13, stack?.isTearingDown == true {
            // ERR_ABRT during deliberate teardown; otherwise it's an lwIP pressure abort and warns below.
            logger.debug("[TCP] lwIP aborted connection (tunnel teardown): \(endpointDescription): \(reason)")
        } else {
            logger.warning("[TCP] lwIP aborted connection: \(endpointDescription): \(reason)")
        }
        // Suppress spurious error logs as in-flight callbacks unwind.
        failureReporter.markReported()
        closed = true
        releaseProxy(abortive: true)
    }

    private var endpointDescription: String {
        "\(dstHost):\(dstPort)"
    }

    private func reportFailure(_ operation: String, error: Error) {
        failureReporter.report(operation: operation, endpoint: endpointDescription, error: error)
    }

    /// Balances `FlowGauge.pendingTCP` exactly once — when the outbound dial
    /// starts (the transport's own gauge count takes over) or on teardown.
    private func settlePendingAdmission() {
        guard pendingAdmissionCounted else { return }
        pendingAdmissionCounted = false
        FlowGauge.decrementPendingTCP()
    }

    private func handleConnectFailure(_ error: Error, bufferedClientData: Data?) {
        failureReporter.report(operation: "Connect", endpoint: endpointDescription,
                               error: error, context: DialDiagnostics.snapshot())
        guard case TransportError.resolutionFailed = error else {
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

    /// Evaluates routing from the sniffed SNI; call only after the sniffer is cleared.
    private func applySNI(_ sni: String) {
        guard let stack else { return }

        // MITM (intercept TLS?) is decided independently of routing (which leg).
        if stack.mitmEnabled, stack.mitmPolicy.matches(sni) {
            mitmEnabled = true
            mitmSNI = sni
            // Routing is deferred to the dialer.
            return
        }

        let router = stack.domainRouter
        guard let match = router.matchDomain(sni) else {
            // No domain rule — keep the IP-derived route.
            return
        }

        ruleSetName = match.ruleSetName
        switch match.action {
        case .direct:
            routeTarget = .direct
            stack.requestLog.record(protocol: .tcp, host: sni, port: dstPort, routeTarget: .direct, ruleSetName: match.ruleSetName)
        case .reject:
            routeTarget = .reject
            stack.requestLog.record(protocol: .tcp, host: sni, port: dstPort, routeTarget: .reject, ruleSetName: match.ruleSetName)
            logger.debug("[TCP] SNI rejected by routing rule: \(sni) (\(dstHost):\(dstPort))")
            rejectWithTLSAlert()
        case .proxy(let id):
            // The domain rule wins over any IP-CIDR route set at accept time.
            routeTarget = .proxy(id)
            if let resolved = router.resolveConfiguration(action: match.action) {
                configuration = resolved
            } else {
                logger.warning("[TCP] SNI routing configuration not found for \(sni)")
            }
            stack.requestLog.record(protocol: .tcp, host: sni, port: dstPort, routeTarget: .proxy(id), ruleSetName: match.ruleSetName)
        }
    }

    /// Resolves a cleartext HTTP sniff: starts a plaintext MITM session when a rule matches the
    /// request authority, otherwise commits the plain (non-intercepted) route.
    private func handleHTTPSniff(_ state: HTTPRequestSniffer.State) {
        switch state {
        case .needMore:
            return
        case .found(let authority):
            httpSniffer = nil
            cancelSniffDeadline()
            applyHTTPMITM(authority: authority)
            guard !closed else { return }
            beginConnecting()
        case .notHTTP:
            httpSniffer = nil
            cancelSniffDeadline()
            beginConnecting()
        }
    }

    /// Enables plaintext MITM when a rewrite rule matches the request's authority.
    private func applyHTTPMITM(authority: String?) {
        guard let stack, stack.mitmEnabled else { return }
        let matchHost = hostIsResolvedDomain ? dstHost : authority
        guard let matchHost, stack.mitmPolicy.matches(matchHost) else { return }
        mitmEnabled = true
        mitmPlaintext = true
        mitmSNI = matchHost
    }

    // MARK: - Direct Connection (bypass)

    private func connectDirect() {
        guard !proxyConnecting && proxyConnection == nil && !closed else { return }
        proxyConnecting = true
        settlePendingAdmission()

        let initialData: Data? = pendingData.isEmpty ? nil : pendingData
        if initialData != nil {
            pendingData.removeAll(keepingCapacity: true)
        }

        // Direct/bypass — not a proxied connection. TCPTransport has no dial
        // timer, so it stays out of the Dial stat automatically.
        let transport = TCPTransport(host: dstHost, port: dstPort)
        let connection = DirectProxyConnection(transport: transport)
        self.proxyConnection = connection
        Task { [weak self] in
            let error: Error?
            do {
                try await transport.connect()
                error = nil
            } catch let dialError {
                error = dialError
            }
            guard let self else { return }
            await self.finishDirectConnect(connection: connection, error: error, initialData: initialData)
        }
    }

    /// Completes a direct dial on the actor: wires the activity timer and starts the relay.
    private func finishDirectConnect(connection: DirectProxyConnection, error: Error?, initialData: Data?) {
        proxyConnecting = false
        guard !closed else { return }

        if let error {
            handleConnectFailure(error, bufferedClientData: initialData)
            return
        }
        handshakeTimer?.cancel()
        handshakeTimer = nil
        activityTimer = makeIdleTimer()

        if let initialData {
            uploadPipeline.buffer.append(initialData)
        }
        if !pendingData.isEmpty {
            uploadPipeline.buffer.append(pendingData)
            pendingData.removeAll(keepingCapacity: true)
        }
        startRelayDrivers(connection)
    }

    // MARK: - Proxy Connection

    private func connectProxy() {
        guard !proxyConnecting && proxyConnection == nil && !closed else { return }
        proxyConnecting = true
        settlePendingAdmission()

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
            isDefaultProxy: stack?.isDefaultConfiguration(configuration.id) ?? false
        )
        self.proxyClient = client

        let host = dstHost
        let port = dstPort
        Task { [weak self] in
            let result: Result<ProxyConnection, Error>
            do {
                result = .success(try await client.connect(to: host, port: port, initialData: initialData))
            } catch {
                result = .failure(error)
            }
            guard let self else {
                if case .success(let connection) = result { connection.cancel() }
                return
            }
            await self.finishProxyConnect(result: result, initialData: initialData)
        }
    }

    /// Completes a proxy dial on the actor: wires the activity timer and starts the relay,
    /// or reports the failure. Cancels a late connection if teardown already closed us.
    private func finishProxyConnect(result: Result<ProxyConnection, Error>, initialData: Data?) {
        proxyConnecting = false
        guard !closed else {
            if case .success(let connection) = result { connection.cancel() }
            return
        }

        switch result {
        case .success(let proxyConnection):
            self.proxyConnection = proxyConnection
            handshakeTimer?.cancel()
            handshakeTimer = nil
            activityTimer = makeIdleTimer()

            if let initialData {
                // Connect success implies handshake-carried initialData was accepted.
                acknowledgeReceivedBytes(initialData.count)
            }
            if !pendingData.isEmpty {
                uploadPipeline.buffer.append(pendingData)
                pendingData.removeAll(keepingCapacity: true)
            }
            startRelayDrivers(proxyConnection)

        case .failure(let error):
            handleConnectFailure(error, bufferedClientData: initialData)
        }
    }

    /// The idle-timeout timer, firing `close()` on the actor when the connection goes quiet.
    private func makeIdleTimer() -> ActivityTimer {
        ActivityTimer(queue: lwipQueue, timeout: initialIdleTimeout) { [weak self] in
            guard let self else { return }
            self.assumeIsolated { me in
                guard !me.closed else { return }
                me.close()
            }
        }
    }

    // MARK: - MITM Session

    private func startMITMSession() {
        guard let stack else { abort(); return }
        settlePendingAdmission()
        let sni = mitmSNI ?? dstHost

        let cache: MITMLeafCertCache?
        if mitmPlaintext {
            cache = nil
        } else if let existing = stack.mitmLeafCache {
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
        activityTimer = makeIdleTimer()

        let initialClientHello = pendingData
        pendingData.removeAll(keepingCapacity: true)

        // Pass the SNI/authority, not the IP-derived host, so rewrite rules match by hostname.
        let session = MITMSession(
            dstHost: sni,
            dstPort: dstPort,
            clientHello: initialClientHello,
            leafCache: cache,
            policy: stack.mitmPolicy,
            dialer: makeMITMDialer(),
            lwipQueue: lwipQueue,
            isPlaintext: mitmPlaintext
        )
        // Inner-leg downlink: inner-leg output (TLS records or cleartext) goes straight to lwIP.
        session.onSendToClient = { [weak self] data in
            guard let self else { return }
            self.lwipQueue.async {
                self.assumeIsolated { me in
                    guard !me.closed else { return }
                    me.activityTimer?.update()
                    me.writeToLWIP(data)
                }
            }
        }
        session.onTeardown = { [weak self] error in
            guard let self else { return }
            self.lwipQueue.async {
                self.assumeIsolated { me in
                    guard !me.closed else { return }
                    if let error {
                        me.reportFailure("MITM", error: error)
                        me.abort()
                    } else {
                        me.closeWhenDrained()
                    }
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

    private enum UpstreamRoute {
        case direct
        case reject
        case proxy(routeTarget: RouteTarget, configuration: ProxyConfiguration)
    }

    private func makeMITMDialer() -> MITMDialer {
        return { [weak self] host, port, completion in
            guard let self else { completion(.failure(TransportError.notConnected)); return }
            self.lwipQueue.async {
                self.assumeIsolated { me in
                    guard !me.closed else { completion(.failure(TransportError.notConnected)); return }
                    me.dialUpstreamBounded(host: host, port: port, completion: completion)
                }
            }
        }
    }

    /// Bounds the deferred MITM upstream dial (TCP connect + proxy protocol handshake) — the gap between the
    /// per-connection `handshakeTimer` and the session's TLS-only `armUpstreamHandshakeTimeout`, where a stalled
    /// protocol handshake would otherwise linger on the 300 s idle timer. On expiry the transport is cancelled,
    /// not just failed; `completion` fires exactly once via ``settleDial(_:_:)``.
    private func dialUpstreamBounded(
        host: String, port: UInt16,
        completion: @escaping (Result<MITMDialResult, Error>) -> Void
    ) {
        let dial = InFlightDial()
        dial.completion = completion
        inFlightDials.append(dial)

        let deadline = DispatchWorkItem { [weak self, weak dial] in
            guard let self, let dial else { return }
            self.assumeIsolated { me in
                guard !me.closed, !dial.settled else { return }
                dial.settled = true
                dial.cancel?()
                me.forgetDial(dial)
                dial.completion?(.failure(HandshakeTimeoutError(phase: "upstream dial")))
            }
        }
        dial.deadline = deadline
        lwipQueue.asyncAfter(deadline: .now() + TunnelConstants.handshakeTimeout, execute: deadline)

        switch commitUpstreamRoute(forDialHost: host, port: port) {
        case .reject:
            settleDial(dial, .failure(TransportError.connectionFailed("rejected by routing rule: \(host)")))
        case .direct:
            dialDirectUpstream(host: host, port: port, dial: dial)
        case .proxy(_, let configuration):
            dialProxyUpstream(configuration: configuration, host: host, port: port, dial: dial)
        }
    }

    /// Resolves a dial exactly once: first of {dial resolves, deadline fires, teardown} wins.
    /// A late result cancels whatever it produced, so a timed-out or torn-down dial can't hand
    /// back a live socket.
    private func settleDial(_ dial: InFlightDial, _ result: Result<MITMDialResult, Error>) {
        guard !dial.settled else {
            if case .success(let d) = result { d.connection.cancel(); d.proxyClient?.cancel() }
            return
        }
        dial.settled = true
        dial.deadline?.cancel()
        forgetDial(dial)
        dial.completion?(result)
    }

    private func forgetDial(_ dial: InFlightDial) {
        inFlightDials.removeAll { $0 === dial }
    }

    private func commitUpstreamRoute(forDialHost host: String, port: UInt16) -> UpstreamRoute {
        let resolved = resolveUpstreamRoute(forDialHost: host)
        switch resolved.route {
        case .direct:
            routeTarget = .direct
        case .reject:
            routeTarget = .reject
        case .proxy(let target, let configuration):
            routeTarget = target
            self.configuration = configuration
        }
        ruleSetName = resolved.ruleSetName
        stack?.requestLog.record(protocol: .tcp, host: host, port: port, routeTarget: routeTarget, viaDefault: resolved.viaDefault, ruleSetName: resolved.ruleSetName)
        return resolved.route
    }

    private func resolveUpstreamRoute(forDialHost host: String) -> (route: UpstreamRoute, viaDefault: Bool, ruleSetName: String?) {
        // A rule matching the real dial host is an explicit route, never the default.
        if let router = stack?.domainRouter, let match = router.matchDomain(host) {
            switch match.action {
            case .direct:
                return (.direct, false, match.ruleSetName)
            case .reject:
                return (.reject, false, match.ruleSetName)
            case .proxy:
                if let configuration = router.resolveConfiguration(action: match.action) {
                    return (.proxy(routeTarget: match.action, configuration: configuration), false, match.ruleSetName)
                }
            }
        }
        if host.caseInsensitiveCompare(mitmSNI ?? dstHost) == .orderedSame {
            // Unchanged host keeps the accept-time route — and carries its default-ness.
            let route: UpstreamRoute = bypass ? .direct : .proxy(routeTarget: routeTarget, configuration: configuration)
            return (route, acceptedViaDefault, ruleSetName)
        }
        return (defaultUpstreamRoute(), true, nil)
    }

    private func defaultUpstreamRoute() -> UpstreamRoute {
        guard let stack,
              case .proxy = stack.defaultRouteTarget,
              let configuration = stack.configuration else {
            return .direct
        }
        return .proxy(routeTarget: stack.defaultRouteTarget, configuration: configuration)
    }

    private func dialDirectUpstream(host: String, port: UInt16, dial: InFlightDial) {
        // Direct/bypass — not a proxied connection. TCPTransport has no dial
        // timer, so it stays out of the Dial stat automatically.
        let transport = TCPTransport(host: host, port: port)
        let connection = DirectProxyConnection(transport: transport)
        dial.cancel = { [weak connection] in connection?.cancel() }
        Task { [weak self] in
            let error: Error?
            do {
                try await transport.connect()
                error = nil
            } catch let dialError {
                error = dialError
            }
            guard let self else {
                connection.cancel()
                return
            }
            if let error {
                // onTeardown reports the failure; don't double-report.
                await self.settleDial(dial, .failure(error))
            } else {
                await self.settleDial(dial, .success(MITMDialResult(connection: connection, proxyClient: nil)))
            }
        }
    }

    private func dialProxyUpstream(configuration: ProxyConfiguration, host: String, port: UInt16,
                                   dial: InFlightDial) {
        let client = ProxyClient(
            configuration: configuration,
            isDefaultProxy: stack?.isDefaultConfiguration(configuration.id) ?? false
        )
        dial.cancel = { [weak client] in client?.cancel() }
        Task { [weak self] in
            let result: Result<ProxyConnection, Error>
            do {
                result = .success(try await client.connect(to: host, port: port, initialData: nil))
            } catch {
                result = .failure(error)
            }
            guard let self else {
                if case .success(let connection) = result { connection.cancel() }
                await client.cancel()
                return
            }
            switch result {
            case .success(let connection):
                await self.settleDial(dial, .success(MITMDialResult(connection: connection, proxyClient: client)))
            case .failure(let error):
                // onTeardown reports the failure; don't double-report.
                await self.settleDial(dial, .failure(error))
            }
        }
    }

    // MARK: - lwIP Write Helper

    /// Writes as much as lwIP's send buffer accepts; returns bytes written, or -1 on a
    /// fatal tcp_write error. `retryOnEmpty` flushes a full buffer once so ACKs free snd_buf.
    private func feedLWIP(_ base: UnsafeRawPointer, count: Int, retryOnEmpty: Bool = false) -> Int {
        var offset = 0
        while offset < count {
            var sndbuf = bridge.tcpSendBuffer(pcb)
            if sndbuf <= 0 {
                if retryOnEmpty {
                    bridge.tcpOutput(pcb)
                    sndbuf = bridge.tcpSendBuffer(pcb)
                }
                guard sndbuf > 0 else { break }
            }
            let chunkSize = min(min(sndbuf, count - offset), TunnelConstants.tcpMaxWriteSize)
            let error = bridge.tcpWrite(pcb, base + offset, UInt16(chunkSize))
            if error != 0 {
                if error == -1 { break }  // ERR_MEM: transient
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
        stack?.addBytesIn(Int64(data.count), target: routeTarget)
        pendingWrite.append(data)
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
                    let sndbuf = bridge.tcpSendBuffer(self.pcb)
                    let queuelen = bridge.tcpSendQueueLength(self.pcb)
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
                // Drain progress is activity; the tightened post-FIN timeout must not fire mid-backlog.
                activityTimer?.update()
                pendingWriteOffset += written
                if pendingWriteOffset >= pendingWrite.count {
                    pendingWrite.removeAll(keepingCapacity: true)
                    pendingWriteOffset = 0
                } else if pendingWriteOffset > pendingWrite.count - pendingWriteOffset {
                    // Compact once the dead prefix outgrows the live suffix (~2× cap).
                    pendingWrite.removeSubrange(0..<pendingWriteOffset)
                    pendingWriteOffset = 0
                }
                bridge.tcpOutput(pcb)
            } else {
                // Nothing drained (ERR_MEM / zero window) — retry after a delay;
                // don't rearm the receive while stalled.
                lwipQueue.asyncAfter(deadline: .now() + .milliseconds(TunnelConstants.drainRetryDelayMs)) { [weak self] in
                    guard let self else { return }
                    self.assumeIsolated { me in
                        guard !me.closed else { return }
                        me.drainPendingWrite()
                    }
                }
                return
            }
        }

        attemptDeferredClose()
        guard !closed else { return }
        propagateDownlinkCloseIfReady()

        // Capacity opened up; let the download driver prefetch the next chunk.
        if pendingWriteCount < TunnelConstants.drainLowWaterMark {
            downloadWakeContinuation.yield(())
        }
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
            bridge.tcpOutput(pcb)
        }
    }

    /// Defers `close()` until both relay buffers drain — the downlink backlog owed
    /// to lwIP and upload bytes the proxy leg hasn't accepted — since an immediate
    /// close truncates both. Drain/pump tails finish via `attemptDeferredClose()`;
    /// the activity timer bounds a stalled peer.
    private func closeWhenDrained() {
        guard !closed else { return }
        closePending = true
        activityTimer?.setTimeout(TunnelConstants.downlinkOnlyTimeout)
        attemptDeferredClose()
    }

    /// Gates the deferred close so `releaseProxy`'s cancel can't race the
    /// forwarded FIN off the wire.
    private var uplinkCloseSettled: Bool {
        proxyConnection == nil || !uplinkDone || uplinkCloseState == .closed
    }

    private func attemptDeferredClose() {
        guard closePending, !closed,
              pendingWriteCount == 0,
              uploadBufferCount == 0,
              !uploadSending,
              uplinkCloseSettled else { return }
        close()
    }

    func close() {
        guard !closed else { return }
        closed = true
        flushPendingToLWIP()
        bridge.tcpClose(pcb)
        releaseProxy(abortive: false)
        bridge.discard(self)
    }

    /// Tears down with a clean FIN: lwIP's `tcp_close` downgrades to RST while
    /// un-recved bytes hold the window down, and a mid-handshake RST makes clients retry.
    private func rejectGracefully() {
        guard !closed else { return }
        var remaining = pendingData.count
        while remaining > 0 {
            let chunk = UInt16(min(remaining, Int(UInt16.max)))
            remaining -= Int(chunk)
            bridge.tcpRecved(pcb, chunk)
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
        alert.withUnsafeBufferPointer { buffer in
            guard let base = buffer.baseAddress else { return }
            _ = feedLWIP(UnsafeRawPointer(base), count: alert.count, retryOnEmpty: true)
            bridge.tcpOutput(pcb)
        }
        rejectGracefully()
    }

    func abort() {
        guard !closed else { return }
        closed = true
        bridge.tcpAbort(pcb)
        releaseProxy(abortive: true)
        bridge.discard(self)
    }

    /// `abortive` closes the outbound leg with RST instead of a graceful FIN.
    private func releaseProxy(abortive: Bool = false) {
        settlePendingAdmission()
        handshakeTimer?.cancel()
        handshakeTimer = nil
        // Mark settled so a dial resolving after teardown cancels its socket instead of completing.
        for dial in inFlightDials {
            dial.settled = true
            dial.deadline?.cancel()
            dial.cancel?()
        }
        inFlightDials.removeAll()
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
        uploadWakeContinuation.finish()
        downloadWakeContinuation.finish()
        mitmSession = nil
        session?.cancel(error: nil)
        if abortive {
            connection?.abort()
        } else {
            connection?.cancel()
        }
        client?.cancel()
    }
}
