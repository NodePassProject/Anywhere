//
//  TCPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "TCPConnection")

nonisolated private struct HandshakeTimeoutError: LocalizedError {
    let phase: String
    var errorDescription: String? { "Handshake timed out during \(phase)" }
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

    /// Dial destination, fixed at accept time; an SNI re-route deliberately
    /// keeps the caller's own DNS choice.
    private(set) var dstHost: String

    /// Routing configuration; an SNI re-match may swap it to a different proxy.
    private(set) var configuration: ProxyConfiguration

    private var proxyClient: ProxyClient?
    private var proxyConnection: ProxyConnection?
    private var proxyConnecting = false
    /// The in-flight proxy dial. Teardown cancels it so a still-connecting handshake unwinds
    /// (its `CancellationError` runs the connect path's cleanup) instead of lingering until the
    /// handshake timeout — `client.cancel()` alone only tears down an already-delivered connection.
    private var proxyDialTask: Task<Void, Never>?

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

    // MARK: Relay
    //
    // The upload and download copy loops run inside one structured task group (``relayTask``)
    // over the proxy connection's async surface and the per-connection
    // ``TCPStreamConcurrencyBridge``, which owns all coalescing/backlog buffering, backpressure,
    // wake continuations, and `tcp_*` window/write calls. Teardown is `stream.terminate()` +
    // `relayTask.cancel()` — no `withTaskCancellationHandler`, no manual pump.

    /// The per-connection byte-relay bridge, created at establishment (both the non-MITM relay
    /// and the MITM downlink ride it); `nil` before the dial resolves.
    private var stream: TCPStreamConcurrencyBridge?

    /// The connection-lifetime relay task (the structured upload+download group); cancelled by
    /// ``releaseProxy(abortive:)``.
    private var relayTask: Task<Void, Never>?

    // MARK: Actor-isolated idle timer (replaces ActivityTimer)
    //
    // No queue+closure timer: the connection stores `lastActivityTick` and re-checks on the actor.
    // `close()` fires when the connection has been quiet for `idleTimeout`.
    private var idleActive = false
    private var idleTimeout: TimeInterval = 0
    private var lastActivityTick: TimeInterval = 0
    private var idleCheckTask: Task<Void, Never>?

    /// Bounds sniff/dial/handshake; cancelled on the first outbound leg or teardown. Actor-isolated.
    private var handshakeTimeoutTask: Task<Void, Never>?
    /// Per-dial teardown handle: cancels the in-flight transport/client, one instance per dial so the
    /// bridge's concurrent per-stream dials don't cross-wire cancels. The deadline is a `Task.sleep`
    /// raced inside ``raceHandshakeDeadline`` rather than a per-dial timer.
    private final class InFlightDial {
        var cancel: (() -> Void)?
    }
    /// Dials awaiting resolution; `releaseProxy` cancels every one on teardown.
    private var inFlightDials: [InFlightDial] = []
    /// Commits the IP-based route if the sniff doesn't resolve in time. Actor-isolated.
    private var sniffDeadlineTask: Task<Void, Never>?
    private var uplinkDone = false
    private var downlinkDone = false
    private var closePending = false
    /// Waits out the downlink drain before a deferred close; owned here so ``releaseProxy``
    /// cancels it symmetrically with the other lifecycle tasks.
    private var deferredCloseTask: Task<Void, Never>?

    /// Logs this connection's terminal failure at most once.
    private let failureReporter = ConnectionFailureReporter(prefix: "[TCP]", logger: logger)

    /// Whether this connection is counted in `FlowGauge.pendingTCP`; settled
    /// exactly once by `settlePendingAdmission()`.
    private var pendingAdmissionCounted = true

    // MARK: Lifecycle
    
    init(stack: TunnelStack,
         pcb: LWIPPCBHandle, dstHost: String, dstPort: UInt16,
         configuration: ProxyConfiguration, routeTarget: RouteTarget,
         viaDefault: Bool,
         ruleSetName: String? = nil,
         sniffSNI: Bool = false,
         hostIsResolvedDomain: Bool = false,
         bridge: LWIPConcurrencyBridge) {
        FlowGauge.incrementPendingTCP()
        self.stack = stack
        self.pcb = pcb.raw
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.configuration = configuration
        self.bridge = bridge
        self.routeTarget = routeTarget
        self.acceptedViaDefault = viaDefault
        self.ruleSetName = ruleSetName
        self.hostIsResolvedDomain = hostIsResolvedDomain

        if sniffSNI {
            self.sniffer = TLSClientHelloSniffer()
        }
    }

    /// Arms the handshake timer and either begins dialing or waits for the sniff deadline.
    /// The bridge's accept trampoline calls this once, on the lwIP queue, right after `init`.
    func start() {
        handshakeTimeoutTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(TunnelConstants.handshakeTimeout))
            guard !Task.isCancelled else { return }
            await self?.handshakeTimedOut()
        }

        if sniffer == nil {
            beginConnecting()
        } else {
            // Server-speaks-first protocols (SSH, SMTP, FTP) never send client
            // bytes; commit the IP-based route at the deadline.
            sniffDeadlineTask = Task { [weak self] in
                try? await Task.sleep(for: .seconds(TunnelConstants.sniffDeadline))
                guard !Task.isCancelled else { return }
                await self?.sniffDeadlineFired()
            }
        }
    }

    /// Fires on the actor when the sniff/dial handshake overran its bound; aborts if still establishing.
    private func handshakeTimedOut() {
        guard !closed, isEstablishing else { return }
        let phase = isSniffing ? "protocol sniff" : (bypass ? "direct dial" : "proxy dial")
        failureReporter.report(
            operation: "Handshake",
            endpoint: endpointDescription,
            error: HandshakeTimeoutError(phase: phase),
            context: DialDiagnostics.snapshot(bridge: bridge)
        )
        abort()
    }

    /// Fires on the actor when the sniff deadline elapsed with no client bytes; commits the IP route.
    private func sniffDeadlineFired() {
        guard !closed, isSniffing else { return }
        sniffer = nil
        httpSniffer = nil
        beginConnecting()
    }

    deinit {
        guard pendingAdmissionCounted else { return }
        FlowGauge.decrementPendingTCP()
        logger.error("[TCP] Connection deallocated with its admission still counted — teardown never ran. Recovered the FlowGauge count in deinit; a teardown path has regressed.")
    }

    private func cancelSniffDeadline() {
        sniffDeadlineTask?.cancel()
        sniffDeadlineTask = nil
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
        markActivity()

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
            markActivity()
            // Ack to lwIP up-front; MITMSession owns inner-leg flow control. The session shares this
            // actor's lwIP executor, entered synchronously via `assumeIsolated`.
            acknowledgeReceivedBytes(count)
            mitmSession.assumeIsolated { $0.feedClientBytes(chunk) }
            return
        }

        guard let stream else {
            guard appendPendingData(bytes: bytePtr, count: count) else { return }
            beginConnecting()
            return
        }

        // Copy on this (shared lwIP) executor before the hop; `ptr` is valid only for this call and
        // the copy is the same one `deliverUpload` did — it just moves ahead of the actor boundary.
        let uploadChunk = Data(bytes: ptr, count: count)
        stream.assumeIsolated { $0.deliverUpload(uploadChunk) }
    }

    // MARK: - Relay

    /// Creates the byte-relay bridge, seeds any bytes buffered during sniff/dial, and starts the
    /// structured upload+download group. Both legs run to their own EOF — half-close is removed,
    /// so no directional FIN is sent; the connection full-closes once both directions have ended.
    private func startRelay(_ connection: ProxyConnection, stream: TCPStreamConcurrencyBridge, seed: Data) {
        if !seed.isEmpty { stream.assumeIsolated { $0.seedUpload(seed) } }
        if uplinkDone { stream.assumeIsolated { $0.deliverUploadEOF() } }
        // Strong self: the relay group owns the connection while copying. `releaseProxy` terminates
        // the stream and cancels the proxy leg, so both loops unwind promptly and the task finishes,
        // letting ARC reclaim — the holder drives teardown, no `[weak self]` cycle-guard needed.
        relayTask = Task {
            await withTaskGroup(of: Void.self) { group in
                group.addTask { await self.runUploadRelay(connection, stream) }
                group.addTask { await self.runDownloadRelay(connection, stream) }
            }
            self.relayFinished()
        }
    }

    /// Uplink copy loop: coalesced app bytes → proxy leg, one `await send` at a time, acking each
    /// chunk back to lwIP only after the upstream accepts it (throttle to the upstream's rate).
    /// Returns at the app's FIN.
    private func runUploadRelay(_ connection: ProxyConnection, _ stream: TCPStreamConcurrencyBridge) async {
        while let chunk = await stream.receiveUpload() {
            do {
                try await connection.send(chunk)
            } catch {
                if !closed { reportFailure("Send", error: error); abort() }
                return
            }
            if closed { return }
            markActivity()
            stack?.addBytesOut(Int64(chunk.count), target: routeTarget)
            await stream.ackUpload(chunk.count)
        }
    }

    /// Downlink copy loop: proxy leg → lwIP via the bridge's backpressured send. At the upstream
    /// EOF it waits for the backlog to drain (so the full close doesn't truncate the tail), then
    /// returns — no `tcp_shutdown_tx` is sent.
    private func runDownloadRelay(_ connection: ProxyConnection, _ stream: TCPStreamConcurrencyBridge) async {
        while true {
            let data: Data?
            do {
                data = try await connection.receive()
            } catch {
                if !closed { reportFailure("Receive", error: error); abort() }
                return
            }
            // nil and empty both mean EOF; transports never deliver zero-byte data.
            guard let data, !data.isEmpty else { break }
            if closed { return }
            markActivity()
            stack?.addBytesIn(Int64(data.count), target: routeTarget)
            do {
                try await stream.sendDownload(data)
            } catch {
                if !closed, case TCPStreamConcurrencyBridge.StreamError.writeFailed = error {
                    reportFailure("Write", error: error)
                    abort()
                }
                return
            }
        }
        if closed { return }
        downlinkDone = true
        if !uplinkDone { setIdleTimeout(TunnelConstants.uplinkOnlyTimeout) }
        await stream.awaitDownloadDrained()
    }

    /// Both relay directions ended (EOF'd + drained): full-close the connection.
    private func relayFinished() {
        guard !closed else { return }
        close()
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

    /// Client ACK freed lwIP send-buffer space: feed the download backpressure/drain in the bridge.
    func handleSent(len: UInt16) {
        guard !closed else { return }
        stream?.assumeIsolated { $0.deliverSendCredit() }
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

        // Propagate the orderly close through the inner TLS leg (shared lwIP executor).
        mitmSession?.assumeIsolated { $0.clientDidClose() }

        uplinkDone = true
        if let stream {
            // Non-MITM: signal the app's FIN; the upload relay drains and returns. The connection
            // full-closes once the download direction also ends (half-close removed).
            stream.assumeIsolated { $0.deliverUploadEOF() }
            if !downlinkDone { setIdleTimeout(TunnelConstants.downlinkOnlyTimeout) }
        } else if !downlinkDone {
            // MITM / pre-relay: tighten the idle window while awaiting the downlink.
            setIdleTimeout(TunnelConstants.downlinkOnlyTimeout)
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
                               error: error, context: DialDiagnostics.snapshot(bridge: bridge))
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
        // Strong self, stored like the proxy dial: teardown cancels this task so a still-connecting
        // transport unwinds; the finish handler's `closed` guard releases a late-delivered dial.
        proxyDialTask = Task {
            let error: Error?
            do {
                try await transport.connect()
                error = nil
            } catch let dialError {
                error = dialError
            }
            // Same-actor call (the Task inherits this actor's executor); no hop, no await.
            self.finishDirectConnect(connection: connection, error: error, initialData: initialData)
        }
    }

    /// Completes a direct dial on the actor: wires the activity timer and starts the relay.
    private func finishDirectConnect(connection: DirectProxyConnection, error: Error?, initialData: Data?) {
        proxyConnecting = false
        proxyDialTask = nil
        guard !closed else { return }

        if let error {
            handleConnectFailure(error, bufferedClientData: initialData)
            return
        }
        handshakeTimeoutTask?.cancel()
        handshakeTimeoutTask = nil
        startIdleTimer()

        let stream = TCPStreamConcurrencyBridge(bridge: bridge, pcb: LWIPPCBHandle(raw: pcb))
        self.stream = stream
        var seed = Data()
        if let initialData { seed.append(initialData) }
        if !pendingData.isEmpty {
            seed.append(pendingData)
            pendingData.removeAll(keepingCapacity: true)
        }
        startRelay(connection, stream: stream, seed: seed)
    }

    // MARK: - Proxy Connection

    private func connectProxy() {
        guard !proxyConnecting && proxyConnection == nil && !closed else { return }
        proxyConnecting = true
        settlePendingAdmission()

        // Protocol-specific policy selects the prefix that can ride the opening write.
        let initialData: Data?
        let prefixLength = configuration.outboundProtocol.initialDataPolicy.prefixLength(
            for: pendingData.count
        )
        if prefixLength > 0 {
            initialData = Data(pendingData.prefix(prefixLength))
            pendingData.removeFirst(prefixLength)
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
        // Strong self: teardown cancels this task (unwinding a still-connecting handshake); the
        // finish handler's `closed` guard cancels a connection delivered after a mid-dial close.
        proxyDialTask = Task {
            let result: Result<ProxyConnection, Error>
            do {
                result = .success(try await client.connect(to: host, port: port, initialData: initialData))
            } catch {
                result = .failure(error)
            }
            // Same-actor call (the Task inherits this actor's executor); no hop, no await.
            self.finishProxyConnect(result: result, initialData: initialData)
        }
    }

    /// Completes a proxy dial on the actor: wires the activity timer and starts the relay,
    /// or reports the failure. Cancels a late connection if teardown already closed us.
    private func finishProxyConnect(result: Result<ProxyConnection, Error>, initialData: Data?) {
        proxyConnecting = false
        proxyDialTask = nil
        guard !closed else {
            if case .success(let connection) = result { connection.cancel() }
            return
        }

        switch result {
        case .success(let proxyConnection):
            self.proxyConnection = proxyConnection
            handshakeTimeoutTask?.cancel()
            handshakeTimeoutTask = nil
            startIdleTimer()

            let stream = TCPStreamConcurrencyBridge(bridge: bridge, pcb: LWIPPCBHandle(raw: pcb))
            self.stream = stream
            if let initialData {
                // Connect success implies handshake-carried initialData was accepted.
                acknowledgeReceivedBytes(initialData.count)
            }
            var seed = Data()
            if !pendingData.isEmpty {
                seed.append(pendingData)
                pendingData.removeAll(keepingCapacity: true)
            }
            startRelay(proxyConnection, stream: stream, seed: seed)

        case .failure(let error):
            handleConnectFailure(error, bufferedClientData: initialData)
        }
    }

    // MARK: - Idle Timer (actor-isolated)

    /// Arms the idle timer at `initialIdleTimeout`; `close()` fires once the connection is quiet that long.
    private func startIdleTimer() {
        idleTimeout = initialIdleTimeout
        lastActivityTick = MonotonicClock.now
        idleActive = true
        scheduleIdleCheck(after: idleTimeout)
    }

    /// Records traffic so the idle check sees the connection as active.
    private func markActivity() {
        lastActivityTick = MonotonicClock.now
    }

    /// Changes the idle window (e.g. tightened after a half-close). `<= 0`, or a window already
    /// exceeded by the elapsed idle time, closes immediately.
    private func setIdleTimeout(_ timeout: TimeInterval) {
        guard idleActive else { return }
        if timeout <= 0 {
            cancelIdleTimer()
            close()
            return
        }
        idleTimeout = timeout
        let elapsed = MonotonicClock.now - lastActivityTick
        if elapsed >= timeout {
            cancelIdleTimer()
            close()
            return
        }
        scheduleIdleCheck(after: timeout - elapsed)
    }

    private func cancelIdleTimer() {
        idleActive = false
        idleCheckTask?.cancel()
        idleCheckTask = nil
    }

    /// Schedules the next idle re-check `delay` seconds out. Weak self so the sleep can't pin the
    /// connection; `await` hops back onto the actor (lwIP executor).
    private func scheduleIdleCheck(after delay: TimeInterval) {
        idleCheckTask?.cancel()
        guard idleActive, delay > 0 else { return }
        idleCheckTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled else { return }
            await self?.checkIdle()
        }
    }

    /// Runs on the actor: closes if idle past `idleTimeout`, else re-arms for the remaining window.
    private func checkIdle() {
        guard !closed, idleActive, idleTimeout > 0 else { return }
        let elapsed = MonotonicClock.now - lastActivityTick
        if elapsed >= idleTimeout {
            idleActive = false
            idleCheckTask = nil
            close()
        } else {
            scheduleIdleCheck(after: idleTimeout - elapsed)
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
        } else {
            do {
                cache = try stack.mitmLeafCacheCreatingIfNeeded()
            } catch {
                reportFailure("MITM leaf cache", error: error)
                abort()
                return
            }
        }

        handshakeTimeoutTask?.cancel()
        handshakeTimeoutTask = nil
        startIdleTimer()

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
            lwipBridge: bridge,
            isPlaintext: mitmPlaintext
        )
        // Downlink bridge: inner-leg output (TLS records or cleartext) rides the per-connection
        // relay bridge — the backlog, backpressure, and `tcp_*` writes are confined there.
        let stream = TCPStreamConcurrencyBridge(bridge: bridge, pcb: LWIPPCBHandle(raw: pcb))
        self.stream = stream
        // The session is an actor on this same lwIP executor; wire its callbacks and kick it off via
        // `assumeIsolated` (we are already on the queue), the same seam its own legs use.
        session.assumeIsolated { s in
            s.onSendToClient = { [weak self] data in
                guard let self else { return }
                self.bridge.enqueue {
                    self.assumeIsolated { me in
                        guard !me.closed, let stream = me.stream else { return }
                        me.markActivity()
                        stream.assumeIsolated { $0.deliverDownload(data) }
                    }
                }
            }
            s.onTeardown = { [weak self] error in
                guard let self else { return }
                self.bridge.enqueue {
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
        }
        mitmSession = session

        // Ack the consumed ClientHello so the client can keep sending.
        if !initialClientHello.isEmpty {
            acknowledgeReceivedBytes(initialClientHello.count)
        }

        session.assumeIsolated { $0.start(sni: sni) }
    }

    private enum UpstreamRoute {
        case direct
        case reject
        case proxy(routeTarget: RouteTarget, configuration: ProxyConfiguration)
    }

    private func makeMITMDialer() -> MITMDialer {
        return { [weak self] host, port in
            guard let self else { throw TransportError.notConnected }
            // Hops onto the actor (lwIP executor); the deadline race and route commit run there.
            return try await self.dialUpstreamBounded(host: host, port: port)
        }
    }

    /// Bounds the deferred MITM upstream dial (TCP connect + proxy protocol handshake) — the gap between the
    /// per-connection handshake timeout and the session's TLS-only `armUpstreamHandshakeTimeout`, where a
    /// stalled protocol handshake would otherwise linger on the 300 s idle timer. On expiry the transport is
    /// cancelled, not just failed (see ``raceHandshakeDeadline``). Actor-isolated.
    private func dialUpstreamBounded(host: String, port: UInt16) async throws -> MITMDialResult {
        guard !closed else { throw TransportError.notConnected }
        switch commitUpstreamRoute(forDialHost: host, port: port) {
        case .reject:
            throw TransportError.connectionFailed("rejected by routing rule: \(host)")
        case .direct:
            return try await dialDirectUpstream(host: host, port: port)
        case .proxy(_, let configuration):
            return try await dialProxyUpstream(configuration: configuration, host: host, port: port)
        }
    }

    private enum DialRace<T: Sendable>: Sendable { case value(T), timedOut }

    /// Races `body` against a `handshakeTimeout` `Task.sleep`. On timeout, `cancelOnTimeout` aborts the
    /// in-flight transport so the (uncancellable) handshake fails instead of leaking a socket, and a
    /// `HandshakeTimeoutError` is thrown; a `body` failure propagates as-is. Replaces the old per-dial
    /// `DispatchWorkItem` deadline + settled-flag race with structured concurrency.
    private func raceHandshakeDeadline<T: Sendable>(
        cancelOnTimeout: @escaping @Sendable () -> Void,
        _ body: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: DialRace<T>.self) { group in
            group.addTask { .value(try await body()) }
            group.addTask {
                try? await Task.sleep(for: .seconds(TunnelConstants.handshakeTimeout))
                return .timedOut
            }
            defer { group.cancelAll() }
            while let next = try await group.next() {
                switch next {
                case .value(let value):
                    return value
                case .timedOut:
                    cancelOnTimeout()   // abort the in-flight handshake so `body` unwinds
                    throw HandshakeTimeoutError(phase: "upstream dial")
                }
            }
            throw HandshakeTimeoutError(phase: "upstream dial")
        }
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
        // Read the default route/configuration from the stack's published UDP-config snapshot
        // (nonisolated), so this stays synchronous without hopping onto the stack actor.
        guard let config = stack?.udpConfig(),
              case .proxy = config.defaultRouteTarget,
              let configuration = config.configuration else {
            return .direct
        }
        return .proxy(routeTarget: config.defaultRouteTarget, configuration: configuration)
    }

    private func dialDirectUpstream(host: String, port: UInt16) async throws -> MITMDialResult {
        // Direct/bypass — not a proxied connection. TCPTransport has no dial
        // timer, so it stays out of the Dial stat automatically.
        let transport = TCPTransport(host: host, port: port)
        let connection = DirectProxyConnection(transport: transport)
        let dial = InFlightDial()
        dial.cancel = { connection.cancel() }
        inFlightDials.append(dial)
        defer { forgetDial(dial) }
        do {
            try await raceHandshakeDeadline(cancelOnTimeout: { connection.cancel() }) {
                try await transport.connect()
            }
            return MITMDialResult(connection: connection, proxyClient: nil)
        } catch {
            // onTeardown reports the failure; don't double-report. Cancel a socket the connect may
            // have opened before failing / timing out.
            connection.cancel()
            throw error
        }
    }

    private func dialProxyUpstream(configuration: ProxyConfiguration, host: String, port: UInt16) async throws -> MITMDialResult {
        let client = ProxyClient(
            configuration: configuration,
            isDefaultProxy: stack?.isDefaultConfiguration(configuration.id) ?? false
        )
        // Run the dial as a task the flow owns: teardown and the handshake-deadline race cancel it so a
        // still-connecting handshake unwinds now (its `CancellationError` runs the connect path's cleanup)
        // rather than lingering — `client.cancel()` alone only tears down an already-delivered connection.
        // `client.cancel()` still runs alongside so a dial that completes in the race self-destructs via deliver().
        let dialTask = Task { try await client.connect(to: host, port: port, initialData: nil) }
        let dial = InFlightDial()
        dial.cancel = { dialTask.cancel(); client.cancel() }
        inFlightDials.append(dial)
        defer { forgetDial(dial) }
        do {
            let connection = try await raceHandshakeDeadline(cancelOnTimeout: { dialTask.cancel() }) {
                try await dialTask.value
            }
            return MITMDialResult(connection: connection, proxyClient: client)
        } catch {
            // onTeardown reports the failure; don't double-report. Cancel the dial task and mark the
            // client so any half-open socket from a raced success is torn down.
            dialTask.cancel()
            await client.cancel()
            throw error
        }
    }

    // MARK: - Close / Abort
    
    private func closeWhenDrained() {
        guard !closed else { return }
        guard let stream else { close(); return }
        closePending = true
        setIdleTimeout(TunnelConstants.downlinkOnlyTimeout)
        deferredCloseTask = Task {
            await stream.awaitDownloadDrained()
            completeDeferredClose()
        }
    }

    private func completeDeferredClose() {
        guard closePending, !closed else { return }
        close()
    }

    func close() {
        guard !closed else { return }
        closed = true
        stream?.assumeIsolated { $0.flushBestEffort() }
        bridge.tcpClose(pcb)
        releaseProxy(abortive: false)
        bridge.discard(self)
    }
    
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
    
    private func rejectWithTLSAlert() {
        guard !closed else { return }
        // type=21 (alert), legacy_record_version=0x0303 (TLS 1.2),
        // length=2, level=2 (fatal), description=49 (access_denied)
        let alert: [UInt8] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x31]
        bridge.tcpWriteImmediate(pcb, Data(alert))
        rejectGracefully()
    }

    func abort() {
        guard !closed else { return }
        closed = true
        bridge.tcpAbort(pcb)
        releaseProxy(abortive: true)
        bridge.discard(self)
    }
    
    private func releaseProxy(abortive: Bool = false) {
        settlePendingAdmission()
        handshakeTimeoutTask?.cancel()
        handshakeTimeoutTask = nil
        for dial in inFlightDials {
            dial.cancel?()
        }
        inFlightDials.removeAll()
        sniffDeadlineTask?.cancel()
        sniffDeadlineTask = nil
        deferredCloseTask?.cancel()
        deferredCloseTask = nil
        sniffer = nil
        cancelIdleTimer()
        let connection = proxyConnection
        let client = proxyClient
        let dial = proxyDialTask
        let session = mitmSession
        let stream = self.stream
        let relay = self.relayTask
        proxyConnection = nil
        proxyClient = nil
        proxyDialTask = nil
        proxyConnecting = false
        self.stream = nil
        self.relayTask = nil
        pendingData = Data()
        mitmSession = nil
        session?.assumeIsolated { $0.cancel(error: nil) }
        stream?.assumeIsolated { $0.terminate() }
        relay?.cancel()
        dial?.cancel()
        if abortive {
            connection?.abort()
        } else {
            connection?.cancel()
        }
        client?.cancel()
    }
}
