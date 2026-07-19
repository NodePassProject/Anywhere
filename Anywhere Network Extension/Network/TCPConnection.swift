//
//  TCPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TCPConnection")

actor TCPConnection {

    nonisolated var unownedExecutor: UnownedSerialExecutor {
        bridge.executor.asUnownedSerialExecutor()
    }
    
    private weak var stack: TunnelStack?

    let pcb: UnsafeMutableRawPointer
    let dstPort: UInt16
    
    let bridge: LWIPConcurrencyBridge
    
    private(set) var dstHost: String
    
    private(set) var configuration: ProxyConfiguration

    private var proxyClient: ProxyClient?
    private var proxyConnection: ProxyConnection?
    private var proxyConnecting = false
    private var proxyDialTask: Task<Void, Never>?
    
    private let acceptedViaDefault: Bool
    
    private var routeTarget: RouteTarget
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
    
    private var stream: TCPStreamConcurrencyBridge?
    
    private var relayTask: Task<Void, Never>?

    // MARK: Actor-isolated idle timer
    
    private var idleActive = false
    private var idleTimeout: TimeInterval = 0
    private nonisolated let lastActivityTick = Atomic<TimeInterval>(0)
    private var idleCheckTask: Task<Void, Never>?
    
    private var handshakeTimeoutTask: Task<Void, Never>?
    private final class InFlightDial {
        var cancel: (() -> Void)?
    }
    
    private var inFlightDials: [InFlightDial] = []
    private var sniffDeadlineTask: Task<Void, Never>?
    private var uplinkDone = false
    private var downlinkDone = false
    private var closePending = false
    private var deferredCloseTask: Task<Void, Never>?
    
    private let failureReporter = ConnectionFailureReporter(prefix: "[TCP]", logger: logger)
    
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
    
    func start() {
        handshakeTimeoutTask = Task {
            try? await Task.sleep(for: .seconds(TunnelConstants.handshakeTimeout))
            guard !Task.isCancelled else { return }
            handshakeTimedOut()
        }

        if sniffer == nil {
            beginConnecting()
        } else {
            sniffDeadlineTask = Task {
                try? await Task.sleep(for: .seconds(TunnelConstants.sniffDeadline))
                guard !Task.isCancelled else { return }
                sniffDeadlineFired()
            }
        }
    }
    
    private func handshakeTimedOut() {
        guard !closed, isEstablishing else { return }
        let phase = isSniffing ? "protocol sniff" : (bypass ? "direct dial" : "proxy dial")
        failureReporter.report(
            operation: "Handshake",
            endpoint: endpointDescription,
            error: AnywhereError.transport(.timedOut(.connect, endpoint: nil, detail: phase)),
            context: DialDiagnostics.snapshot(bridge: bridge)
        )
        abort()
    }
    
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
    
    @discardableResult
    private func appendPendingData(bytes ptr: UnsafePointer<UInt8>, count: Int) -> Bool {
        if pendingData.count + count > TunnelConstants.tcpMaxPendingDataSize {
            logger.warning("[TCP] pendingData cap exceeded for \(dstHost):\(dstPort) (\(pendingData.count) + \(count) > \(TunnelConstants.tcpMaxPendingDataSize)), aborting")
            failureReporter.markReported()
            abort()
            return false
        }
        pendingData.append(ptr, count: count)
        return true
    }
    
    private var isEstablishing: Bool {
        proxyConnecting || isSniffing
    }

    private var isSniffing: Bool {
        sniffer != nil || httpSniffer != nil
    }
    
    private var initialIdleTimeout: TimeInterval {
        uplinkDone ? TunnelConstants.downlinkOnlyTimeout : TunnelConstants.connectionIdleTimeout
    }

    private var mitmCanInterceptPlaintext: Bool {
        stack?.mitmEnabled == true
    }

    // MARK: - lwIP Callbacks
    
    func handleReceivedData(bytes ptr: UnsafeRawPointer, count: Int) {
        guard !closed, count > 0 else { return }
        markActivity()

        let bytePtr = ptr.assumingMemoryBound(to: UInt8.self)
        
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
        
        if let mitmSession {
            let chunk = Data(bytes: bytePtr, count: count)
            markActivity()
            acknowledgeReceivedBytes(count)
            mitmSession.assumeIsolated { $0.feedClientBytes(chunk) }
            return
        }

        guard let stream else {
            guard appendPendingData(bytes: bytePtr, count: count) else { return }
            beginConnecting()
            return
        }
        
        let uploadChunk = Data(bytes: ptr, count: count)
        stream.assumeIsolated { $0.deliverUpload(uploadChunk) }
    }

    // MARK: - Relay
    
    private func startRelay(_ connection: ProxyConnection, stream: TCPStreamConcurrencyBridge, seed: Data) {
        stream.assumeIsolated { s in
            s.onFatalWrite = { [weak self] error in
                guard let self else { return }
                self.bridge.enqueue {
                    self.assumeIsolated { me in
                        guard !me.closed else { return }
                        me.reportFailure("Write", error: error)
                        me.abort()
                    }
                }
            }
        }
        if !seed.isEmpty { stream.assumeIsolated { $0.seedUpload(seed) } }
        if uplinkDone { stream.assumeIsolated { $0.deliverUploadEOF() } }
        let context = RelayContext(stack: stack, routeTarget: routeTarget)
        relayTask = Task {
            await self.runRelay(connection, stream: stream, context: context)
        }
    }
    
    private struct RelayContext: Sendable {
        weak var stack: TunnelStack?
        let routeTarget: RouteTarget
    }
    
    @concurrent
    private nonisolated func runRelay(_ connection: ProxyConnection, stream: TCPStreamConcurrencyBridge, context: RelayContext) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.runUploadRelay(connection, stream, context: context) }
            group.addTask { await self.runDownloadRelay(connection, stream, context: context) }
        }
        await relayFinished()
    }
    
    @concurrent
    private nonisolated func runUploadRelay(_ connection: ProxyConnection, _ stream: TCPStreamConcurrencyBridge, context: RelayContext) async {
        var unacked = 0
        while let chunk = await stream.receiveUpload(acking: unacked) {
            do {
                try await connection.send(chunk)
            } catch {
                await relayFailed("Send", error: error)
                return
            }
            markActivity()
            context.stack?.addBytesOut(Int64(chunk.count), target: context.routeTarget)
            unacked = chunk.count
        }
    }
    
    @concurrent
    private nonisolated func runDownloadRelay(_ connection: ProxyConnection, _ stream: TCPStreamConcurrencyBridge, context: RelayContext) async {
        while true {
            let data: Data?
            do {
                data = try await connection.receive()
            } catch {
                await relayFailed("Receive", error: error)
                return
            }
            guard let data, !data.isEmpty else { break }
            if stream.canPushDownload {
                stream.pushDownload(data)
            } else {
                do {
                    try await stream.sendDownload(data)
                } catch {
                    if case AnywhereError.transport(.writeFailed) = error {
                        await relayFailed("Write", error: error)
                    }
                    return
                }
            }
            markActivity()
            context.stack?.addBytesIn(Int64(data.count), target: context.routeTarget)
        }
        await downlinkReachedEOF()
        await stream.awaitDownloadDrained()
    }
    
    private func relayFailed(_ operation: String, error: Error) {
        guard !closed else { return }
        reportFailure(operation, error: error)
        abort()
    }
    private func downlinkReachedEOF() {
        guard !closed else { return }
        downlinkDone = true
        if !uplinkDone { setIdleTimeout(TunnelConstants.uplinkOnlyTimeout) }
    }
    
    private func relayFinished() {
        guard !closed else { return }
        close()
    }
    
    private func acknowledgeReceivedBytes(_ byteCount: Int) {
        guard byteCount > 0 else { return }
        stack?.addBytesOut(Int64(byteCount), target: routeTarget)
        var remaining = byteCount
        while remaining > 0 {
            let part = UInt16(min(remaining, Int(UInt16.max)))
            remaining -= Int(part)
            bridge.tcpRecved(pcb, part)
        }
        bridge.tcpOutput(pcb)
    }
    
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
    
    func handleError(err: Int32) {
        let reason = AnywhereError.Transport.lwipName(err)
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
    
    private func settlePendingAdmission() {
        guard pendingAdmissionCounted else { return }
        pendingAdmissionCounted = false
        FlowGauge.decrementPendingTCP()
    }

    private func handleConnectFailure(_ error: Error, bufferedClientData: Data?) {
        failureReporter.report(operation: "Connect", endpoint: endpointDescription,
                               error: error, context: DialDiagnostics.snapshot(bridge: bridge))
        guard case AnywhereError.dns(.resolutionFailed) = error else {
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
    
    private func bufferedBytesAreTLSHandshake() -> Bool {
        var iterator = pendingData.makeIterator()
        return iterator.next() == 0x16 && iterator.next() == 0x03
    }

    // MARK: - Route Commit
    
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

        switch match.action {
        case .direct:
            ruleSetName = match.ruleSetName
            routeTarget = .direct
            stack.requestLog.record(protocol: .tcp, host: sni, port: dstPort, routeTarget: .direct, ruleSetName: match.ruleSetName)
        case .reject:
            ruleSetName = match.ruleSetName
            routeTarget = .reject
            stack.requestLog.record(protocol: .tcp, host: sni, port: dstPort, routeTarget: .reject, ruleSetName: match.ruleSetName)
            logger.debug("[TCP] SNI rejected by routing rule: \(sni) (\(dstHost):\(dstPort))")
            rejectWithTLSAlert()
        case .proxy(let id):
            // The domain rule wins over any IP-CIDR route set at accept time — but only with
            // its configuration in hand. Committing `.proxy(id)` while keeping the accept-time
            // configuration would dial a proxy the request log doesn't show.
            guard let resolved = router.resolveConfiguration(action: match.action) else {
                logger.report("[TCP] SNI route", error: AnywhereError.routing(.configurationMissing(host: sni)))
                return
            }
            ruleSetName = match.ruleSetName
            routeTarget = .proxy(id)
            configuration = resolved
            stack.requestLog.record(protocol: .tcp, host: sni, port: dstPort, routeTarget: .proxy(id), ruleSetName: match.ruleSetName)
        }
    }
    
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
    
    private func startIdleTimer() {
        idleTimeout = initialIdleTimeout
        markActivity()
        idleActive = true
        scheduleIdleCheck(after: idleTimeout)
    }
    
    private nonisolated func markActivity() {
        lastActivityTick.store(MonotonicClock.now, ordering: .relaxed)
    }
    
    private func setIdleTimeout(_ timeout: TimeInterval) {
        guard idleActive else { return }
        if timeout <= 0 {
            cancelIdleTimer()
            close()
            return
        }
        idleTimeout = timeout
        let elapsed = MonotonicClock.now - lastActivityTick.load(ordering: .relaxed)
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
    
    private func scheduleIdleCheck(after delay: TimeInterval) {
        idleCheckTask?.cancel()
        guard idleActive, delay > 0 else { return }
        idleCheckTask = Task {
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled else { return }
            checkIdle()
        }
    }

    /// Runs on the actor: closes if idle past `idleTimeout`, else re-arms for the remaining window.
    private func checkIdle() {
        guard !closed, idleActive, idleTimeout > 0 else { return }
        let elapsed = MonotonicClock.now - lastActivityTick.load(ordering: .relaxed)
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
        
        let stream = TCPStreamConcurrencyBridge(bridge: bridge, pcb: LWIPPCBHandle(raw: pcb))
        self.stream = stream
        stream.assumeIsolated { s in
            s.onFatalWrite = { [weak self] error in
                guard let self else { return }
                self.bridge.enqueue {
                    self.assumeIsolated { me in
                        guard !me.closed else { return }
                        me.reportFailure("MITM downlink", error: error)
                        me.abort()
                    }
                }
            }
        }
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
            guard let self else { throw AnywhereError.transport(.notConnected) }
            // Hops onto the actor (lwIP executor); the deadline race and route commit run there.
            return try await self.dialUpstreamBounded(host: host, port: port)
        }
    }
    
    private func dialUpstreamBounded(host: String, port: UInt16) async throws -> MITMDialResult {
        guard !closed else { throw AnywhereError.transport(.notConnected) }
        switch commitUpstreamRoute(forDialHost: host, port: port) {
        case .reject:
            throw AnywhereError.routing(.rejectedByRule(host: host))
        case .direct:
            return try await dialDirectUpstream(host: host, port: port)
        case .proxy(_, let configuration):
            return try await dialProxyUpstream(configuration: configuration, host: host, port: port)
        }
    }

    private enum DialRace<T: Sendable>: Sendable { case value(T), timedOut }
    
    private func raceHandshakeDeadline<T: Sendable>(
        cancelOnTimeout: @escaping @Sendable () -> Void,
        _ body: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: DialRace<T>.self) { group in
            group.addTask { .value(try await body()) }
            group.addTask {
                try await Task.sleep(for: .seconds(TunnelConstants.handshakeTimeout))
                return .timedOut
            }
            defer { group.cancelAll() }
            while let next = try await group.next() {
                switch next {
                case .value(let value):
                    return value
                case .timedOut:
                    cancelOnTimeout()   // abort the in-flight handshake so `body` unwinds
                    throw AnywhereError.transport(.timedOut(.connect, endpoint: nil, detail: "upstream dial"))
                }
            }
            throw AnywhereError.transport(.timedOut(.connect, endpoint: nil, detail: "upstream dial"))
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
                logger.report("[TCP] MITM dial route", error: AnywhereError.routing(.configurationMissing(host: host)))
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
