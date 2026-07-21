//
//  TCPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TCPConnection")

actor TCPConnection: MITMSessionHost {

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
    
    private var rootTask: Task<Void, Never>?

    private let acceptedViaDefault: Bool

    private var routeTarget: RouteTarget
    private var ruleSetName: String?

    private var bypass: Bool {
        if case .direct = routeTarget { return true }
        return false
    }

    private var pendingData = Data()
    private var closed = false
    
    private enum EstablishSignal: Sendable { case data, clientFIN }
    private var establishing = true
    private let establishInbox = AsyncInbox<EstablishSignal>()
    
    // MARK: MITM

    private var mitmEnabled = false
    private var mitmPlaintext = false
    private var mitmSNI: String?
    private var mitmSession: MITMSession?
    
    private let hostIsResolvedDomain: Bool

    // MARK: SNI / HTTP Sniffing
    
    private var sniffer: TLSClientHelloSniffer?
    private var httpSniffer: HTTPRequestSniffer?
    private var sniffFedOffset = 0

    // MARK: Relay

    private var stream: TCPStreamConcurrencyBridge?

    // MARK: - Idle timer

    private var idleActive = false
    private var idleTimeoutValue: TimeInterval = 0
    private nonisolated let lastActivityTick = Atomic<TimeInterval>(0)
    private nonisolated let idlePoke = AsyncInbox<Void>(capacity: 1)

    // MARK: - Half-close

    private var uplinkDone = false
    private var downlinkDone = false
    private var closePending = false

    // MARK: - Nursery jobs

    private struct DialJob: Sendable {
        let id: Int
        let route: DialRoute
        let host: String
        let port: UInt16
    }
    private enum DialRoute: Sendable {
        case direct
        case proxy(configuration: ProxyConfiguration, isDefault: Bool)
    }
    private enum NurseryJob: Sendable {
        case dial(DialJob)
        case drainThenClose
    }
    private let nurseryJobs: AsyncStream<NurseryJob>
    private nonisolated let nurseryJobContinuation: AsyncStream<NurseryJob>.Continuation
    
    private var dialWaiters: [Int: CheckedContinuation<MITMDialResult, Error>] = [:]
    private var nextDialID = 0

    private let failureReporter = ConnectionFailureReporter(prefix: "[TCP]", logger: logger)

    private var pendingAdmissionCounted = true

    // MARK: Lifecycle
    
    init(
        stack: TunnelStack,
        pcb: LWIPPCBHandle, dstHost: String, dstPort: UInt16,
        configuration: ProxyConfiguration, routeTarget: RouteTarget,
        viaDefault: Bool,
        ruleSetName: String? = nil,
        sniffSNI: Bool = false,
        hostIsResolvedDomain: Bool = false,
        bridge: LWIPConcurrencyBridge
    ) {
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
        (self.nurseryJobs, self.nurseryJobContinuation) = AsyncStream.makeStream(of: NurseryJob.self)

        if sniffSNI {
            self.sniffer = TLSClientHelloSniffer()
        }
    }
    
    nonisolated func adopt() -> UnsafeMutableRawPointer {
        assumeIsolated { $0.start() }
        return BridgeContext.passRetained(self)
    }

    private func start() {
        rootTask = Task { await self.run() }
    }
    
    private func run() async {
        await withDiscardingTaskGroup { group in
            group.addTask { await self.runLifecycle() }
            group.addTask { await self.runIdleWatch() }
            for await job in self.nurseryJobs {
                switch job {
                case .dial(let dial):
                    group.addTask { await self.runDial(dial) }
                case .drainThenClose:
                    group.addTask { await self.runDrainThenClose() }
                }
            }
        }
    }

    deinit {
        guard pendingAdmissionCounted else { return }
        FlowGauge.decrementPendingTCP()
        logger.error("[TCP] Connection deallocated with its admission still counted — teardown never ran. Recovered the FlowGauge count in deinit; a teardown path has regressed.")
    }

    // MARK: - Lifecycle flow
    
    private func runLifecycle() async {
        let outcome = await withHandshakeDeadline { await self.establishAndDial() }
        switch outcome {
        case .relay(let connection, let stream, let seed):
            await runRelayAndClose(connection, stream: stream, seed: seed)
        case .mitm, .done:
            return
        }
    }

    private enum Establishment {
        case relay(ProxyConnection, TCPStreamConcurrencyBridge, seed: Data)
        case mitm
        case done
    }
    
    private func withHandshakeDeadline(_ operation: @escaping @Sendable () async -> Establishment) async -> Establishment {
        await withTaskGroup(of: Establishment?.self) { group in
            group.addTask { Optional(await operation()) }
            group.addTask {
                try? await Task.sleep(for: .seconds(TunnelConstants.handshakeTimeout))
                return nil
            }
            defer { group.cancelAll() }
            while let next = await group.next() {
                if let established = next {
                    return established
                }
                handshakeTimedOutDuringEstablishment()
                return .done
            }
            return .done
        }
    }

    private func handshakeTimedOutDuringEstablishment() {
        guard !closed, establishing else { return }
        let phase = isSniffing ? "protocol sniff" : (bypass ? "direct dial" : "proxy dial")
        failureReporter.report(
            operation: "Handshake",
            endpoint: endpointDescription,
            error: AnywhereError.transport(.timedOut(.connect, endpoint: nil, detail: phase))
        )
        abort()
    }

    private func establishAndDial() async -> Establishment {
        await runSniffPhase()
        guard !closed else { return .done }
        return await beginConnecting()
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

    // MARK: - Protocol sniff
    
    private func runSniffPhase() async {
        guard sniffer != nil else { return }
        await withSniffDeadline { await self.runSniffLoop() }
    }

    private func withSniffDeadline(_ loop: @escaping @Sendable () async -> Void) async {
        await withTaskGroup(of: Bool.self) { group in
            group.addTask { await loop(); return true }
            group.addTask {
                try? await Task.sleep(for: .seconds(TunnelConstants.sniffDeadline))
                return false
            }
            defer { group.cancelAll() }
            if let first = await group.next(), first == false {
                sniffDeadlineFired()
            }
        }
    }
    
    private func sniffDeadlineFired() {
        guard !closed, isSniffing else { return }
        sniffer = nil
        httpSniffer = nil
    }
    
    private func runSniffLoop() async {
        while true {
            feedSniffState()
            if closed || !isSniffing { return }
            let signal: EstablishSignal?
            do {
                signal = try await establishInbox.next()
            } catch {
                return
            }
            guard let signal else { return }
            if case .clientFIN = signal {
                handleFINDuringSniff()
                return
            }
        }
    }
    
    private func feedSniffState() {
        guard !closed else { return }
        let delta = sniffDelta()

        if sniffer != nil {
            guard !delta.isEmpty else { return }
            guard let state = sniffer?.feed(delta) else { return }
            switch state {
            case .needMore:
                return
            case .found(let sni):
                sniffer = nil
                applySNI(sni)
                return
            case .notTLS:
                sniffer = nil
                if mitmCanInterceptPlaintext {
                    var http = HTTPRequestSniffer()
                    let httpState = http.feed(pendingData)
                    httpSniffer = http
                    sniffFedOffset = pendingData.count
                    handleHTTPSniff(httpState)
                }
                return
            case .unavailable:
                sniffer = nil
                return
            }
        }

        if httpSniffer != nil {
            guard !delta.isEmpty else { return }
            if let state = httpSniffer?.feed(delta) {
                handleHTTPSniff(state)
            }
            return
        }
    }
    
    private func sniffDelta() -> Data {
        guard sniffFedOffset < pendingData.count else { return Data() }
        let delta = pendingData.subdata(in: sniffFedOffset..<pendingData.count)
        sniffFedOffset = pendingData.count
        return delta
    }

    private func handleHTTPSniff(_ state: HTTPRequestSniffer.State) {
        switch state {
        case .needMore:
            return
        case .found(let authority):
            httpSniffer = nil
            applyHTTPMITM(authority: authority)
        case .notHTTP:
            httpSniffer = nil
        }
    }
    
    private func handleFINDuringSniff() {
        sniffer = nil
        httpSniffer = nil
        if pendingData.isEmpty {
            close()
        }
    }

    private func applySNI(_ sni: String) {
        guard let stack else { return }

        if stack.mitmEnabled, stack.mitmPolicy.matches(sni) {
            mitmEnabled = true
            mitmSNI = sni
            return
        }

        let router = stack.domainRouter
        guard let match = router.matchDomain(sni) else {
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

    private func applyHTTPMITM(authority: String?) {
        guard let stack, stack.mitmEnabled else { return }
        let matchHost = hostIsResolvedDomain ? dstHost : authority
        guard let matchHost, stack.mitmPolicy.matches(matchHost) else { return }
        mitmEnabled = true
        mitmPlaintext = true
        mitmSNI = matchHost
    }

    // MARK: - Route commit / dial

    private func beginConnecting() async -> Establishment {
        guard !closed else { return .done }
        if mitmEnabled {
            return startMITMSession()
        }
        if bypass {
            return await connectDirect()
        }
        return await connectProxy()
    }

    // MARK: Direct connection (bypass)

    private func connectDirect() async -> Establishment {
        settlePendingAdmission()

        let initialData: Data? = pendingData.isEmpty ? nil : pendingData
        if initialData != nil {
            pendingData.removeAll(keepingCapacity: true)
        }

        let transport = TCPTransport(host: dstHost, port: dstPort)
        let connection = DirectProxyConnection(transport: transport)
        self.proxyConnection = connection

        let error: Error?
        do {
            try await transport.connect()
            error = nil
        } catch let dialError {
            error = dialError
        }
        
        guard !closed else { return .done }

        if let error {
            return handleConnectFailure(error, bufferedClientData: initialData)
        }

        let stream = TCPStreamConcurrencyBridge(bridge: bridge, pcb: LWIPPCBHandle(raw: pcb))
        self.stream = stream
        establishing = false
        startIdleTimer()

        var seed = Data()
        if let initialData { seed.append(initialData) }
        if !pendingData.isEmpty {
            seed.append(pendingData)
            pendingData.removeAll(keepingCapacity: true)
        }
        return .relay(connection, stream, seed: seed)
    }

    // MARK: Proxy connection

    private func connectProxy() async -> Establishment {
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

        let result: Result<ProxyConnection, Error>
        do {
            result = .success(try await client.connect(to: host, port: port, initialData: initialData))
        } catch {
            result = .failure(error)
        }
        
        guard !closed else {
            if case .success(let connection) = result { connection.cancel() }
            return .done
        }

        switch result {
        case .success(let proxyConnection):
            self.proxyConnection = proxyConnection
            let stream = TCPStreamConcurrencyBridge(bridge: bridge, pcb: LWIPPCBHandle(raw: pcb))
            self.stream = stream
            establishing = false
            startIdleTimer()
            if let initialData {
                // Connect success implies the handshake-carried initialData was accepted.
                acknowledgeReceivedBytes(initialData.count)
            }
            var seed = Data()
            if !pendingData.isEmpty {
                seed.append(pendingData)
                pendingData.removeAll(keepingCapacity: true)
            }
            return .relay(proxyConnection, stream, seed: seed)

        case .failure(let error):
            return handleConnectFailure(error, bufferedClientData: initialData)
        }
    }
    
    private func handleConnectFailure(
        _ error: Error,
        bufferedClientData: Data?
    ) -> Establishment {
        failureReporter.report(
            operation: "Connect",
            endpoint: endpointDescription,
            error: error
        )
        guard case AnywhereError.dns(.resolutionFailed) = error else {
            abort()
            return .done
        }
        if let bufferedClientData, !bufferedClientData.isEmpty {
            pendingData = bufferedClientData + pendingData
        }
        if bufferedBytesAreTLSHandshake() {
            rejectWithTLSAlert()
        } else {
            rejectGracefully()
        }
        return .done
    }

    private func bufferedBytesAreTLSHandshake() -> Bool {
        var iterator = pendingData.makeIterator()
        return iterator.next() == 0x16 && iterator.next() == 0x03
    }

    // MARK: - Relay

    private func runRelayAndClose(_ connection: ProxyConnection, stream: TCPStreamConcurrencyBridge, seed: Data) async {
        startRelaySetup(connection, stream: stream, seed: seed)
        let context = RelayContext(stack: stack, routeTarget: routeTarget)
        await runRelay(connection, stream: stream, context: context)
        relayFinished()
    }

    private func startRelaySetup(_ connection: ProxyConnection, stream: TCPStreamConcurrencyBridge, seed: Data) {
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
            lwip_bridge_tcp_recved(pcb, part)
        }
        lwip_bridge_tcp_output(pcb)
    }

    // MARK: - lwIP callbacks

    func handleReceivedData(bytes ptr: UnsafeRawPointer, count: Int) {
        guard !closed, count > 0 else { return }
        markActivity()

        let bytePtr = ptr.assumingMemoryBound(to: UInt8.self)

        if let mitmSession {
            let chunk = Data(bytes: bytePtr, count: count)
            acknowledgeReceivedBytes(count)
            mitmSession.assumeIsolated { $0.feedClientBytes(chunk) }
            return
        }

        if let stream {
            let uploadChunk = Data(bytes: ptr, count: count)
            stream.assumeIsolated { $0.deliverUpload(uploadChunk) }
            return
        }
        
        guard appendPendingData(bytes: bytePtr, count: count) else { return }
        establishInbox.yield(.data)
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

    func handleSent(len: UInt16) {
        guard !closed else { return }
        stream?.assumeIsolated { $0.deliverSendCredit() }
    }

    func handleRemoteClose() {
        guard !closed else { return }

        if establishing {
            uplinkDone = true
            establishInbox.yield(.clientFIN)
            return
        }
        
        mitmSession?.assumeIsolated { $0.clientDidClose() }

        uplinkDone = true
        if let stream {
            stream.assumeIsolated { $0.deliverUploadEOF() }
            if !downlinkDone { setIdleTimeout(TunnelConstants.downlinkOnlyTimeout) }
        } else if !downlinkDone {
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
        failureReporter.markReported()
        guard !closed else { return }
        closed = true
        teardown(abortive: true)
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

    // MARK: - Idle timer

    private func startIdleTimer() {
        idleTimeoutValue = initialIdleTimeout
        markActivity()
        idleActive = true
        pokeIdle()
    }

    private nonisolated func markActivity() {
        lastActivityTick.store(MonotonicClock.now, ordering: .relaxed)
    }

    private func setIdleTimeout(_ timeout: TimeInterval) {
        guard idleActive else { return }
        if timeout <= 0 {
            idleActive = false
            close()
            return
        }
        idleTimeoutValue = timeout
        let elapsed = MonotonicClock.now - lastActivityTick.load(ordering: .relaxed)
        if elapsed >= timeout {
            idleActive = false
            close()
            return
        }
        pokeIdle()
    }

    private func pokeIdle() {
        idlePoke.yield(())
    }

    private enum IdleAction { case stop, waitActivation, sleep(TimeInterval), fire }

    private func idleNextAction() -> IdleAction {
        if closed { return .stop }
        if !idleActive { return .waitActivation }
        let elapsed = MonotonicClock.now - lastActivityTick.load(ordering: .relaxed)
        if elapsed >= idleTimeoutValue { return .fire }
        return .sleep(idleTimeoutValue - elapsed)
    }
    
    private func idleFireAndReport() -> Bool {
        guard !closed, idleActive else { return true }
        let elapsed = MonotonicClock.now - lastActivityTick.load(ordering: .relaxed)
        if elapsed >= idleTimeoutValue {
            idleActive = false
            close()
            return true
        }
        return false
    }

    private nonisolated func runIdleWatch() async {
        while true {
            switch await idleNextAction() {
            case .stop:
                return
            case .waitActivation:
                if (try? await idlePoke.next()) == nil { return }
            case .sleep(let seconds):
                await sleepOrPoke(seconds: seconds)
            case .fire:
                if await idleFireAndReport() { return }
            }
        }
    }
    
    private nonisolated func sleepOrPoke(seconds: TimeInterval) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                do { try await Task.sleep(for: .seconds(seconds)) } catch { }
            }
            group.addTask { _ = try? await self.idlePoke.next() }
            _ = await group.next()
            group.cancelAll()
        }
    }

    // MARK: - MITM session

    private func startMITMSession() -> Establishment {
        guard let stack else { abort(); return .done }
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
                return .done
            }
        }

        startIdleTimer()

        let initialClientHello = pendingData
        pendingData.removeAll(keepingCapacity: true)

        let session = MITMSession(
            dstHost: sni,
            dstPort: dstPort,
            clientHello: initialClientHello,
            leafCache: cache,
            policy: stack.mitmPolicy,
            lwipBridge: bridge,
            isPlaintext: mitmPlaintext
        )
        session.assumeIsolated { $0.host = self }

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
        mitmSession = session
        establishing = false

        if !initialClientHello.isEmpty {
            acknowledgeReceivedBytes(initialClientHello.count)
        }

        session.assumeIsolated { $0.start(sni: sni) }
        return .mitm
    }

    private enum UpstreamRoute {
        case direct
        case reject
        case proxy(routeTarget: RouteTarget, configuration: ProxyConfiguration)
    }

    // MARK: - MITMSessionHost
    
    func mitmDialUpstream(host: String, port: UInt16) async throws -> MITMDialResult {
        guard !closed else { throw AnywhereError.transport(.notConnected) }
        let route: DialRoute
        switch commitUpstreamRoute(forDialHost: host, port: port) {
        case .reject:
            throw AnywhereError.routing(.rejectedByRule(host: host))
        case .direct:
            route = .direct
        case .proxy(_, let configuration):
            route = .proxy(configuration: configuration,
                           isDefault: stack?.isDefaultConfiguration(configuration.id) ?? false)
        }

        nextDialID += 1
        let id = nextDialID
        return try await withCheckedThrowingContinuation { continuation in
            guard !closed else {
                continuation.resume(throwing: AnywhereError.transport(.terminated))
                return
            }
            dialWaiters[id] = continuation
            nurseryJobContinuation.yield(.dial(DialJob(id: id, route: route, host: host, port: port)))
        }
    }
    
    private func runDial(_ job: DialJob) async {
        let result: Result<MITMDialResult, Error>
        if closed {
            result = .failure(AnywhereError.transport(.terminated))
        } else {
            do {
                result = .success(try await performDial(job))
            } catch {
                result = .failure(error)
            }
        }
        deliverDial(id: job.id, result: result)
    }

    private func deliverDial(id: Int, result: Result<MITMDialResult, Error>) {
        guard let waiter = dialWaiters.removeValue(forKey: id) else {
            if case .success(let dial) = result {
                dial.connection.cancel()
                dial.proxyClient?.cancel()
            }
            return
        }
        waiter.resume(with: result)
    }

    private static var upstreamDialTimeout: AnywhereError {
        .transport(.timedOut(.connect, endpoint: nil, detail: "upstream dial"))
    }

    private func performDial(_ job: DialJob) async throws -> MITMDialResult {
        switch job.route {
        case .direct:
            return try await dialDirectUpstream(host: job.host, port: job.port)
        case .proxy(let configuration, let isDefault):
            return try await dialProxyUpstream(configuration: configuration, isDefault: isDefault,
                                               host: job.host, port: job.port)
        }
    }

    private func dialDirectUpstream(host: String, port: UInt16) async throws -> MITMDialResult {
        let transport = TCPTransport(host: host, port: port)
        let connection = DirectProxyConnection(transport: transport)
        do {
            try await withDialDeadline(.seconds(TunnelConstants.handshakeTimeout), onExpiry: {
                connection.cancel()
            }, error: {
                Self.upstreamDialTimeout
            }) {
                try await withTaskCancellationHandler {
                    try await transport.connect()
                } onCancel: {
                    connection.cancel()
                }
            }
            return MITMDialResult(connection: connection, proxyClient: nil)
        } catch {
            connection.cancel()
            throw error
        }
    }

    private func dialProxyUpstream(configuration: ProxyConfiguration, isDefault: Bool,
                                   host: String, port: UInt16) async throws -> MITMDialResult {
        let client = ProxyClient(configuration: configuration, isDefaultProxy: isDefault)
        do {
            let connection = try await withDialDeadline(.seconds(TunnelConstants.handshakeTimeout), onExpiry: {
                client.cancel()
            }, error: {
                Self.upstreamDialTimeout
            }) {
                try await withTaskCancellationHandler {
                    try await client.connect(to: host, port: port, initialData: nil)
                } onCancel: {
                    // Structural cancellation (connection teardown) unblocks the in-flight connect.
                    client.cancel()
                }
            }
            return MITMDialResult(connection: connection, proxyClient: client)
        } catch {
            await client.cancel()
            throw error
        }
    }

    nonisolated func mitmSessionSendToClient(_ data: Data) {
        bridge.enqueue {
            self.assumeIsolated { me in
                guard !me.closed, let stream = me.stream else { return }
                me.markActivity()
                stream.assumeIsolated { $0.deliverDownload(data) }
            }
        }
    }

    nonisolated func mitmSessionDidTearDown(error: Error?) {
        bridge.enqueue {
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
            let route: UpstreamRoute = bypass ? .direct : .proxy(routeTarget: routeTarget, configuration: configuration)
            return (route, acceptedViaDefault, ruleSetName)
        }
        return (defaultUpstreamRoute(), true, nil)
    }

    private func defaultUpstreamRoute() -> UpstreamRoute {
        guard let config = stack?.udpConfig(),
              case .proxy = config.defaultRouteTarget,
              let configuration = config.configuration else {
            return .direct
        }
        return .proxy(routeTarget: config.defaultRouteTarget, configuration: configuration)
    }

    // MARK: - Close / abort / teardown

    private func closeWhenDrained() {
        guard !closed else { return }
        guard stream != nil else { close(); return }
        closePending = true
        setIdleTimeout(TunnelConstants.downlinkOnlyTimeout)
        nurseryJobContinuation.yield(.drainThenClose)
    }

    private func runDrainThenClose() async {
        guard let stream = self.stream else {
            completeDeferredClose()
            return
        }
        await stream.awaitDownloadDrained()
        completeDeferredClose()
    }

    private func completeDeferredClose() {
        guard closePending, !closed else { return }
        close()
    }

    func close() {
        guard !closed else { return }
        closed = true
        stream?.assumeIsolated { $0.flushBestEffort() }
        relinquishPCB(abortive: false)
        teardown(abortive: false)
    }

    func abort() {
        guard !closed else { return }
        closed = true
        relinquishPCB(abortive: true)
        teardown(abortive: true)
    }
    
    private func relinquishPCB(abortive: Bool) {
        if abortive {
            lwip_bridge_tcp_abort(pcb)
        } else {
            lwip_bridge_tcp_close(pcb)
        }
        BridgeContext.release(self)
    }

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

    private func rejectWithTLSAlert() {
        guard !closed else { return }
        // type=21 (alert), legacy_record_version=0x0303 (TLS 1.2),
        // length=2, level=2 (fatal), description=49 (access_denied)
        let alert: [UInt8] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x31]
        writeImmediate(Data(alert))
        rejectGracefully()
    }
    
    private func writeImmediate(_ data: Data) {
        guard !data.isEmpty else { return }
        var written = 0
        data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            while written < data.count {
                let sndbuf = Int(lwip_bridge_tcp_sndbuf(pcb))
                guard sndbuf > 0 else { break }
                let chunk = min(min(sndbuf, data.count - written), TunnelConstants.tcpMaxWriteSize)
                guard lwip_bridge_tcp_write(pcb, base + written, UInt16(chunk)) == 0 else { break }
                written += chunk
            }
        }
        if written > 0 { lwip_bridge_tcp_output(pcb) }
    }
    
    private func teardown(abortive: Bool) {
        settlePendingAdmission()
        
        for (_, waiter) in dialWaiters {
            waiter.resume(throwing: AnywhereError.transport(.terminated))
        }
        dialWaiters.removeAll()
        
        nurseryJobContinuation.finish()
        establishInbox.finish()

        idleActive = false

        let connection = proxyConnection
        let client = proxyClient
        let session = mitmSession
        let stream = self.stream
        proxyConnection = nil
        proxyClient = nil
        self.stream = nil
        mitmSession = nil
        sniffer = nil
        httpSniffer = nil
        pendingData = Data()
        establishing = false
        
        session?.assumeIsolated { $0.cancel(error: nil) }
        stream?.assumeIsolated { $0.terminate() }
        if abortive {
            connection?.abort()
        } else {
            connection?.cancel()
        }
        client?.cancel()
        
        rootTask?.cancel()
        rootTask = nil
    }
}
