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

    private var routeTarget: RouteTarget
    private var ruleSetName: String?

    private var ruleMatched: Bool

    private var bypass: Bool {
        let resolved = routeTarget.resolved(against: stack?.udpConfig().defaultRouteTarget ?? .direct)
        if case .direct = resolved { return true }
        return false
    }

    private var pendingData = Data()

    private enum Phase: PhaseTransitionable {
        case establishing
        case relaying
        case closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.establishing, .relaying):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }

    private var phase: Phase = .establishing

    @discardableResult
    private func transition(to new: Phase) -> Bool {
        let old = phase
        guard Phase.transition(&phase, to: new) else {
            if new != .closed {
                logger.error("[TCP] Invalid transition \(old) → \(new) for \(endpointDescription); ignored")
            }
            return false
        }
        return true
    }

    private let establishInbox = AsyncInbox<Void>()

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
    private var sniffedSNI: String?

    // MARK: Relay

    private var stream: TCPStreamConcurrencyBridge?

    // MARK: - Idle timer

    private var idleActive = false
    private var idleTimeoutValue: TimeInterval = 0
    private nonisolated let lastActivityTick = Atomic<TimeInterval>(0)
    private nonisolated let idlePoke = AsyncInbox<Void>(capacity: 1)

    // MARK: - Deferred close

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

    // MARK: Lifecycle

    init(
        stack: TunnelStack,
        pcb: LWIPPCBHandle, dstHost: String, dstPort: UInt16,
        configuration: ProxyConfiguration, routeTarget: RouteTarget,
        ruleSetName: String? = nil,
        sniffSNI: Bool = false,
        hostIsResolvedDomain: Bool = false,
        bridge: LWIPConcurrencyBridge
    ) {
        self.stack = stack
        self.pcb = pcb.raw
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.configuration = configuration
        self.bridge = bridge
        self.routeTarget = routeTarget
        self.ruleMatched = ruleSetName != nil
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

    // MARK: - Lifecycle flow

    private func runLifecycle() async {
        let outcome = await withHandshakeDeadline { await self.establishAndDial() }
        switch outcome {
        case .relay(let connection, let stream):
            await runRelayAndClose(connection, stream: stream)
        case .mitm, .done:
            return
        }
    }

    private enum Establishment {
        case relay(ProxyConnection, TCPStreamConcurrencyBridge)
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
                guard phase == .establishing else { continue }
                handshakeTimedOutDuringEstablishment()
                return .done
            }
            return .done
        }
    }

    private func handshakeTimedOutDuringEstablishment() {
        guard phase == .establishing else { return }
        let stage = isSniffing ? "protocol sniff" : (bypass ? "direct dial" : "proxy dial")
        failureReporter.report(
            operation: "Handshake",
            endpoint: endpointDescription,
            error: AnywhereError.transport(.timedOut(.connect, endpoint: nil, detail: stage))
        )
        abort()
    }

    private func establishAndDial() async -> Establishment {
        await runSniffPhase()
        guard phase != .closed else { return .done }
        await applyIPRuleMatch()
        guard phase != .closed else { return .done }
        return await beginConnecting()
    }

    private func applyIPRuleMatch() async {
        guard hostIsResolvedDomain, !ruleMatched, phase != .closed,
              let stack, !stack.connectionRouter.preventDNSLeak.load(ordering: .relaxed),
              let ip = await RuleResolver.shared.resolveIPv4(for: dstHost),
              phase != .closed, let match = stack.domainRouter.matchIP(ip)
        else { return }

        let router = stack.domainRouter
        switch match.action {
        case .default, .defaultProxy:
            ruleMatched = true
            ruleSetName = match.ruleSetName
            routeTarget = match.action
        case .direct:
            ruleMatched = true
            ruleSetName = match.ruleSetName
            routeTarget = .direct
        case .reject:
            ruleMatched = true
            ruleSetName = match.ruleSetName
            routeTarget = .reject
            stack.requestLog.record(protocol: .tcp, host: dstHost, port: dstPort, routeTarget: .reject, ruleSetName: match.ruleSetName)
            logger.debug("[TCP] Rejected by IP rule: \(dstHost) → \(ip):\(dstPort)")
            stack.fakeIPPool.markRejected(domain: dstHost)
            rejectSilently()
        case .proxy(let id):
            guard let resolved = router.resolveConfiguration(action: match.action) else {
                logger.report("[TCP] IP-rule route", error: AnywhereError.routing(.configurationMissing(host: dstHost)))
                return
            }
            ruleMatched = true
            ruleSetName = match.ruleSetName
            routeTarget = .proxy(id)
            configuration = resolved
        }
    }

    private var isSniffing: Bool {
        sniffer != nil || httpSniffer != nil
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
        guard phase != .closed, isSniffing else { return }
        sniffer = nil
        httpSniffer = nil
    }

    private func runSniffLoop() async {
        while true {
            feedSniffState()
            if phase == .closed || !isSniffing { return }
            if (try? await establishInbox.next()) == nil { return }
        }
    }

    private func feedSniffState() {
        guard phase != .closed else { return }
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

    private func applySNI(_ sni: String) {
        guard let stack else { return }
        sniffedSNI = sni

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
        case .default, .defaultProxy:
            ruleMatched = true
            ruleSetName = match.ruleSetName
            routeTarget = match.action
            if let defaultConfiguration = stack.udpConfig().configuration {
                configuration = defaultConfiguration
            }
        case .direct:
            ruleMatched = true
            ruleSetName = match.ruleSetName
            routeTarget = .direct
        case .reject:
            ruleMatched = true
            ruleSetName = match.ruleSetName
            routeTarget = .reject
            stack.requestLog.record(protocol: .tcp, host: sni, port: dstPort, routeTarget: .reject, ruleSetName: match.ruleSetName)
            logger.debug("[TCP] SNI rejected by routing rule: \(sni) (\(dstHost):\(dstPort))")
            rejectSilently()
        case .proxy(let id):
            guard let resolved = router.resolveConfiguration(action: match.action) else {
                logger.report("[TCP] SNI route", error: AnywhereError.routing(.configurationMissing(host: sni)))
                return
            }
            ruleMatched = true
            ruleSetName = match.ruleSetName
            routeTarget = .proxy(id)
            configuration = resolved
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
        guard phase != .closed else { return .done }
        if mitmEnabled {
            return startMITMSession()
        }
        stack?.requestLog.record(
            protocol: .tcp,
            host: sniffedSNI ?? dstHost,
            port: dstPort,
            routeTarget: routeTarget,
            ruleSetName: ruleSetName
        )
        if bypass {
            return await connectDirect()
        }
        return await connectProxy()
    }

    // MARK: Direct connection (bypass)

    private func connectDirect() async -> Establishment {
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

        guard phase != .closed else { return .done }

        if let error {
            return handleConnectFailure(error, bufferedClientData: initialData)
        }

        var seed = Data()
        if let initialData { seed.append(initialData) }
        if !pendingData.isEmpty {
            seed.append(pendingData)
            pendingData.removeAll(keepingCapacity: true)
        }
        return .relay(connection, installStream(seed: seed))
    }

    private func installStream(seed: Data) -> TCPStreamConcurrencyBridge {
        let stream = TCPStreamConcurrencyBridge(bridge: bridge, pcb: LWIPPCBHandle(raw: pcb))
        if !seed.isEmpty { stream.assumeIsolated { $0.seedUpload(seed) } }
        self.stream = stream
        transition(to: .relaying)
        startIdleTimer()
        return stream
    }

    // MARK: Proxy connection

    private func connectProxy() async -> Establishment {
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

        guard phase != .closed else {
            if case .success(let connection) = result { connection.cancel() }
            return .done
        }

        switch result {
        case .success(let proxyConnection):
            self.proxyConnection = proxyConnection
            var seed = Data()
            if !pendingData.isEmpty {
                seed.append(pendingData)
                pendingData.removeAll(keepingCapacity: true)
            }
            let stream = installStream(seed: seed)
            if let initialData {
                acknowledgeReceivedBytes(initialData.count)
            }
            return .relay(proxyConnection, stream)

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

    private func runRelayAndClose(_ connection: ProxyConnection, stream: TCPStreamConcurrencyBridge) async {
        startRelaySetup(stream: stream)
        let context = RelayContext(stack: stack, routeTarget: routeTarget)
        await runRelay(connection, stream: stream, context: context)
    }

    private func startRelaySetup(stream: TCPStreamConcurrencyBridge) {
        stream.assumeIsolated { s in
            s.onFatalWrite = { [weak self] error in
                guard let self else { return }
                self.bridge.enqueue {
                    self.assumeIsolated { me in
                        guard me.phase != .closed else { return }
                        me.reportFailure("Write", error: error)
                        me.abort()
                    }
                }
            }
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
            await group.next()
            await self.relayFinished()
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
            guard let data, !data.isEmpty else {
                await boundDownlinkDrain()
                break
            }
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
        await stream.awaitDownloadDrained()
    }

    private func boundDownlinkDrain() {
        guard phase != .closed else { return }
        markActivity()
        setIdleTimeout(TunnelConstants.drainBeforeCloseTimeout)
    }

    private func relayFailed(_ operation: String, error: Error) {
        guard phase != .closed else { return }
        reportFailure(operation, error: error)
        abort()
    }

    private func relayFinished() {
        guard phase != .closed else { return }
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
        guard phase != .closed, count > 0 else { return }
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
        establishInbox.yield(())
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
        guard phase != .closed else { return }
        stream?.assumeIsolated { $0.deliverSendCredit() }
    }

    func handleRemoteClose() {
        guard phase != .closed else { return }
        close()
    }

    func handleError(err: Int32) {
        let reason = AnywhereError.Transport.lwipName(err)
        if err == -15 { // ERR_CLSD — orderly close, not a failure
            logger.debug("[TCP] lwIP closed connection: \(endpointDescription): \(reason)")
        } else if err == -14 { // ERR_RST — always local-app-initiated in TUN mode
            logger.debug("[TCP] lwIP peer reset: \(endpointDescription): \(reason)")
        } else if err == -13, stack?.lwipAbortContext.load(ordering: .relaxed) == .teardown {
            // ERR_ABRT during deliberate teardown; otherwise it's an lwIP pressure abort and warns below.
            logger.debug("[TCP] lwIP aborted connection (tunnel teardown): \(endpointDescription): \(reason)")
        } else if err == -13, stack?.lwipAbortContext.load(ordering: .relaxed) == .pressureFlush {
            // ERR_ABRT from the pressure-cap flush: expected for every live
            // connection at once, and already announced by one warning there.
            logger.debug("[TCP] Connection flushed by pressure cap: \(endpointDescription)")
        } else {
            logger.warning("[TCP] lwIP aborted connection: \(endpointDescription): \(reason)")
        }
        failureReporter.markReported()
        finish(.lwipError)
    }

    private var endpointDescription: String {
        "\(dstHost):\(dstPort)"
    }

    private func reportFailure(_ operation: String, error: Error) {
        failureReporter.report(operation: operation, endpoint: endpointDescription, error: error)
    }

    // MARK: - Idle timer

    private func startIdleTimer() {
        idleTimeoutValue = TunnelConstants.connectionIdleTimeout
        markActivity()
        idleActive = true
        idlePoke.yield(())
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
        idlePoke.yield(())
    }

    private enum IdleAction { case stop, waitActivation, sleep(TimeInterval), fire }

    private func idleNextAction() -> IdleAction {
        if phase == .closed { return .stop }
        if !idleActive { return .waitActivation }
        let elapsed = MonotonicClock.now - lastActivityTick.load(ordering: .relaxed)
        if elapsed >= idleTimeoutValue { return .fire }
        return .sleep(idleTimeoutValue - elapsed)
    }

    private func idleFireAndReport() -> Bool {
        guard phase != .closed, idleActive else { return true }
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
                await idleSleep(seconds)
            case .fire:
                if await idleFireAndReport() { return }
            }
        }
    }

    private nonisolated func idleSleep(_ seconds: TimeInterval) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { try? await Task.sleep(for: .seconds(seconds)) }
            group.addTask { _ = try? await self.idlePoke.next() }
            defer { group.cancelAll() }
            _ = await group.next()
        }
    }

    // MARK: - MITM session

    private func startMITMSession() -> Establishment {
        guard let stack else { abort(); return .done }
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
                        guard me.phase != .closed else { return }
                        me.reportFailure("MITM downlink", error: error)
                        me.abort()
                    }
                }
            }
        }
        mitmSession = session
        transition(to: .relaying)

        if !initialClientHello.isEmpty {
            acknowledgeReceivedBytes(initialClientHello.count)
        }

        session.assumeIsolated { $0.start(sni: sni) }
        return .mitm
    }

    private enum UpstreamRoute {
        case route(target: RouteTarget, configuration: ProxyConfiguration?)
        case reject

        var target: RouteTarget {
            switch self {
            case .route(let target, _): return target
            case .reject: return .reject
            }
        }
    }

    // MARK: - MITMSessionHost

    func mitmDialUpstream(host: String, port: UInt16) async throws -> MITMDialResult {
        guard phase != .closed else { throw AnywhereError.transport(.notConnected) }
        let route: DialRoute
        switch await commitUpstreamRoute(forDialHost: host, port: port) {
        case .reject:
            throw AnywhereError.routing(.rejectedByRule(host: host))
        case .route(_, nil):
            route = .direct
        case .route(_, let configuration?):
            route = .proxy(configuration: configuration,
                           isDefault: stack?.isDefaultConfiguration(configuration.id) ?? false)
        }

        nextDialID += 1
        let id = nextDialID
        return try await withCheckedThrowingContinuation { continuation in
            guard phase != .closed else {
                continuation.resume(throwing: AnywhereError.transport(.terminated))
                return
            }
            dialWaiters[id] = continuation
            nurseryJobContinuation.yield(.dial(DialJob(id: id, route: route, host: host, port: port)))
        }
    }

    private func runDial(_ job: DialJob) async {
        let result: Result<MITMDialResult, Error>
        if phase == .closed {
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
                guard me.phase != .closed, let stream = me.stream else { return }
                me.markActivity()
                stream.assumeIsolated { $0.deliverDownload(data) }
            }
        }
    }

    nonisolated func mitmSessionDidTearDown(error: Error?) {
        bridge.enqueue {
            self.assumeIsolated { me in
                guard me.phase != .closed else { return }
                if let error {
                    me.reportFailure("MITM", error: error)
                    me.abort()
                } else {
                    me.closeWhenDrained()
                }
            }
        }
    }

    private func commitUpstreamRoute(forDialHost host: String, port: UInt16) async -> UpstreamRoute {
        let resolved = await resolveUpstreamRoute(forDialHost: host)
        stack?.requestLog.record(protocol: .tcp, host: host, port: port, routeTarget: resolved.route.target, ruleSetName: resolved.ruleSetName)
        guard phase != .closed else { return resolved.route }
        if host.caseInsensitiveCompare(mitmSNI ?? dstHost) == .orderedSame {
            routeTarget = resolved.route.target
            if case .route(_, let configuration?) = resolved.route {
                self.configuration = configuration
            }
            ruleSetName = resolved.ruleSetName
        }
        return resolved.route
    }

    private func resolveUpstreamRoute(forDialHost host: String) async -> (route: UpstreamRoute, ruleSetName: String?) {
        if let router = stack?.domainRouter, let match = router.matchDomain(host),
           let applied = upstreamRoute(applying: match, dialHost: host) {
            return applied
        }
        if host.caseInsensitiveCompare(mitmSNI ?? dstHost) == .orderedSame {
            let route: UpstreamRoute = .route(target: routeTarget, configuration: bypass ? nil : configuration)
            return (route, ruleSetName)
        }
        if let router = stack?.domainRouter,
           let ip = await ipRuleCandidate(forDialHost: host),
           let match = router.matchIP(ip),
           let applied = upstreamRoute(applying: match, dialHost: host) {
            return applied
        }
        return (defaultUpstreamRoute(), nil)
    }

    private func upstreamRoute(applying match: DomainRouter.Match, dialHost host: String) -> (route: UpstreamRoute, ruleSetName: String?)? {
        switch match.action {
        case .default, .defaultProxy:
            return (defaultUpstreamRoute(as: match.action), match.ruleSetName)
        case .direct:
            return (.route(target: .direct, configuration: nil), match.ruleSetName)
        case .reject:
            return (.reject, match.ruleSetName)
        case .proxy:
            guard let configuration = stack?.domainRouter.resolveConfiguration(action: match.action) else {
                logger.report("[TCP] MITM dial route", error: AnywhereError.routing(.configurationMissing(host: host)))
                return nil
            }
            return (.route(target: match.action, configuration: configuration), match.ruleSetName)
        }
    }

    private func ipRuleCandidate(forDialHost host: String) async -> String? {
        if let literal = Self.bareIPLiteral(host) { return literal }
        guard let stack, !stack.connectionRouter.preventDNSLeak.load(ordering: .relaxed) else { return nil }
        return await RuleResolver.shared.resolveIPv4(for: host)
    }

    nonisolated private static func bareIPLiteral(_ host: String) -> String? {
        let bare: String
        if host.hasPrefix("[") && host.hasSuffix("]") {
            bare = String(host.dropFirst().dropLast())
        } else {
            bare = host
        }
        var v4 = in_addr()
        if inet_pton(AF_INET, bare, &v4) == 1 { return bare }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, bare, &v6) == 1 { return bare }
        return nil
    }

    private func defaultUpstreamRoute(as target: RouteTarget = .default) -> UpstreamRoute {
        guard let config = stack?.udpConfig(), case .proxy = config.defaultRouteTarget else {
            return .route(target: target, configuration: nil)
        }
        return .route(target: target, configuration: config.configuration)
    }

    // MARK: - Close / abort / teardown

    private func closeWhenDrained() {
        guard phase != .closed else { return }
        guard stream != nil else { close(); return }
        closePending = true
        markActivity()
        setIdleTimeout(TunnelConstants.drainBeforeCloseTimeout)
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
        guard closePending, phase != .closed else { return }
        close()
    }

    private enum Exit {
        case graceful
        case abortive
        case silentReject
        case lwipError
    }

    private func finish(_ exit: Exit) {
        guard transition(to: .closed) else { return }
        switch exit {
        case .graceful:
            if let stream {
                stream.assumeIsolated {
                    $0.flushBestEffort()
                    $0.flushReceiveWindowForClose()
                }
            } else {
                flushPendingReceiveWindow()
            }
            lwip_bridge_tcp_close(pcb)
            BridgeContext.release(self)
            teardown(abortive: false)
        case .abortive:
            lwip_bridge_tcp_abort(pcb)
            BridgeContext.release(self)
            teardown(abortive: true)
        case .silentReject:
            lwip_bridge_tcp_discard(pcb)
            BridgeContext.release(self)
            teardown(abortive: true)
        case .lwipError:
            teardown(abortive: true)
        }
    }

    func close() {
        finish(.graceful)
    }

    func abort() {
        finish(.abortive)
    }

    private func rejectGracefully() {
        finish(.graceful)
    }

    private func flushPendingReceiveWindow() {
        guard !pendingData.isEmpty else { return }
        var remaining = pendingData.count
        pendingData.removeAll(keepingCapacity: false)
        while remaining > 0 {
            let chunk = UInt16(min(remaining, Int(UInt16.max)))
            remaining -= Int(chunk)
            lwip_bridge_tcp_recved(pcb, chunk)
        }
    }

    private func rejectSilently() {
        finish(.silentReject)
    }

    private func rejectWithTLSAlert() {
        guard phase != .closed else { return }
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
        for (_, waiter) in dialWaiters {
            waiter.resume(throwing: AnywhereError.transport(.terminated))
        }
        dialWaiters.removeAll()

        nurseryJobContinuation.finish()
        establishInbox.finish()

        idleActive = false
        idlePoke.finish()

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
        closePending = false

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
