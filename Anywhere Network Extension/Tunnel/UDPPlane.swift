//
//  UDPPlane.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation
import Synchronization
import AnywhereIP

nonisolated private let logger = AnywhereLogger(category: "UDPPlane")

nonisolated enum UDPPlaneCommand {
    case setMultiplexerPool((any UDPMultiplexerPool)?)
    case revalidateQUIC
    case reclaim
}

actor UDPPlane {
    private unowned let stack: TunnelStack

    // MARK: Registry / session state

    private var flows: [TunnelStack.UDPFlowKey: UDPFlow] = [:] {
        didSet { FlowGauge.publishUDPTable(flows.count) }
    }

    private var cleanupDeadline: TimeInterval?
    
    nonisolated private let bufferLedger = UDPBufferLedger(budget: TunnelConstants.udpGlobalBufferBudget)

    private var udpPressureLog = PressureEventThrottle(message: "[UDP] Flow table full")

    private struct PendingDatagrams {
        var datagrams: [InboundDatagram] = []
        var byteCount = 0
    }
    private var pendingResolutions: [TunnelStack.UDPFlowKey: PendingDatagrams] = [:]

    private struct PendingSniff {
        var sniffer: QUICClientHelloSniffer
        var datagrams: [InboundDatagram] = []
        var byteCount = 0
        let generation: UInt64
    }
    private var pendingSniffs: [TunnelStack.UDPFlowKey: PendingSniff] = [:]
    private var sniffGeneration: UInt64 = 0
    private var pendingSniffCapWarned = false

    private struct QUICBlock {
        enum Cause {
            case policy
            case mitm(host: String)
            case proxied(RouteTarget)
            case rejected
        }
        let cause: Cause
        var deadline: TimeInterval
    }
    private var quicBlocks: [TunnelStack.UDPFlowKey: QUICBlock] = [:]

    private enum SniffStage {
        case pending
        case done(serverName: String?)
    }

    private var ssSessions: [UUID: ShadowsocksUDPSession] = [:]

    private var multiplexerPoolStorage: (any UDPMultiplexerPool)?

    private var pendingResolutionCapWarned = false

    init(stack: TunnelStack) {
        self.stack = stack
    }

    // MARK: - Multiplexer pool

    var multiplexerPool: (any UDPMultiplexerPool)? { multiplexerPoolStorage }

    func apply(_ command: UDPPlaneCommand) {
        switch command {
        case .setMultiplexerPool(let pool):
            multiplexerPoolStorage = pool
        case .revalidateQUIC:
            revalidateQUIC()
        case .reclaim:
            reclaim()
        }
    }

    // MARK: - Intake

    private struct FlowBatch {
        let flow: UDPFlow
        var payloads: [Data]
    }

    func feed(_ datagrams: [InboundDatagram]) async {
        let udpConfig = stack.udpConfig()
        var batches: [FlowBatch] = []
        for datagram in datagrams {
            guard stack.publishedPhase.load(ordering: .relaxed) == .running else { break }
            if let flow = openFlow(for: datagram, udpConfig: udpConfig) {
                if let index = batches.firstIndex(where: { $0.flow === flow }) {
                    batches[index].payloads.append(datagram.payload)
                } else {
                    batches.append(FlowBatch(flow: flow, payloads: [datagram.payload]))
                }
                continue
            }
            await deliver(&batches)
            await handleInboundUDP(datagram)
        }
        await deliver(&batches)
    }

    private func openFlow(for datagram: InboundDatagram, udpConfig: TunnelStack.UDPConfig) -> UDPFlow? {
        let destination = datagram.destination
        if destination.port == 53 || udpConfig.blockUDP { return nil }
        if destination.port == 443 && udpConfig.quicPolicy.blocksAllQUIC { return nil }
        if udpConfig.blockWebRTC && TunnelStack.isSTUNMessage(datagram.payload) { return nil }
        guard let flow = flows[TunnelStack.UDPFlowKey(datagram)], !flow.isClosed else { return nil }
        return flow
    }

    private func deliver(_ batches: inout [FlowBatch]) async {
        for batch in batches {
            await batch.flow.handleReceivedData(batch.payloads)
        }
        batches.removeAll(keepingCapacity: true)
    }

    private func deferUntilResolved(
        _ datagram: InboundDatagram,
        flowKey: TunnelStack.UDPFlowKey,
        domain: String
    ) -> Bool {
        if var pending = pendingResolutions[flowKey] {
            guard pending.byteCount + datagram.payload.count <= TunnelConstants.udpPendingResolutionMaxBytes
                    else { return true }
            pending.datagrams.append(datagram)
            pending.byteCount += datagram.payload.count
            pendingResolutions[flowKey] = pending
            return true
        }

        guard pendingResolutions.count < TunnelLimits.udpMaxPendingResolutions else {
            if !pendingResolutionCapWarned {
                pendingResolutionCapWarned = true
                logger.warning("[UDP] Pending-resolution table full")
            }
            return false
        }

        pendingResolutions[flowKey] = PendingDatagrams(datagrams: [datagram],
                                                       byteCount: datagram.payload.count)
        Task { [weak self] in
            _ = await DNSResolver.localRequests.resolveHost(domain)
            await self?.resumeAfterResolution(flowKey: flowKey)
        }
        return true
    }

    private func resumeAfterResolution(flowKey: TunnelStack.UDPFlowKey) async {
        guard let pending = pendingResolutions.removeValue(forKey: flowKey) else { return }
        if pendingResolutionCapWarned, pendingResolutions.count <= TunnelLimits.udpMaxPendingResolutions / 2 {
            pendingResolutionCapWarned = false
        }
        for datagram in pending.datagrams {
            guard stack.publishedPhase.load(ordering: .relaxed) == .running else { return }
            await handleInboundUDP(datagram, awaitedResolution: true)
        }
    }

    private func handleInboundUDP(
        _ datagram: InboundDatagram,
        awaitedResolution: Bool = false,
        sniff: SniffStage = .pending
    ) async {
        let payload = datagram.payload
        let dstAddress = datagram.destination.address
        let dstPort = datagram.destination.port

        let udpConfig = stack.udpConfig()

        if dstPort == 53 {
            if let destination = TunnelStack.dnsDestination(
                for: dstAddress.description, exempting: udpConfig.interceptExemptDNSServers
            ) {
                if await handleDNSQuery(datagram, destination: destination, udpConfig: udpConfig) {
                    return
                }
            }
        }

        if udpConfig.blockUDP && dstPort != 53 {
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        let isQUIC = Self.isQUIC(payload, port: dstPort)
        let flowKey = TunnelStack.UDPFlowKey(datagram)

        if isQUIC && udpConfig.quicPolicy.blocksAllQUIC {
            blockQUIC(datagram, flowKey: flowKey, cause: .policy)
            return
        }

        if udpConfig.blockWebRTC && TunnelStack.isSTUNMessage(payload) {
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        if let flow = flows[flowKey] {
            if !flow.isClosed {
                await flow.handleReceivedData([payload])
                return
            }
            flows.removeValue(forKey: flowKey)
        }

        if replyToBlockedQUIC(datagram, flowKey: flowKey) {
            return
        }

        if stack.isRejectMarked(dstAddress) {
            return
        }

        guard let defaultConfiguration = udpConfig.configuration else { return }

        let decision = stack.connectionRouter.decision(forIP: dstAddress.description)

        let dstHost = decision.host

        var flowConfiguration = defaultConfiguration
        var routeTarget: RouteTarget = .default
        var ruleSetName: String? = nil

        switch decision.action {
        case .route(let target, let configuration, let matchedRuleSet):
            routeTarget = target
            ruleSetName = matchedRuleSet
            if let configuration {
                flowConfiguration = configuration
            }
        case .reject(let matchedRuleSet):
            stack.requestLog.record(protocol: .udp, host: dstHost, port: dstPort, routeTarget: .reject, ruleSetName: matchedRuleSet)
            return
        case .unreachable:
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        var sniffedServerName: String?
        switch sniff {
        case .done(let serverName):
            sniffedServerName = serverName
        case .pending:
            if !decision.hostIsResolvedDomain {
                switch await sniffQUIC(datagram, flowKey: flowKey) {
                case .consumed:
                    return
                case .finished(let serverName):
                    sniffedServerName = serverName
                }
            }
        }

        if let sniffedServerName,
           let action = stack.connectionRouter.action(forSniffedHost: sniffedServerName) {
            switch action {
            case .route(let target, let configuration, let matchedRuleSet):
                routeTarget = target
                ruleSetName = matchedRuleSet
                flowConfiguration = configuration ?? defaultConfiguration
            case .reject(let matchedRuleSet):
                recordQUICBlock(flowKey, cause: .rejected)
                stack.requestLog.record(protocol: .udp, host: sniffedServerName, port: dstPort, routeTarget: .reject, ruleSetName: matchedRuleSet)
                return
            case .unreachable:
                stack.sendICMPPortUnreachable(rejecting: datagram)
                return
            }
        }

        let policyHost = sniffedServerName ?? dstHost

        if isQUIC, blocksQUIC(to: policyHost, udpConfig: udpConfig) {
            blockQUIC(datagram, flowKey: flowKey, cause: .mitm(host: policyHost))
            return
        }

        if !awaitedResolution, decision.ipRuleLookupPending,
           deferUntilResolved(datagram, flowKey: flowKey, domain: dstHost) {
            return
        }

        if isQUIC, blocksQUIC(routedTo: routeTarget, udpConfig: udpConfig) {
            blockQUIC(datagram, flowKey: flowKey, cause: .proxied(routeTarget))
            return
        }

        guard makeRoomForNewFlow() else { return }

        stack.requestLog.record(protocol: .udp, host: policyHost, port: dstPort, routeTarget: routeTarget, ruleSetName: ruleSetName)

        let flow = UDPFlow(
            stack: stack,
            plane: self,
            ledger: bufferLedger,
            flowKey: flowKey,
            dstHost: dstHost,
            sniffedHost: sniffedServerName,
            isQUIC: isQUIC,
            configuration: flowConfiguration,
            routeTarget: routeTarget,
            ruleSetName: ruleSetName
        )
        insert(flow)
        await flow.handleReceivedData([payload])
    }

    // MARK: - QUIC policy

    private func blocksQUIC(to host: String, udpConfig: TunnelStack.UDPConfig) -> Bool {
        udpConfig.quicPolicy.blocksQUIC(
            mitmListed: udpConfig.mitmEnabled && stack.mitmPolicy.matches(host)
        )
    }

    private func blocksQUIC(routedTo routeTarget: RouteTarget, udpConfig: TunnelStack.UDPConfig) -> Bool {
        udpConfig.quicPolicy.blocksQUIC(
            isProxied: routeTarget.resolved(against: udpConfig.defaultRouteTarget).configurationID != nil
        )
    }

    private func revalidateQUIC() {
        let udpConfig = stack.udpConfig()
        for (key, block) in quicBlocks where !stillBlocks(block.cause, udpConfig: udpConfig) {
            quicBlocks.removeValue(forKey: key)
        }
        for (key, flow) in flows where flow.isQUIC {
            let host = flow.sniffedHost ?? flow.dstHost
            let cause: QUICBlock.Cause
            if udpConfig.quicPolicy.blocksAllQUIC {
                cause = .policy
            } else if blocksQUIC(to: host, udpConfig: udpConfig) {
                cause = .mitm(host: host)
            } else if blocksQUIC(routedTo: flow.routeTarget, udpConfig: udpConfig) {
                cause = .proxied(flow.routeTarget)
            } else {
                continue
            }
            flows.removeValue(forKey: key)
            recordQUICBlock(key, cause: cause)
            Task { await flow.close() }
        }
    }

    private func stillBlocks(_ cause: QUICBlock.Cause, udpConfig: TunnelStack.UDPConfig) -> Bool {
        switch cause {
        case .policy: return udpConfig.quicPolicy.blocksAllQUIC
        case .mitm(let host): return blocksQUIC(to: host, udpConfig: udpConfig)
        case .proxied(let routeTarget): return blocksQUIC(routedTo: routeTarget, udpConfig: udpConfig)
        case .rejected: return true
        }
    }

    private static func isQUIC(_ payload: Data, port: UInt16) -> Bool {
        port == 443 || QUICClientHelloSniffer.looksLikeClientInitial(payload)
    }

    private func blockQUIC(_ datagram: InboundDatagram, flowKey: TunnelStack.UDPFlowKey, cause: QUICBlock.Cause) {
        recordQUICBlock(flowKey, cause: cause)
        stack.sendICMPPortUnreachable(rejecting: datagram)
    }

    private func recordQUICBlock(_ flowKey: TunnelStack.UDPFlowKey, cause: QUICBlock.Cause) {
        if quicBlocks[flowKey] == nil, quicBlocks.count >= TunnelLimits.udpMaxQUICBlocks,
           let oldest = quicBlocks.min(by: { $0.value.deadline < $1.value.deadline })?.key {
            quicBlocks.removeValue(forKey: oldest)
        }
        let deadline = MonotonicClock.now + TunnelConstants.udpQUICBlockIdleTimeout
        quicBlocks[flowKey] = QUICBlock(cause: cause, deadline: deadline)
        if cleanupDeadline.map({ deadline < $0 }) ?? true {
            stack.scheduleUDPCleanup(at: deadline)
        }
    }

    private func replyToBlockedQUIC(_ datagram: InboundDatagram, flowKey: TunnelStack.UDPFlowKey) -> Bool {
        guard var block = quicBlocks[flowKey] else { return false }
        let now = MonotonicClock.now
        guard now <= block.deadline else {
            quicBlocks.removeValue(forKey: flowKey)
            return false
        }
        block.deadline = now + TunnelConstants.udpQUICBlockIdleTimeout
        quicBlocks[flowKey] = block
        if case .rejected = block.cause { return true }
        stack.sendICMPPortUnreachable(rejecting: datagram)
        return true
    }

    // MARK: - QUIC SNI sniffing

    private enum SniffOutcome {
        case consumed
        case finished(serverName: String?)
    }

    private func sniffQUIC(_ datagram: InboundDatagram, flowKey: TunnelStack.UDPFlowKey) async -> SniffOutcome {
        var pending: PendingSniff
        if let held = pendingSniffs.removeValue(forKey: flowKey) {
            pending = held
        } else {
            guard QUICClientHelloSniffer.looksLikeClientInitial(datagram.payload) else {
                return .finished(serverName: nil)
            }
            guard pendingSniffs.count < TunnelLimits.udpMaxPendingSniffs else {
                if !pendingSniffCapWarned {
                    pendingSniffCapWarned = true
                    logger.warning("[UDP] Pending-sniff table full")
                }
                return .finished(serverName: nil)
            }
            sniffGeneration += 1
            pending = PendingSniff(
                sniffer: QUICClientHelloSniffer(
                    bufferLimit: TunnelConstants.quicSnifferBufferLimit,
                    datagramLimit: TunnelConstants.quicSnifferDatagramLimit
                ),
                generation: sniffGeneration
            )
        }

        var state = pending.sniffer.feed(datagram.payload)
        if state == .needMore, pending.byteCount + datagram.payload.count > TunnelConstants.udpPendingSniffMaxBytes {
            state = .unavailable
        }

        switch state {
        case .needMore:
            pending.datagrams.append(datagram)
            pending.byteCount += datagram.payload.count
            let isFirst = pending.datagrams.count == 1
            pendingSniffs[flowKey] = pending
            if isFirst {
                let generation = pending.generation
                Task { [weak self] in
                    try? await Task.sleep(seconds: TunnelConstants.sniffDeadline, precision: .prompt)
                    await self?.sniffDeadlineFired(flowKey: flowKey, generation: generation)
                }
            }
            return .consumed
        case .found(let serverName):
            notePendingSniffDrained()
            return await releaseHeldDatagrams(pending.datagrams, then: datagram, serverName: serverName)
        case .notQUIC, .unavailable:
            notePendingSniffDrained()
            return await releaseHeldDatagrams(pending.datagrams, then: datagram, serverName: nil)
        }
    }

    private func releaseHeldDatagrams(
        _ held: [InboundDatagram],
        then datagram: InboundDatagram,
        serverName: String?
    ) async -> SniffOutcome {
        guard !held.isEmpty else {
            return .finished(serverName: serverName)
        }
        for datagram in held + [datagram] {
            guard stack.publishedPhase.load(ordering: .relaxed) == .running else { break }
            await handleInboundUDP(datagram, sniff: .done(serverName: serverName))
        }
        return .consumed
    }

    private func sniffDeadlineFired(flowKey: TunnelStack.UDPFlowKey, generation: UInt64) async {
        guard let pending = pendingSniffs[flowKey], pending.generation == generation else { return }
        pendingSniffs.removeValue(forKey: flowKey)
        notePendingSniffDrained()
        for datagram in pending.datagrams {
            guard stack.publishedPhase.load(ordering: .relaxed) == .running else { return }
            await handleInboundUDP(datagram, sniff: .done(serverName: nil))
        }
    }

    private func notePendingSniffDrained() {
        if pendingSniffCapWarned, pendingSniffs.count <= TunnelLimits.udpMaxPendingSniffs / 2 {
            pendingSniffCapWarned = false
        }
    }

    // MARK: - Flow registry

    private func insert(_ flow: UDPFlow) {
        flows[flow.flowKey] = flow
        if cleanupDeadline.map({ flow.idleDeadline < $0 }) ?? true {
            stack.scheduleUDPCleanup(at: flow.idleDeadline)
        }
    }

    func remove(_ flow: UDPFlow) {
        if flows[flow.flowKey] === flow {
            flows.removeValue(forKey: flow.flowKey)
        }
    }
    
    func evictForBufferPressure(_ victims: [UDPBufferLedger.Victim]) {
        for victim in victims {
            guard let flow = flows[victim.handle], ObjectIdentifier(flow) == victim.id else { continue }
            flows.removeValue(forKey: victim.handle)
            logger.warning("[UDP] Uplink buffer full")
            Task { await flow.close() }
        }
    }
    
    private func makeRoomForNewFlow() -> Bool {
        guard flows.count >= TunnelLimits.udpMaxFlows else { return true }
        let now = MonotonicClock.now
        var unassured: (key: TunnelStack.UDPFlowKey, idleFor: TimeInterval)?
        var assured: (key: TunnelStack.UDPFlowKey, idleFor: TimeInterval)?
        for (key, flow) in flows {
            if flow.isClosed {
                flows.removeValue(forKey: key)
                return true
            }
            let snapshot = flow.pressureSnapshot(now: now)
            if !snapshot.isAssured {
                if snapshot.idleFor > (unassured?.idleFor ?? -1) { unassured = (key, snapshot.idleFor) }
            } else if snapshot.idleFor >= TunnelConstants.pressureIdleTimeout,
                      snapshot.idleFor > (assured?.idleFor ?? -1) {
                assured = (key, snapshot.idleFor)
            }
        }
        guard let victim = unassured ?? assured, let flow = flows.removeValue(forKey: victim.key) else {
            udpPressureLog.noteDropped(now: now, logger: logger)
            return false
        }
        Task { await flow.close() }
        return true
    }

    // MARK: - Cleanup

    func cleanup() -> TimeInterval? {
        let now = MonotonicClock.now
        var next: TimeInterval?
        for (key, flow) in flows {
            let deadline = flow.idleDeadline
            if now > deadline {
                Task { await flow.close() }
                flows.removeValue(forKey: key)
            } else if next.map({ deadline < $0 }) ?? true {
                next = deadline
            }
        }
        for (key, block) in quicBlocks {
            if now > block.deadline {
                quicBlocks.removeValue(forKey: key)
            } else if next.map({ block.deadline < $0 }) ?? true {
                next = block.deadline
            }
        }
        cleanupDeadline = next
        return next
    }

    // MARK: - Shadowsocks UDP sessions

    func shadowsocksSession(for configuration: ProxyConfiguration) -> Result<ShadowsocksUDPSession, AnywhereError> {
        if let existing = ssSessions[configuration.id], existing.isUsable {
            return .success(existing)
        }
        ssSessions.removeValue(forKey: configuration.id)

        guard case .shadowsocks(let shadowsocks) = configuration.outbound else {
            return .failure(AnywhereError.proxy(.shadowsocks, .protocolViolation(detail: "Shadowsocks password not set")))
        }
        guard let cipher = shadowsocks.cipher else {
            return .failure(AnywhereError.proxy(.shadowsocks, .cipher(.unsupportedMethod(shadowsocks.method))))
        }

        let mode: ShadowsocksUDPSession.Mode
        if cipher.isSS2022 {
            guard let pskList = ShadowsocksKeyDerivation.decodePSKList(password: shadowsocks.password, keySize: cipher.keySize) else {
                return .failure(AnywhereError.proxy(.shadowsocks, .cipher(.invalidKey)))
            }
            if cipher == .blake3chacha20poly1305 {
                mode = .ss2022ChaCha(psk: pskList.last!)
            } else {
                mode = .ss2022AES(cipher: cipher, pskList: pskList)
            }
        } else {
            let masterKey = ShadowsocksKeyDerivation.deriveKey(password: shadowsocks.password, keySize: cipher.keySize)
            mode = .legacy(cipher: cipher, masterKey: masterKey)
        }

        let session = ShadowsocksUDPSession(
            mode: mode,
            serverHost: configuration.serverAddress,
            serverPort: configuration.serverPort
        )
        ssSessions[configuration.id] = session
        return .success(session)
    }

    private func purgeShadowsocksUDPSessions() {
        let all = Array(ssSessions.values)
        ssSessions.removeAll()
        for session in all { session.cancel() }
    }

    // MARK: - DNS interception (synthetic address)

    private func handleDNSQuery(
        _ datagram: InboundDatagram,
        destination: TunnelStack.DNSDestination,
        udpConfig: TunnelStack.UDPConfig
    ) async -> Bool {
        let payload = datagram.payload
        guard let parsed = payload.withUnsafeBytes({ ptr -> (domain: String, qtype: UInt16)? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.parseQuery(UnsafeBufferPointer(start: base, count: ptr.count))
        }) else { return false }

        let domain = parsed.domain.lowercased()
        let qtype = parsed.qtype

        if domain == "_dns.resolver.arpa" {
            return sendNODATA(answering: datagram, qtype: qtype)
        }

        if qtype == 65 {
            return sendNODATA(answering: datagram, qtype: qtype)
        }

        let (ruleMatch, rulesVersion) = stack.connectionRouter.dnsVerdict(forDomain: domain)
        if let ruleMatch, case .reject = ruleMatch.action {
            if stack.connectionRouter.shouldLogDNSReject(domain: domain) {
                stack.requestLog.record(
                    protocol: .unknown,
                    host: domain,
                    port: 53,
                    routeTarget: .reject,
                    ruleSetName: ruleMatch.ruleSetName
                )
            }
            guard qtype == 1 || qtype == 28 else {
                return sendNODATA(answering: datagram, qtype: qtype)
            }
            let zeroIP = [UInt8](repeating: 0, count: qtype == 1 ? 4 : 16)
            return sendAddressAnswer(
                answering: datagram,
                ips: [zeroIP],
                qtype: qtype,
                ttl: TunnelConstants.dnsBlockedAnswerTTL
            )
        }

        if qtype == 28 {
            return sendNODATA(answering: datagram, qtype: qtype)
        }

        guard qtype == 1 else {
            if destination == .anywhereResolver {
                if await forwardToUpstreamResolver(datagram) {
                    return true
                }
                return sendNODATA(answering: datagram, qtype: qtype)
            }
            return false
        }

        if udpConfig.syntheticAddressExcludedDomains.contains(domain) {
            if let mapped = DNSHosts.shared.addresses(for: domain, family: .ipv4) {
                return sendAddressAnswer(
                    answering: datagram,
                    ips: mapped.compactMap(Self.ipv4Bytes),
                    qtype: qtype,
                    ttl: TunnelConstants.dnsHostMappingAnswerTTL
                )
            }
            if destination == .anywhereResolver {
                if await forwardToUpstreamResolver(datagram) {
                    return true
                }
                return sendNODATA(answering: datagram, qtype: qtype)
            }
            return false
        }

        let offset = stack.syntheticAddressPool.allocate(domain: domain, verdict: ruleMatch, verdictVersion: rulesVersion)
        let ipv4 = SyntheticAddressPool.ipv4Bytes(offset: offset)
        return sendAddressAnswer(
            answering: datagram,
            ips: [[ipv4.0, ipv4.1, ipv4.2, ipv4.3]],
            qtype: qtype,
            ttl: TunnelConstants.dnsSyntheticAddressAnswerTTL
        )
    }

    private func forwardToUpstreamResolver(_ datagram: InboundDatagram) async -> Bool {
        let udpConfig = stack.udpConfig()
        guard let defaultConfiguration = udpConfig.configuration else { return false }

        let upstream = DNSUpstream.forwardingServers(
            preferring: AWCore.getFallbackDNSUpstream(), includeIPv6: false
        ).first ?? DNSUpstream.defaultUDPServer
        let payload = datagram.payload
        let dstPort = datagram.destination.port

        let flowKey = TunnelStack.UDPFlowKey(datagram)
        if let existing = flows[flowKey] {
            if !existing.isClosed {
                await existing.handleReceivedData([payload])
                return true
            }
            flows.removeValue(forKey: flowKey)
        }

        let decision = stack.connectionRouter.decision(forIP: upstream)

        var flowConfiguration = defaultConfiguration
        var routeTarget: RouteTarget = .default
        var ruleSetName: String? = nil

        switch decision.action {
        case .route(let target, let ruleConfiguration, let matchedRuleSet):
            routeTarget = target
            ruleSetName = matchedRuleSet
            if let ruleConfiguration { flowConfiguration = ruleConfiguration }
        case .reject(let matchedRuleSet):
            stack.requestLog.record(
                protocol: .udp, host: upstream, port: dstPort,
                routeTarget: .reject,
                ruleSetName: matchedRuleSet
            )
            return false
        case .unreachable:
            return false
        }

        guard makeRoomForNewFlow() else { return true }

        stack.requestLog.record(
            protocol: .udp, host: upstream, port: dstPort,
            routeTarget: routeTarget, ruleSetName: ruleSetName
        )

        let flow = UDPFlow(
            stack: stack,
            plane: self,
            ledger: bufferLedger,
            flowKey: flowKey,
            dstHost: upstream,
            configuration: flowConfiguration,
            routeTarget: routeTarget,
            ruleSetName: ruleSetName
        )
        insert(flow)
        await flow.handleReceivedData([payload])
        return true
    }

    private func sendNODATA(answering datagram: InboundDatagram, qtype: UInt16) -> Bool {
        guard let responseData = datagram.payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                answerIPs: [],
                qtype: qtype
            )
        }) else { return false }

        stack.writeOutboundUDP(responseData, from: datagram.destination, to: datagram.source)

        return true
    }

    private func sendAddressAnswer(
        answering datagram: InboundDatagram,
        ips: [[UInt8]],
        qtype: UInt16,
        ttl: UInt32
    ) -> Bool {
        guard let responseData = datagram.payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                answerIPs: ips,
                qtype: qtype,
                ttl: ttl
            )
        }) else { return false }

        stack.writeOutboundUDP(responseData, from: datagram.destination, to: datagram.source)

        return true
    }

    private static func ipv4Bytes(_ address: String) -> [UInt8]? {
        var raw = in_addr()
        guard inet_pton(AF_INET, address, &raw) == 1 else { return nil }
        return withUnsafeBytes(of: raw) { Array($0) }
    }

    // MARK: - Reclaim

    private func reclaim() {
        multiplexerPoolStorage?.closeAll()
        multiplexerPoolStorage = nil
        purgeShadowsocksUDPSessions()
        pendingResolutions.removeAll()
        pendingResolutionCapWarned = false
        pendingSniffs.removeAll()
        pendingSniffCapWarned = false
        quicBlocks.removeAll()
        let all = Array(flows.values)
        flows.removeAll()
        for flow in all {
            Task { await flow.close() }
        }
    }
}
