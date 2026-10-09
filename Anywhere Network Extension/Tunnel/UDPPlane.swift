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

    private var udpPressureLog = PressureEventThrottle(label: "UDP", cap: TunnelLimits.udpMaxFlows)

    private struct PendingDatagrams {
        var datagrams: [InboundDatagram] = []
        var byteCount = 0
    }
    private var pendingResolutions: [TunnelStack.UDPFlowKey: PendingDatagrams] = [:]

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
                logger.warning("[UDP] pending-resolution table full (\(TunnelLimits.udpMaxPendingResolutions)); new flows dial on the default outbound")
            }
            return false
        }

        pendingResolutions[flowKey] = PendingDatagrams(datagrams: [datagram],
                                                       byteCount: datagram.payload.count)
        Task { [weak self] in
            _ = await DNSResolver.localRequests.resolveHost(domain, family: .ipv4)
            await self?.resumeAfterResolution(flowKey: flowKey)
        }
        return true
    }

    private func resumeAfterResolution(flowKey: TunnelStack.UDPFlowKey) async {
        guard let pending = pendingResolutions.removeValue(forKey: flowKey) else { return }
        if pendingResolutionCapWarned, pendingResolutions.count <= TunnelLimits.udpMaxPendingResolutions / 2 {
            pendingResolutionCapWarned = false
            logger.info("[UDP] pending-resolution table drained; waiting on IP-rule lookups again")
        }
        for datagram in pending.datagrams {
            guard stack.publishedPhase.load(ordering: .relaxed) == .running else { return }
            await handleInboundUDP(datagram, awaitedResolution: true)
        }
    }

    private func handleInboundUDP(_ datagram: InboundDatagram, awaitedResolution: Bool = false) async {
        let payload = datagram.payload
        let dstAddress = datagram.destination.address
        let dstPort = datagram.destination.port

        let udpConfig = stack.udpConfig()

        if dstPort == 53 {
            if let destination = TunnelStack.dnsDestination(
                for: dstAddress.description, exempting: udpConfig.interceptExemptDNSServers
            ) {
                if await handleDNSQuery(datagram, destination: destination) {
                    return
                }
            }
        }

        if udpConfig.blockUDP && dstPort != 53 {
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        if dstPort == 443 && udpConfig.quicPolicy.blocksAllQUIC {
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        if udpConfig.blockWebRTC && TunnelStack.isSTUNMessage(payload) {
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        let flowKey = TunnelStack.UDPFlowKey(datagram)
        if let flow = flows[flowKey] {
            if !flow.isClosed {
                await flow.handleReceivedData([payload])
                return
            }
            flows.removeValue(forKey: flowKey)
        }

        if stack.isRejectMarked(dstAddress) {
            return
        }

        guard let defaultConfiguration = udpConfig.configuration else { return }

        let decision = stack.connectionRouter.decision(forIP: dstAddress.description, port: dstPort, proto: "UDP")

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

        if dstPort == 443, blocksQUIC(to: dstHost, udpConfig: udpConfig) {
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        if !awaitedResolution, decision.ipRuleLookupPending,
           deferUntilResolved(datagram, flowKey: flowKey, domain: dstHost) {
            return
        }

        if dstPort == 443, blocksQUIC(routedTo: routeTarget, udpConfig: udpConfig) {
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        guard makeRoomForNewFlow() else { return }

        stack.requestLog.record(protocol: .udp, host: dstHost, port: dstPort, routeTarget: routeTarget, ruleSetName: ruleSetName)

        let flow = UDPFlow(
            stack: stack,
            plane: self,
            ledger: bufferLedger,
            flowKey: flowKey,
            dstHost: dstHost,
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
        for (key, flow) in flows where key.destination.port == 443 {
            guard blocksQUIC(to: flow.dstHost, udpConfig: udpConfig)
                    || blocksQUIC(routedTo: flow.routeTarget, udpConfig: udpConfig) else { continue }
            flows.removeValue(forKey: key)
            Task { await flow.close() }
        }
    }

    // MARK: - Flow registry

    private func insert(_ flow: UDPFlow) {
        flows[flow.flowKey] = flow
        if cleanupDeadline.map({ flow.idleDeadline < $0 }) ?? true {
            stack.udpCleanupResume.yield(())
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
            logger.warning("[UDP] Global uplink budget full; evicting \(victim.handle) holding \(victim.bytes) buffered bytes")
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
        logger.debug("[UDP] Flow table full; evicting \(victim.key) idle \(Int(victim.idleFor))s")
        udpPressureLog.noteEvicted(now: now, logger: logger)
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

    // MARK: - DNS interception (fake-IP)

    private func handleDNSQuery(_ datagram: InboundDatagram, destination: TunnelStack.DNSDestination) async -> Bool {
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
                logger.debug("[DNS] Rejected by domain rule: \(domain)")
            }
            guard qtype == 1 || qtype == 28 else {
                return sendNODATA(answering: datagram, qtype: qtype)
            }
            let zeroIP = [UInt8](repeating: 0, count: qtype == 1 ? 4 : 16)
            return sendAddressAnswer(
                answering: datagram,
                ip: zeroIP,
                qtype: qtype,
                ttl: TunnelConstants.dnsBlockedAnswerTTL
            )
        }

        if qtype == 28 {
            return sendNODATA(answering: datagram, qtype: qtype)
        }

        guard qtype == 1 else {
            if destination == .anywhereResolver {
                if await forwardToUpstreamResolver(datagram, domain: domain, qtype: qtype) {
                    return true
                }
                return sendNODATA(answering: datagram, qtype: qtype)
            }
            return false
        }

        let offset = stack.fakeIPPool.allocate(domain: domain, verdict: ruleMatch, verdictVersion: rulesVersion)
        let ipv4 = FakeIPPool.ipv4Bytes(offset: offset)
        return sendAddressAnswer(
            answering: datagram,
            ip: [ipv4.0, ipv4.1, ipv4.2, ipv4.3],
            qtype: qtype,
            ttl: TunnelConstants.dnsFakeIPAnswerTTL
        )
    }

    private func forwardToUpstreamResolver(_ datagram: InboundDatagram, domain: String, qtype: UInt16) async -> Bool {
        let udpConfig = stack.udpConfig()
        guard let defaultConfiguration = udpConfig.configuration else { return false }

        let upstream = DNSUpstream.forwardingServers(
            preferring: AWCore.getFallbackDNSUpstream(), includeIPv6: false
        ).first ?? DNSUpstream.defaultPlainServer
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

        let decision = stack.connectionRouter.decision(forIP: upstream, port: dstPort, proto: "UDP")

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
        logger.debug("[DNS] Forwarding qtype \(qtype) for \(domain) → \(upstream):\(dstPort) via \(flowConfiguration.name)")
        await flow.handleReceivedData([payload])
        return true
    }

    private func sendNODATA(answering datagram: InboundDatagram, qtype: UInt16) -> Bool {
        guard let responseData = datagram.payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                answerIP: nil,
                qtype: qtype
            )
        }) else { return false }

        stack.writeOutboundUDP(responseData, from: datagram.destination, to: datagram.source)

        return true
    }

    private func sendAddressAnswer(
        answering datagram: InboundDatagram,
        ip: [UInt8],
        qtype: UInt16,
        ttl: UInt32
    ) -> Bool {
        guard let responseData = datagram.payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                answerIP: ip,
                qtype: qtype,
                ttl: ttl
            )
        }) else { return false }

        stack.writeOutboundUDP(responseData, from: datagram.destination, to: datagram.source)

        return true
    }

    // MARK: - Reclaim

    private func reclaim() {
        multiplexerPoolStorage?.closeAll()
        multiplexerPoolStorage = nil
        purgeShadowsocksUDPSessions()
        pendingResolutions.removeAll()
        pendingResolutionCapWarned = false
        let all = Array(flows.values)
        flows.removeAll()
        for flow in all {
            Task { await flow.close() }
        }
    }
}
