//
//  UDPPlane.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "UDPPlane")

nonisolated enum UDPPlaneCommand {
    case setMultiplexerPool(VLESSVisionUDPMultiplexerPool?)
    case reclaim(replacementMultiplexerPool: VLESSVisionUDPMultiplexerPool?)
}

actor UDPPlane {
    private unowned let stack: TunnelStack

    // MARK: Registry / session state

    private var flows: [TunnelStack.UDPFlowKey: UDPFlow] = [:] {
        didSet { FlowGauge.publishUDPTable(flows.count) }
    }
    
    nonisolated private let bufferLedger = UDPBufferLedger(budget: TunnelConstants.udpGlobalBufferBudget)

    private var udpPressureLog = PressureEventThrottle(label: "UDP", cap: TunnelLimits.udpMaxFlows)

    private struct PendingDatagrams {
        var datagrams: [UDPPacket.Inbound] = []
        var byteCount = 0
    }
    private var pendingResolutions: [TunnelStack.UDPFlowKey: PendingDatagrams] = [:]

    private var ssSessions: [UUID: ShadowsocksUDPSession] = [:]

    private var multiplexerPoolStorage: VLESSVisionUDPMultiplexerPool?

    private var pendingResolutionCapWarned = false

    init(stack: TunnelStack) {
        self.stack = stack
    }

    // MARK: - Multiplexer pool

    var multiplexerPool: VLESSVisionUDPMultiplexerPool? { multiplexerPoolStorage }

    func apply(_ command: UDPPlaneCommand) {
        switch command {
        case .setMultiplexerPool(let pool):
            multiplexerPoolStorage = pool
        case .reclaim(let replacement):
            reclaim(replacementMultiplexerPool: replacement)
        }
    }

    // MARK: - Intake

    func feed(_ packets: [Data]) async {
        for packet in packets {
            if let datagram = UDPPacket.parse(packet) {
                await handleInboundUDP(datagram)
            }
        }
    }

    private func deferUntilResolved(
        _ datagram: UDPPacket.Inbound,
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
            _ = await RuleResolver.shared.resolveIPv4(for: domain)
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
            await handleInboundUDP(datagram, awaitedResolution: true)
        }
    }

    private func handleInboundUDP(_ datagram: UDPPacket.Inbound, awaitedResolution: Bool = false) async {
        let payload = datagram.payload
        let isIPv6 = datagram.isIPv6

        let udpConfig = stack.udpConfig()

        if datagram.dstPort == 53 {
            let dstIPString = TunnelStack.ipAddrToString(datagram.dstIP, isIPv6: isIPv6)
            if let destination = TunnelStack.dnsDestination(
                for: dstIPString, exempting: udpConfig.interceptExemptDNSServers
            ) {
                if await handleDNSQuery(datagram, destination: destination) {
                    return  // Fake response sent, no flow needed
                }
            }
        }

        if udpConfig.blockUDP && datagram.dstPort != 53 {
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        if datagram.dstPort == 443 && udpConfig.quicPolicy.blocksAllQUIC {
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        if udpConfig.blockWebRTC && TunnelStack.isSTUNMessage(payload) {
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        let flowKey = TunnelStack.UDPFlowKey(
            srcIP: datagram.srcIP, srcPort: datagram.srcPort,
            dstIP: datagram.dstIP, dstPort: datagram.dstPort,
            isIPv6: isIPv6
        )
        if let flow = flows[flowKey] {
            if !flow.isClosed {
                await flow.handleReceivedData(payload, payloadLength: payload.count)
                return
            }
            flows.removeValue(forKey: flowKey)
        }

        if stack.connectionRouter.isRejectMarkedDestination(ipBytes: datagram.dstIP, isIPv6: isIPv6) {
            return
        }

        guard let defaultConfiguration = udpConfig.configuration else { return }
        let dstIPString = TunnelStack.ipAddrToString(datagram.dstIP, isIPv6: isIPv6)
        let srcHost = TunnelStack.ipAddrToString(datagram.srcIP, isIPv6: isIPv6)
        let srcIPData = datagram.srcIPData
        let dstIPData = datagram.dstIPData

        let decision = stack.connectionRouter.decision(forIP: dstIPString, port: datagram.dstPort, proto: "UDP")

        if !awaitedResolution, decision.ipRuleLookupPending,
           deferUntilResolved(datagram, flowKey: flowKey, domain: decision.host) {
            return
        }

        let dstHost = decision.host
        let dstIsDomain = decision.hostIsResolvedDomain

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
            stack.requestLog.record(protocol: .udp, host: dstHost, port: datagram.dstPort, routeTarget: .reject, ruleSetName: matchedRuleSet)
            return
        case .unreachable:
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        let isProxied = routeTarget.resolved(against: udpConfig.defaultRouteTarget).configurationID != nil
        if datagram.dstPort == 443,
           udpConfig.quicPolicy.blocksResolvedQUIC(
            isProxied: isProxied,
            mitmListed: dstIsDomain && udpConfig.mitmEnabled && stack.mitmPolicy.matches(dstHost)
           ) {
            logger.debug("[UDP] QUIC blocked (automatic): \(dstHost):443 reason=\(isProxied ? "proxied" : "mitm")")
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        guard makeRoomForNewFlow() else { return }

        stack.requestLog.record(protocol: .udp, host: dstHost, port: datagram.dstPort, routeTarget: routeTarget, ruleSetName: ruleSetName)

        let flow = UDPFlow(
            stack: stack,
            plane: self,
            ledger: bufferLedger,
            flowKey: flowKey,
            srcHost: srcHost,
            srcPort: datagram.srcPort,
            dstHost: dstHost,
            dstPort: datagram.dstPort,
            srcIPData: srcIPData,
            dstIPData: dstIPData,
            isIPv6: isIPv6,
            configuration: flowConfiguration,
            routeTarget: routeTarget
        )
        flows[flowKey] = flow
        await flow.handleReceivedData(payload, payloadLength: payload.count)
    }

    // MARK: - Flow registry

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

    func cleanup() {
        let now = MonotonicClock.now
        for (key, flow) in flows where now > flow.idleDeadline {
            Task { await flow.close() }
            flows.removeValue(forKey: key)
        }
    }

    // MARK: - Shadowsocks UDP sessions

    func shadowsocksSession(for configuration: ProxyConfiguration) -> Result<ShadowsocksUDPSession, AnywhereError> {
        if let existing = ssSessions[configuration.id], existing.isUsable {
            return .success(existing)
        }
        ssSessions.removeValue(forKey: configuration.id)

        guard case .shadowsocks(let password, let method) = configuration.outbound else {
            return .failure(AnywhereError.proxy(.shadowsocks, .protocolViolation(detail: "Shadowsocks password not set")))
        }
        guard let cipher = ShadowsocksCipher(method: method) else {
            return .failure(AnywhereError.proxy(.shadowsocks, .cipher(.unsupportedMethod(method))))
        }

        let mode: ShadowsocksUDPSession.Mode
        if cipher.isSS2022 {
            guard let pskList = ShadowsocksKeyDerivation.decodePSKList(password: password, keySize: cipher.keySize) else {
                return .failure(AnywhereError.proxy(.shadowsocks, .cipher(.invalidKey)))
            }
            if cipher == .blake3chacha20poly1305 {
                mode = .ss2022ChaCha(psk: pskList.last!)
            } else {
                mode = .ss2022AES(cipher: cipher, pskList: pskList)
            }
        } else {
            let masterKey = ShadowsocksKeyDerivation.deriveKey(password: password, keySize: cipher.keySize)
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

    private func handleDNSQuery(_ datagram: UDPPacket.Inbound, destination: TunnelStack.DNSDestination) async -> Bool {
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

        guard qtype == 1 || qtype == 28 else {
            if destination == .anywhereResolver {
                if await forwardToUpstreamResolver(datagram, domain: domain, qtype: qtype) {
                    return true
                }
                return sendNODATA(answering: datagram, qtype: qtype)
            }
            return false
        }

        let offset = stack.fakeIPPool.allocate(domain: domain, verdict: ruleMatch, verdictVersion: rulesVersion)

        if qtype == 1 {
            let ipv4 = FakeIPPool.ipv4Bytes(offset: offset)
            return sendAddressAnswer(
                answering: datagram,
                ip: [ipv4.0, ipv4.1, ipv4.2, ipv4.3],
                qtype: qtype,
                ttl: TunnelConstants.dnsFakeIPAnswerTTL
            )
        }
        guard stack.udpConfig().advertiseIPv6ToApps else {
            return sendNODATA(answering: datagram, qtype: qtype)
        }
        return sendAddressAnswer(
            answering: datagram,
            ip: FakeIPPool.ipv6Bytes(offset: offset),
            qtype: qtype,
            ttl: TunnelConstants.dnsFakeIPAnswerTTL
        )
    }

    private func forwardToUpstreamResolver(_ datagram: UDPPacket.Inbound, domain: String, qtype: UInt16) async -> Bool {
        let udpConfig = stack.udpConfig()
        guard let defaultConfiguration = udpConfig.configuration else { return false }

        let upstream = DNSUpstream.forwardingServers(
            preferring: AWCore.getFallbackDNSUpstream(), includeIPv6: false
        ).first ?? DNSUpstream.defaultPlainServer
        let payload = datagram.payload

        let flowKey = TunnelStack.UDPFlowKey(
            srcIP: datagram.srcIP, srcPort: datagram.srcPort,
            dstIP: datagram.dstIP, dstPort: datagram.dstPort,
            isIPv6: datagram.isIPv6
        )
        if let existing = flows[flowKey] {
            if !existing.isClosed {
                await existing.handleReceivedData(payload, payloadLength: payload.count)
                return true
            }
            flows.removeValue(forKey: flowKey)
        }

        let decision = stack.connectionRouter.decision(forIP: upstream, port: datagram.dstPort, proto: "UDP")

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
                protocol: .udp, host: upstream, port: datagram.dstPort,
                routeTarget: .reject,
                ruleSetName: matchedRuleSet
            )
            return false
        case .unreachable:
            return false
        }
        
        guard makeRoomForNewFlow() else { return true }

        stack.requestLog.record(
            protocol: .udp, host: upstream, port: datagram.dstPort,
            routeTarget: routeTarget, ruleSetName: ruleSetName
        )

        let flow = UDPFlow(
            stack: stack,
            plane: self,
            ledger: bufferLedger,
            flowKey: flowKey,
            srcHost: TunnelStack.ipAddrToString(datagram.srcIP, isIPv6: datagram.isIPv6),
            srcPort: datagram.srcPort,
            dstHost: upstream,
            dstPort: datagram.dstPort,
            srcIPData: datagram.srcIPData,
            dstIPData: datagram.dstIPData,
            isIPv6: datagram.isIPv6,
            configuration: flowConfiguration,
            routeTarget: routeTarget
        )
        flows[flowKey] = flow
        logger.debug("[DNS] Forwarding qtype \(qtype) for \(domain) → \(upstream):\(datagram.dstPort) via \(flowConfiguration.name)")
        await flow.handleReceivedData(payload, payloadLength: payload.count)
        return true
    }

    private func sendNODATA(answering datagram: UDPPacket.Inbound, qtype: UInt16) -> Bool {
        guard let responseData = datagram.payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                answerIP: nil,
                qtype: qtype
            )
        }) else { return false }

        stack.writeOutboundUDP(
            srcIP: datagram.dstIPData, srcPort: datagram.dstPort,
            dstIP: datagram.srcIPData, dstPort: datagram.srcPort,
            isIPv6: datagram.isIPv6,
            payload: responseData
        )

        return true
    }

    private func sendAddressAnswer(
        answering datagram: UDPPacket.Inbound,
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

        stack.writeOutboundUDP(
            srcIP: datagram.dstIPData, srcPort: datagram.dstPort,
            dstIP: datagram.srcIPData, dstPort: datagram.srcPort,
            isIPv6: datagram.isIPv6,
            payload: responseData
        )

        return true
    }

    // MARK: - Reclaim

    private func reclaim(replacementMultiplexerPool: VLESSVisionUDPMultiplexerPool?) {
        multiplexerPoolStorage?.closeAll()
        multiplexerPoolStorage = replacementMultiplexerPool
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
