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
    
    func feed(_ packets: [Data]) {
        for packet in packets {
            if let datagram = UDPPacket.parse(packet) {
                handleInboundUDP(datagram)
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
    
    private func resumeAfterResolution(flowKey: TunnelStack.UDPFlowKey) {
        guard let pending = pendingResolutions.removeValue(forKey: flowKey) else { return }
        if pendingResolutionCapWarned, pendingResolutions.count <= TunnelLimits.udpMaxPendingResolutions / 2 {
            pendingResolutionCapWarned = false
            logger.info("[UDP] pending-resolution table drained; waiting on IP-rule lookups again")
        }
        for datagram in pending.datagrams {
            handleInboundUDP(datagram, awaitedResolution: true)
        }
    }
    
    private func handleInboundUDP(_ datagram: UDPPacket.Inbound, awaitedResolution: Bool = false) {
        let payload = datagram.payload
        let isIPv6 = datagram.isIPv6
        
        let udpConfig = stack.udpConfig()
        
        // DNS interception: fake-IP for our own resolver; queries to any other
        // resolver are proxied to the real server.
        if datagram.dstPort == 53 {
            let dstIPString = TunnelStack.ipAddrToString(datagram.dstIP, isIPv6: isIPv6)
            if let destination = TunnelStack.dnsDestination(
                for: dstIPString, exempting: udpConfig.interceptExemptDNSServers
            ) {
                if handleDNSQuery(datagram, destination: destination) {
                    return  // Fake response sent, no flow needed
                }
                // `.publicResolver` non-A/AAAA — fall through, proxy MX/SRV/TXT to real server
            }
            // Non-intercepted DNS server — fall through to ordinary UDP flow
        }
        
        // Block UDP: reject every datagram except DNS (port 53).
        if udpConfig.blockUDP && datagram.dstPort != 53 {
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }
        
        // QUIC (Blocked mode): drop UDP/443 with ICMP port-unreachable so
        // HTTP/3 clients fail fast and fall back to HTTP/2. Automatic mode is
        // decided post-resolution below (needs the routing result).
        if datagram.dstPort == 443 && udpConfig.quicPolicy.blocksAllQUIC {
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }
        
        // WebRTC: reject STUN so ICE gathering fails fast. STUN rides arbitrary
        // negotiated ports, so classify by payload; runs before the flow lookup
        // so a candidate never opens a flow.
        if udpConfig.blockWebRTC && TunnelStack.isSTUNMessage(payload) {
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }
        
        // Fast path: deliver to an existing flow. The flow holds its resolved
        // domain from creation, so it survives fake-IP pool eviction.
        let flowKey = TunnelStack.UDPFlowKey(
            srcIP: datagram.srcIP, srcPort: datagram.srcPort,
            dstIP: datagram.dstIP, dstPort: datagram.dstPort,
            isIPv6: isIPv6
        )
        if let flow = flows[flowKey] {
            Task { await flow.handleReceivedData(payload, payloadLength: payload.count) }
            return
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
        var routeTarget = udpConfig.defaultRouteTarget
        var ruleSetName: String? = nil
        
        switch decision.action {
        case .route(let target, let configuration, let matchedRuleSet):
            routeTarget = target
            ruleSetName = matchedRuleSet
            if let configuration {
                flowConfiguration = configuration
            }
        case .routeViaDefault:
            break
        case .reject(let matchedRuleSet):
            stack.requestLog.record(protocol: .udp, host: dstHost, port: datagram.dstPort, routeTarget: .reject, ruleSetName: matchedRuleSet)
            return
        case .unreachable:
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }
        
        // QUIC (Automatic mode): drop UDP/443 that is proxied or MITM-listed,
        // forcing fallback to TCP where those paths work. `mitmListed` is an
        // autoclosure — the trie is consulted only when it can change the answer.
        let isProxied = routeTarget.configurationID != nil
        if datagram.dstPort == 443,
           udpConfig.quicPolicy.blocksResolvedQUIC(
            isProxied: isProxied,
            mitmListed: dstIsDomain && udpConfig.mitmEnabled && stack.mitmPolicy.matches(dstHost)
           ) {
            logger.debug("[UDP] QUIC blocked (automatic): \(dstHost):443 reason=\(isProxied ? "proxied" : "mitm")")
            stack.sendICMPPortUnreachable(rejecting: datagram)
            return
        }
        
        stack.requestLog.record(protocol: .udp, host: dstHost, port: datagram.dstPort, routeTarget: routeTarget, viaDefault: decision.viaDefault, ruleSetName: ruleSetName)
        
        let flow = UDPFlow(
            stack: stack,
            plane: self,
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
        flushAllFlowsIfAtCap()
        flows[flowKey] = flow
        Task { await flow.handleReceivedData(payload, payloadLength: payload.count) }
    }

    // MARK: - Flow registry

    func remove(_ flow: UDPFlow) {
        if flows[flow.flowKey] === flow {
            flows.removeValue(forKey: flow.flowKey)
        }
    }
    
    private func flushAllFlowsIfAtCap() {
        guard flows.count >= TunnelLimits.udpMaxFlows else { return }
        logger.warning("[UDP] Flow cap reached (\(flows.count)/\(TunnelLimits.udpMaxFlows)); silently flushing all UDP flows, clients will retry")
        let all = Array(flows.values)
        flows.removeAll()
        for flow in all {
            Task { await flow.close() }
        }
        pendingResolutions.removeAll()
        pendingResolutionCapWarned = false
        purgeShadowsocksUDPSessions()
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
    
    private func handleDNSQuery(_ datagram: UDPPacket.Inbound, destination: TunnelStack.DNSDestination) -> Bool {
        let payload = datagram.payload
        guard let parsed = payload.withUnsafeBytes({ ptr -> (domain: String, qtype: UInt16)? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.parseQuery(UnsafeBufferPointer(start: base, count: ptr.count))
        }) else { return false }
        
        let domain = parsed.domain.lowercased()
        let qtype = parsed.qtype
        
        // Block DDR (RFC 9462) — otherwise the system auto-upgrades to DoH/DoT
        // and bypasses the port-53 interception this tunnel relies on.
        if domain == "_dns.resolver.arpa" {
            return sendNODATA(answering: datagram, qtype: qtype)
        }
        
        // NODATA for SVCB/HTTPS (qtype 65, RFC 9460). NODATA forces the
        // fallback to A/AAAA, which we fake-IP and route.
        if qtype == 65 {
            return sendNODATA(answering: datagram, qtype: qtype)
        }
        
        guard qtype == 1 || qtype == 28 else {
            if destination == .anywhereResolver {
                if forwardToUpstreamResolver(datagram, domain: domain, qtype: qtype) {
                    return true
                }
                return sendNODATA(answering: datagram, qtype: qtype)
            }
            return false
        }
        
        let offset = stack.fakeIPPool.allocate(domain: domain)
        
        var fakeIPBytes: [UInt8]?
        if qtype == 1 {
            let ipv4 = FakeIPPool.ipv4Bytes(offset: offset)
            fakeIPBytes = [ipv4.0, ipv4.1, ipv4.2, ipv4.3]
        } else if qtype == 28, stack.udpConfig().advertiseIPv6ToApps {
            fakeIPBytes = FakeIPPool.ipv6Bytes(offset: offset)
        }
        
        guard let responseData = payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                fakeIP: fakeIPBytes,
                qtype: qtype
            )
        }) else { return false }
        
        stack.writeOutboundUDP(
            srcIP: datagram.dstIPData, srcPort: datagram.dstPort,
            dstIP: datagram.srcIPData, dstPort: datagram.srcPort,
            isIPv6: datagram.isIPv6, payload: responseData
        )
        
        return true
    }
    
    private func forwardToUpstreamResolver(_ datagram: UDPPacket.Inbound, domain: String, qtype: UInt16) -> Bool {
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
            Task { await existing.handleReceivedData(payload, payloadLength: payload.count) }
            return true
        }
        
        let decision = stack.connectionRouter.decision(forIP: upstream, port: datagram.dstPort, proto: "UDP")
        
        var flowConfiguration = defaultConfiguration
        var routeTarget = udpConfig.defaultRouteTarget
        var ruleSetName: String? = nil
        
        switch decision.action {
        case .route(let target, let ruleConfiguration, let matchedRuleSet):
            routeTarget = target
            ruleSetName = matchedRuleSet
            if let ruleConfiguration { flowConfiguration = ruleConfiguration }
        case .routeViaDefault:
            break
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
        
        stack.requestLog.record(
            protocol: .udp, host: upstream, port: datagram.dstPort,
            routeTarget: routeTarget, viaDefault: decision.viaDefault,
            ruleSetName: ruleSetName
        )
        
        let flow = UDPFlow(
            stack: stack,
            plane: self,
            flowKey: flowKey,
            srcHost: TunnelStack.ipAddrToString(datagram.srcIP, isIPv6: datagram.isIPv6),
            srcPort: datagram.srcPort,
            dstHost: upstream,                  // outbound → real upstream resolver
            dstPort: datagram.dstPort,
            srcIPData: datagram.srcIPData,
            dstIPData: datagram.dstIPData,      // reply source → the Anywhere resolver address
            isIPv6: datagram.isIPv6,
            configuration: flowConfiguration,
            routeTarget: routeTarget
        )
        flushAllFlowsIfAtCap()
        flows[flowKey] = flow
        logger.debug("[DNS] Forwarding qtype \(qtype) for \(domain) → \(upstream):\(datagram.dstPort) via \(flowConfiguration.name)")
        Task { await flow.handleReceivedData(payload, payloadLength: payload.count) }
        return true
    }
    
    private func sendNODATA(answering datagram: UDPPacket.Inbound, qtype: UInt16) -> Bool {
        guard let responseData = datagram.payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                fakeIP: nil,
                qtype: qtype
            )
        }) else { return false }
        
        stack.writeOutboundUDP(
            srcIP: datagram.dstIPData, srcPort: datagram.dstPort,
            dstIP: datagram.srcIPData, dstPort: datagram.srcPort,
            isIPv6: datagram.isIPv6, payload: responseData
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
