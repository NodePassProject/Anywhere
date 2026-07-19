//
//  UDPPlane.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "UDPPlane")

nonisolated enum UDPPlaneCommand {
    /// Install the mux pool built for the current runtime config (no teardown).
    case setMultiplexerPool(VLESSVisionUDPMultiplexerPool?)
    /// Tear down the per-tunnel UDP transports and install `replacement`.
    case reclaim(replacementMultiplexerPool: VLESSVisionUDPMultiplexerPool?)
}

actor UDPPlane {

    private unowned let stack: TunnelStack

    // MARK: Registry / session state

    /// Active UDP flows keyed by 5-tuple.
    private var flows: [TunnelStack.UDPFlowKey: UDPFlow] = [:]

    /// Shared Shadowsocks UDP sessions keyed by configuration id: one session serves every flow
    /// for that configuration, so a shared sessionID + socket restores full-cone NAT.
    private var ssSessions: [UUID: ShadowsocksUDPSession] = [:]

    /// Mux manager for multiplexing Vision UDP flows (present when a Vision flow is active).
    private var multiplexerPoolStorage: VLESSVisionUDPMultiplexerPool?

    /// Rising-edge latch so a sustained flow storm logs once, not per evicted flow.
    private var flowCapWarned = false
    /// Rising-edge latch for UDP flows shed by the flow budget / exhaustion brake.
    private var shedWarned = false
    /// Whether the UDP flow cap is shrunk to ``TunnelLimits/udpMaxFlowsUnderPressure``.
    private var pressureShedding = false

    init(stack: TunnelStack) {
        self.stack = stack
    }

    // MARK: - Multiplexer pool

    /// The active Vision UDP mux pool; read by flows dialing the fast path.
    var multiplexerPool: VLESSVisionUDPMultiplexerPool? { multiplexerPoolStorage }

    /// Applies a mux/reclaim command in the order the stack's driver submits them, so a restart's
    /// reclaim-then-set can't be reordered.
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
    
    private func handleInboundUDP(_ datagram: UDPPacket.Inbound) {
        let payload = datagram.payload
        let isIPv6 = datagram.isIPv6

        // Read config from the published snapshot — the stored properties are lwipQueue-owned.
        let udpConfig = stack.udpConfig()

        // DNS interception: fake-IP for our own resolver; queries to any other
        // resolver are proxied to the real server.
        if datagram.dstPort == 53 {
            let dstIPString = TunnelStack.ipAddrToString(datagram.dstIP, isIPv6: isIPv6)
            if let destination = TunnelStack.dnsDestination(for: dstIPString) {
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
        let flowKey = TunnelStack.UDPFlowKey(srcIP: datagram.srcIP, srcPort: datagram.srcPort,
                                             dstIP: datagram.dstIP, dstPort: datagram.dstPort, isIPv6: isIPv6)
        if let flow = flows[flowKey] {
            Task { await flow.handleReceivedData(payload, payloadLength: payload.count) }
            return
        }

        guard let defaultConfiguration = udpConfig.configuration else { return }
        let dstIPString = TunnelStack.ipAddrToString(datagram.dstIP, isIPv6: isIPv6)
        let srcHost = TunnelStack.ipAddrToString(datagram.srcIP, isIPv6: isIPv6)
        let srcIPData = datagram.srcIPData
        let dstIPData = datagram.dstIPData

        let decision = stack.connectionRouter.decision(forIP: dstIPString, port: datagram.dstPort, proto: "UDP")
        let dstHost = decision.host
        let dstIsDomain = decision.hostIsResolvedDomain

        var flowConfiguration = defaultConfiguration
        // Committed routing identity; drives the dial path and the QUIC automatic
        // check. Read from the snapshot — the stored property is lwipQueue-owned.
        var routeTarget = udpConfig.defaultRouteTarget
        // Rule set behind the committed route; nil while on the default.
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
            stack.sendICMPPortUnreachable(rejecting: datagram)
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

        // Shed new non-DNS flows above the UDP watermark. Silent drop: the
        // app's own timeout is the backoff, where an ICMP reply would invite
        // an instant retry. DNS is exempt so resolution survives pressure.
        let sheddingNewFlows = FlowGauge.admissionLoad >= TunnelLimits.udpFlowAdmissionWatermark
        if sheddingNewFlows {
            if datagram.dstPort != 53 {
                if !shedWarned {
                    shedWarned = true
                    logger.warning("[UDP] dropping new flows: kernel flow pressure [flows=\(FlowGauge.live) udp=\(FlowGauge.liveUDP)]")
                }
                return
            }
            // DNS rides through without resetting the shed latch.
        } else if shedWarned {
            shedWarned = false
            logger.info("[UDP] flow pressure recovered; admitting new flows")
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
        evictUDPFlowsToAdmit()
        flows[flowKey] = flow
        Task { await flow.handleReceivedData(payload, payloadLength: payload.count) }
    }

    // MARK: - Flow registry

    /// Removes `flow` only if it is still the registered flow for its key — a stale teardown
    /// callback must not orphan a recreated flow for the same 5-tuple.
    func remove(_ flow: UDPFlow) {
        if flows[flow.flowKey] === flow {
            flows.removeValue(forKey: flow.flowKey)
        }
    }

    /// The UDP flow cap in effect: shrinks under kernel flow pressure so a UDP-heavy swarm sheds
    /// instead of pinning the whole budget. Enter/exit watermarks differ (hysteresis).
    private func currentUDPFlowCap() -> Int {
        let load = FlowGauge.admissionLoad
        if pressureShedding {
            if load < TunnelLimits.flowPressureExitWatermark {
                pressureShedding = false
                return TunnelLimits.udpMaxFlows
            }
            return TunnelLimits.udpMaxFlowsUnderPressure
        }
        if load >= TunnelLimits.flowPressureWatermark {
            pressureShedding = true
            return TunnelLimits.udpMaxFlowsUnderPressure
        }
        return TunnelLimits.udpMaxFlows
    }

    /// Caps ``flows`` by evicting the flows with the smallest idle deadlines — unreplied flows time
    /// out sooner, so one-way NAT probes shed first. Run before each insert.
    private func evictUDPFlowsToAdmit() {
        let cap = currentUDPFlowCap()
        guard flows.count >= cap else { return }
        if !flowCapWarned {
            flowCapWarned = true
            logger.warning("[UDP] Flow table at capacity (\(cap)); evicting flows with least time left to bound memory")
        }
        // Free one slot for the incoming flow — plus, under pressure, whatever it takes to get
        // back under the shrunken cap.
        shedUDPFlows(count: flows.count - cap + 1)
    }

    /// Closes up to ``TunnelLimits/udpShedBatchLimit`` of the flows with the smallest idle
    /// deadlines — batched so a cap shrink drains over a few passes instead of one teardown spike.
    private func shedUDPFlows(count: Int) {
        let shedCount = min(count, TunnelLimits.udpShedBatchLimit)
        guard shedCount > 0 else { return }
        // Rank by deadline (a nonisolated read) and close the victims on their own actors.
        let victims = flows.values.sorted { $0.idleDeadline < $1.idleDeadline }.prefix(shedCount)
        for victim in victims {
            Task { await victim.close() }
            if flows[victim.flowKey] === victim {
                flows.removeValue(forKey: victim.flowKey)
            }
        }
    }

    // MARK: - Cleanup (periodic)

    /// Reaps UDP flows past their idle deadline and sheds below the (possibly shrunken) cap under
    /// kernel flow pressure. Driven by ``TunnelScheduler`` so it catches up promptly on device wake.
    func cleanup() {
        let now = MonotonicClock.now
        for (key, flow) in flows where now > flow.idleDeadline {
            Task { await flow.close() }
            flows.removeValue(forKey: key)
        }
        // Under kernel flow pressure, shed below the shrunken cap even with no inserts arriving —
        // TCP alone can fill the budget, and eviction-on-insert never runs then.
        let cap = currentUDPFlowCap()
        if flows.count > cap {
            shedUDPFlows(count: flows.count - cap)
        }
        // Re-arm the flow-cap warning so a later storm logs its own rising edge.
        if flowCapWarned && flows.count < cap {
            flowCapWarned = false
        }
    }

    // MARK: - Shadowsocks UDP sessions

    /// Returns the shared SS UDP session for `configuration`, creating or replacing terminal ones;
    /// sharing one sessionID + socket across flows restores full-cone NAT.
    func shadowsocksSession(for configuration: ProxyConfiguration) -> Result<ShadowsocksUDPSession, Error> {
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

    /// Cancels and forgets every SS UDP session.
    private func purgeShadowsocksUDPSessions() {
        let all = Array(ssSessions.values)
        ssSessions.removeAll()
        for session in all { session.cancel() }
    }

    // MARK: - DNS interception (fake-IP)

    /// Intercepts a DNS query carried by `datagram`. Returns true if handled (no UDP flow needed).
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

        // NODATA for SVCB/HTTPS (qtype 65, RFC 9460): proxied answers follow
        // CNAME chains that routing rules (matched on the original domain) may
        // miss; this forces fallback to A/AAAA, which we fake-IP.
        if qtype == 65 {
            return sendNODATA(answering: datagram, qtype: qtype)
        }

        // Only A (1) and AAAA (28) get fake IPs. Other types:
        // `.anywhereResolver` forwards upstream (NODATA if no config);
        // `.publicResolver` falls through to a proxied UDP flow.
        guard qtype == 1 || qtype == 28 else {
            if destination == .anywhereResolver {
                if forwardToUpstreamResolver(datagram, domain: domain, qtype: qtype) {
                    return true
                }
                return sendNODATA(answering: datagram, qtype: qtype)
            }
            return false
        }

        // Fake-IP even rejected domains — a NODATA here could be negatively
        // cached by the OS; rejects are enforced at connection time instead.
        let offset = stack.fakeIPPool.allocate(domain: domain)

        var fakeIPBytes: [UInt8]?
        if qtype == 1 {
            let ipv4 = FakeIPPool.ipv4Bytes(offset: offset)
            fakeIPBytes = [ipv4.0, ipv4.1, ipv4.2, ipv4.3]
        } else if qtype == 28, stack.udpConfig().advertiseIPv6ToApps {
            fakeIPBytes = FakeIPPool.ipv6Bytes(offset: offset)
        }
        // else: AAAA with IPv6 disabled → nil → NODATA response

        guard let responseData = payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                fakeIP: fakeIPBytes,
                qtype: qtype
            )
        }) else { return false }

        // Reply sourced from the resolver the app queried so the client accepts it.
        stack.writeOutboundUDP(
            srcIP: datagram.dstIPData, srcPort: datagram.dstPort,
            dstIP: datagram.srcIPData, dstPort: datagram.srcPort,
            isIPv6: datagram.isIPv6, payload: responseData
        )

        return true
    }

    /// Forwards a non-A/AAAA query to a real upstream resolver through the default proxy and relays
    /// the reply (nothing answers behind the tunnel peer address). Returns `false` when there is no
    /// active configuration; the caller falls back to NODATA.
    private func forwardToUpstreamResolver(_ datagram: UDPPacket.Inbound, domain: String, qtype: UInt16) -> Bool {
        let udpConfig = stack.udpConfig()
        guard let configuration = udpConfig.configuration else { return false }

        // Forward over IPv4 regardless of query family — proxy egress always
        // reaches it; the reply family follows the flow's `isIPv6`.
        let upstream = TunnelConstants.fallbackDNSServers(includeIPv6: false).first ?? "1.1.1.1"
        let payload = datagram.payload

        // Key on the original 5-tuple so a retransmitted query reuses this flow;
        // intercepted destinations re-enter here, never the fast path.
        let flowKey = TunnelStack.UDPFlowKey(srcIP: datagram.srcIP, srcPort: datagram.srcPort,
                                             dstIP: datagram.dstIP, dstPort: datagram.dstPort, isIPv6: datagram.isIPv6)
        if let existing = flows[flowKey] {
            Task { await existing.handleReceivedData(payload, payloadLength: payload.count) }
            return true
        }

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
            configuration: configuration,
            routeTarget: udpConfig.defaultRouteTarget   // proxied via the default outbound
        )
        evictUDPFlowsToAdmit()
        flows[flowKey] = flow
        logger.debug("[DNS] Forwarding qtype \(qtype) for \(domain) → \(upstream):\(datagram.dstPort) via \(configuration.name)")
        Task { await flow.handleReceivedData(payload, payloadLength: payload.count) }
        return true
    }

    /// Answers `datagram` with a NODATA DNS response (ANCOUNT=0).
    private func sendNODATA(answering datagram: UDPPacket.Inbound, qtype: UInt16) -> Bool {
        guard let responseData = datagram.payload.withUnsafeBytes({ ptr -> Data? in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return nil }
            return DNSPacket.generateResponse(
                query: UnsafeBufferPointer(start: base, count: ptr.count),
                fakeIP: nil,
                qtype: qtype
            )
        }) else { return false }

        // Response sourced from the resolver the app queried (original dst).
        stack.writeOutboundUDP(
            srcIP: datagram.dstIPData, srcPort: datagram.dstPort,
            dstIP: datagram.srcIPData, dstPort: datagram.srcPort,
            isIPv6: datagram.isIPv6, payload: responseData
        )

        return true
    }

    // MARK: - Reclaim

    /// Tears down the per-tunnel UDP transports (Vision mux, SS sessions, per-flow connections) and
    /// installs `replacementMultiplexerPool` (built on the lwIP queue, which owns `configuration`).
    /// Serialized against intake by the actor, so a datagram can't land on a half-swapped mux.
    private func reclaim(replacementMultiplexerPool: VLESSVisionUDPMultiplexerPool?) {
        multiplexerPoolStorage?.closeAll()
        multiplexerPoolStorage = replacementMultiplexerPool
        purgeShadowsocksUDPSessions()
        let all = Array(flows.values)
        flows.removeAll()
        for flow in all {
            Task { await flow.close() }
        }
    }
}
