//
//  TunnelStack+UDP.swift
//  Anywhere
//
//  Created by NodePassProject on 5/23/26.
//

import Foundation

private let logger = AnywhereLogger(category: "TunnelStack+UDP")

extension TunnelStack {

    // MARK: - Flow Registry

    /// Removes `flow` only if it is still the registered flow for its key — a
    /// stale teardown callback must not orphan a recreated flow for the same
    /// 5-tuple. Must be called on ``udpQueue``.
    func removeUDPFlow(_ flow: UDPFlow) {
        if udpFlows[flow.flowKey] === flow {
            udpFlows.removeValue(forKey: flow.flowKey)
        }
    }

    /// Caps ``udpFlows`` by evicting the flow with the smallest idle deadline —
    /// unreplied flows time out sooner, so one-way NAT probes shed first. Async
    /// `close` (never `closeSync`): the victim may be inside `getaddrinfo`.
    /// Run on ``udpQueue`` before each insert.
    func evictUDPFlowsToAdmit() {
        // Runs before every insert and frees at most one slot, so a single pass suffices.
        let cap = TunnelConstants.udpMaxFlows
        guard udpFlows.count >= cap else { return }

        var victim: UDPFlow?
        var victimDeadline = TimeInterval.greatestFiniteMagnitude
        for flow in udpFlows.values {
            let deadline = flow.idleDeadline
            if deadline < victimDeadline { victimDeadline = deadline; victim = flow }
        }

        if let victim {
            PerformanceMonitor.event(.udpFlowEvicted)
            if !udpFlowCapWarned {
                udpFlowCapWarned = true
                logger.warning("[UDP] Flow table at capacity (\(cap)); evicting flow with least time left to bound memory")
            }
            victim.close()
            removeUDPFlow(victim)
        }
    }

    // MARK: - Inbound UDP

    /// Routes one parsed inbound UDP datagram. Must be called on ``udpQueue``
    /// (mutates ``udpFlows``).
    func handleInboundUDP(_ datagram: UDPPacket.Inbound) {
        let payload = datagram.payload
        let isIPv6 = datagram.isIPv6

        // Read config from the published snapshot — the stored properties are
        // lwipQueue-owned.
        let udpConfig = udpConfig()

        // DNS interception: fake-IP for our own resolver; queries to any other
        // resolver are proxied to the real server.
        if datagram.dstPort == 53 {
            let dstIPString = TunnelStack.ipAddrToString(datagram.dstIP, isIPv6: isIPv6)
            if let destination = TunnelStack.dnsDestination(for: dstIPString) {
                if handleDNSQuery(
                    payload: payload,
                    srcIP: datagram.srcIPData,
                    srcPort: datagram.srcPort,
                    dstIP: datagram.dstIPData,
                    dstPort: datagram.dstPort,
                    isIPv6: isIPv6,
                    destination: destination
                ) {
                    return  // Fake response sent, no flow needed
                }
                // `.publicResolver` non-A/AAAA — fall through, proxy MX/SRV/TXT to real server
            }
            // Non-intercepted DNS server — fall through to ordinary UDP flow
        }

        // QUIC (Blocked mode): drop UDP/443 with ICMP port-unreachable so
        // HTTP/3 clients fail fast and fall back to HTTP/2. Automatic mode is
        // decided post-resolution below (needs the routing result).
        if datagram.dstPort == 443 && udpConfig.quicPolicy.blocksAllQUIC {
            sendICMPPortUnreachable(
                srcIP: datagram.srcIPData,
                srcPort: datagram.srcPort,
                dstIP: datagram.dstIPData,
                dstPort: datagram.dstPort,
                isIPv6: isIPv6,
                udpPayloadLength: payload.count
            )
            return
        }

        // WebRTC: reject STUN so ICE gathering fails fast. STUN rides arbitrary
        // negotiated ports, so classify by payload; runs before the flow lookup
        // so a candidate never opens a flow.
        if udpConfig.blockWebRTC && TunnelStack.isSTUNMessage(payload) {
            sendICMPPortUnreachable(
                srcIP: datagram.srcIPData,
                srcPort: datagram.srcPort,
                dstIP: datagram.dstIPData,
                dstPort: datagram.dstPort,
                isIPv6: isIPv6,
                udpPayloadLength: payload.count
            )
            return
        }

        // Fast path: deliver to an existing flow. The flow holds its resolved
        // domain from creation, so it survives fake-IP pool eviction.
        let flowKey = UDPFlowKey(srcIP: datagram.srcIP, srcPort: datagram.srcPort,
                                 dstIP: datagram.dstIP, dstPort: datagram.dstPort, isIPv6: isIPv6)
        if let flow = udpFlows[flowKey] {
            flow.handleReceivedData(payload, payloadLength: payload.count)
            return
        }

        guard let defaultConfiguration = udpConfig.configuration else { return }
        let dstIPString = TunnelStack.ipAddrToString(datagram.dstIP, isIPv6: isIPv6)
        let srcHost = TunnelStack.ipAddrToString(datagram.srcIP, isIPv6: isIPv6)
        let srcIPData = datagram.srcIPData
        let dstIPData = datagram.dstIPData

        var dstHost = dstIPString
        var flowConfiguration = defaultConfiguration
        // Committed routing identity; drives the dial path and the QUIC automatic check.
        var routeTarget = defaultRouteTarget
        var dstIsDomain = false

        // True until a routing rule matches — i.e. the default outbound is used.
        var viaDefault = true

        switch resolveFakeIP(dstIPString, dstPort: datagram.dstPort, proto: "UDP") {
        case .passthrough:
            if let action = domainRouter.matchIP(dstIPString) {
                viaDefault = false
                switch action {
                case .direct:
                    routeTarget = .direct
                case .reject:
                    requestLog.record(proto: "UDP", host: dstIPString, port: datagram.dstPort, routeTarget: .reject)
                    logger.debug("[UDP] IP rejected by routing rule: \(dstIPString):\(datagram.dstPort)")
                    sendICMPPortUnreachable(
                        srcIP: srcIPData,
                        srcPort: datagram.srcPort,
                        dstIP: dstIPData,
                        dstPort: datagram.dstPort,
                        isIPv6: isIPv6,
                        udpPayloadLength: payload.count
                    )
                    return
                case .proxy(let id):
                    routeTarget = .proxy(id)
                    if let configuration = domainRouter.resolveConfiguration(action: action) {
                        flowConfiguration = configuration
                    } else {
                        logger.warning("[UDP] Routing config not found for \(dstIPString)")
                    }
                }
            }
        case .resolved(let domain, let target, let configuration):
            dstHost = domain
            dstIsDomain = true
            // `target == nil` → no domain rule matched; keep the default route.
            switch target {
            case .direct:
                routeTarget = .direct
                viaDefault = false
            case .proxy(let id):
                routeTarget = .proxy(id)
                viaDefault = false
                if let configuration {
                    flowConfiguration = configuration
                }
            case .reject, .none:
                break
            }
        case .drop(let domain):
            requestLog.record(proto: "UDP", host: domain, port: datagram.dstPort, routeTarget: .reject)
            sendICMPPortUnreachable(
                srcIP: srcIPData,
                srcPort: datagram.srcPort,
                dstIP: dstIPData,
                dstPort: datagram.dstPort,
                isIPv6: isIPv6,
                udpPayloadLength: payload.count
            )
            return
        case .unreachable:
            sendICMPPortUnreachable(
                srcIP: srcIPData,
                srcPort: datagram.srcPort,
                dstIP: dstIPData,
                dstPort: datagram.dstPort,
                isIPv6: isIPv6,
                udpPayloadLength: payload.count
            )
            return
        }

        // QUIC (Automatic mode): drop UDP/443 that is proxied or MITM-listed,
        // forcing fallback to TCP where those paths work. `mitmListed` is an
        // autoclosure — the trie is consulted only when it can change the answer.
        let isProxied = routeTarget.configurationID != nil
        if datagram.dstPort == 443,
           udpConfig.quicPolicy.blocksResolvedQUIC(
               isProxied: isProxied,
               mitmListed: dstIsDomain && udpConfig.mitmEnabled && mitmPolicy.matches(dstHost)
           ) {
            logger.debug("[UDP] QUIC blocked (automatic): \(dstHost):443 reason=\(isProxied ? "proxied" : "mitm")")
            sendICMPPortUnreachable(
                srcIP: srcIPData,
                srcPort: datagram.srcPort,
                dstIP: dstIPData,
                dstPort: datagram.dstPort,
                isIPv6: isIPv6,
                udpPayloadLength: payload.count
            )
            return
        }

        requestLog.record(
            proto: "UDP",
            host: dstHost,
            port: datagram.dstPort,
            routeTarget: routeTarget,
            viaDefault: viaDefault
        )

        let flow = UDPFlow(
            flowKey: flowKey,
            srcHost: srcHost,
            srcPort: datagram.srcPort,
            dstHost: dstHost,
            dstPort: datagram.dstPort,
            srcIPData: srcIPData,
            dstIPData: dstIPData,
            isIPv6: isIPv6,
            configuration: flowConfiguration,
            routeTarget: routeTarget,
            flowQueue: udpQueue
        )
        evictUDPFlowsToAdmit()
        udpFlows[flowKey] = flow
        PerformanceMonitor.gauge(.udpFlowCount, udpFlows.count, highWater: TunnelConstants.udpMaxFlows)
        flow.handleReceivedData(payload, payloadLength: payload.count)
    }

    /// Classifies a STUN message (RFC 5389 §6) by the magic cookie at offset 4
    /// plus structural checks, so no port allow-list is needed. Classic STUN
    /// (RFC 3489, no cookie) is deliberately unmatched — WebRTC always sends
    /// the cookie, and matching cookieless traffic could drop unrelated UDP.
    static func isSTUNMessage(_ payload: Data) -> Bool {
        guard payload.count >= 20 else { return false }
        // A sliced `Data` keeps its parent's indices — address relative to startIndex.
        let base = payload.startIndex
        guard payload[base] & 0xC0 == 0 else { return false }
        // Bytes 4–7: the magic cookie.
        guard payload[base + 4] == 0x21, payload[base + 5] == 0x12,
              payload[base + 6] == 0xA4, payload[base + 7] == 0x42 else { return false }
        // Length must be 4-byte aligned and fill the datagram exactly.
        let messageLength = Int(payload[base + 2]) << 8 | Int(payload[base + 3])
        return messageLength & 0x3 == 0 && messageLength + 20 == payload.count
    }

    // MARK: - Outbound UDP

    /// Builds a UDP packet and queues it to the TUN output; callers pass the
    /// original 5-tuple swapped. Callable from any queue.
    func writeOutboundUDP(srcIP: Data, srcPort: UInt16,
                          dstIP: Data, dstPort: UInt16,
                          isIPv6: Bool, payload: Data) {
        guard let packet = UDPPacket.build(
            srcIP: srcIP, srcPort: srcPort,
            dstIP: dstIP, dstPort: dstPort,
            isIPv6: isIPv6, payload: payload
        ) else {
            logger.debug("[UDP] Dropped outbound datagram: build failed (len=\(payload.count), v6=\(isIPv6))")
            return
        }
        enqueueOutbound(packet, isIPv6: isIPv6)
    }
}
