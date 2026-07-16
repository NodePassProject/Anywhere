//
//  TunnelStack+UDP.swift
//  Anywhere
//
//  Created by NodePassProject on 5/23/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TunnelStack+UDP")

extension TunnelStack {

    // MARK: - Flow Registry

    /// Removes `flow` only if it is still the registered flow for its key — a
    /// stale teardown callback must not orphan a recreated flow for the same
    /// 5-tuple. Must be called on ``udpQueue``.
    func removeUDPFlow(_ flow: UDPFlow) {
        udpFlows.withLock { flows in
            if flows[flow.flowKey] === flow {
                flows.removeValue(forKey: flow.flowKey)
            }
        }
    }

    /// The UDP flow cap in effect: shrinks under kernel flow pressure so a
    /// UDP-heavy swarm sheds instead of pinning the whole budget. Enter/exit
    /// watermarks differ (hysteresis). Run on ``udpQueue``.
    func currentUDPFlowCap() -> Int {
        let load = FlowGauge.admissionLoad
        if udpPressureShedding {
            if load < TunnelLimits.flowPressureExitWatermark {
                udpPressureShedding = false
                return TunnelLimits.udpMaxFlows
            }
            return TunnelLimits.udpMaxFlowsUnderPressure
        }
        if load >= TunnelLimits.flowPressureWatermark {
            udpPressureShedding = true
            return TunnelLimits.udpMaxFlowsUnderPressure
        }
        return TunnelLimits.udpMaxFlows
    }

    /// Caps ``udpFlows`` by evicting the flows with the smallest idle deadlines —
    /// unreplied flows time out sooner, so one-way NAT probes shed first.
    /// Run on ``udpQueue`` before each insert.
    func evictUDPFlowsToAdmit() {
        let cap = currentUDPFlowCap()
        let count = udpFlows.withLock { $0.count }
        guard count >= cap else { return }
        if !udpFlowCapWarned {
            udpFlowCapWarned = true
            logger.warning("[UDP] Flow table at capacity (\(cap)); evicting flows with least time left to bound memory")
        }
        // Free one slot for the incoming flow — plus, under pressure, whatever
        // it takes to get back under the shrunken cap.
        shedUDPFlows(count: count - cap + 1)
    }

    /// Closes up to ``TunnelLimits/udpShedBatchLimit`` of the flows with the
    /// smallest idle deadlines — batched so a cap shrink drains over a few
    /// passes instead of one teardown churn spike. Run on ``udpQueue``.
    func shedUDPFlows(count: Int) {
        let shedCount = min(count, TunnelLimits.udpShedBatchLimit)
        guard shedCount > 0 else { return }
        // Snapshot the flows under the registry lock, then rank by deadline (a nonisolated read)
        // and close the victims off-lock on their own actors.
        let flows = udpFlows.withLock { Array($0.values) }
        let victims = flows.sorted { $0.idleDeadline < $1.idleDeadline }.prefix(shedCount)
        for victim in victims {
            Task { await victim.close() }
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
                if handleDNSQuery(datagram, destination: destination) {
                    return  // Fake response sent, no flow needed
                }
                // `.publicResolver` non-A/AAAA — fall through, proxy MX/SRV/TXT to real server
            }
            // Non-intercepted DNS server — fall through to ordinary UDP flow
        }

        // Block UDP: reject every datagram except DNS (port 53).
        if udpConfig.blockUDP && datagram.dstPort != 53 {
            sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        // QUIC (Blocked mode): drop UDP/443 with ICMP port-unreachable so
        // HTTP/3 clients fail fast and fall back to HTTP/2. Automatic mode is
        // decided post-resolution below (needs the routing result).
        if datagram.dstPort == 443 && udpConfig.quicPolicy.blocksAllQUIC {
            sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        // WebRTC: reject STUN so ICE gathering fails fast. STUN rides arbitrary
        // negotiated ports, so classify by payload; runs before the flow lookup
        // so a candidate never opens a flow.
        if udpConfig.blockWebRTC && TunnelStack.isSTUNMessage(payload) {
            sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        // Fast path: deliver to an existing flow. The flow holds its resolved
        // domain from creation, so it survives fake-IP pool eviction.
        let flowKey = UDPFlowKey(srcIP: datagram.srcIP, srcPort: datagram.srcPort,
                                 dstIP: datagram.dstIP, dstPort: datagram.dstPort, isIPv6: isIPv6)
        if let flow = udpFlows.withLock({ $0[flowKey] }) {
            Task { await flow.handleReceivedData(payload, payloadLength: payload.count) }
            return
        }

        guard let defaultConfiguration = udpConfig.configuration else { return }
        let dstIPString = TunnelStack.ipAddrToString(datagram.dstIP, isIPv6: isIPv6)
        let srcHost = TunnelStack.ipAddrToString(datagram.srcIP, isIPv6: isIPv6)
        let srcIPData = datagram.srcIPData
        let dstIPData = datagram.dstIPData

        let decision = connectionRouter.decision(forIP: dstIPString, port: datagram.dstPort, proto: "UDP")
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
            requestLog.record(protocol: .udp, host: dstHost, port: datagram.dstPort, routeTarget: .reject, ruleSetName: matchedRuleSet)
            sendICMPPortUnreachable(rejecting: datagram)
            return
        case .unreachable:
            sendICMPPortUnreachable(rejecting: datagram)
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
            sendICMPPortUnreachable(rejecting: datagram)
            return
        }

        // Shed new non-DNS flows above the UDP watermark. Silent drop: the
        // app's own timeout is the backoff, where an ICMP reply would invite
        // an instant retry. DNS is exempt so resolution survives pressure.
        let sheddingNewFlows = FlowGauge.admissionLoad >= TunnelLimits.udpFlowAdmissionWatermark
        if sheddingNewFlows {
            if datagram.dstPort != 53 {
                if !udpShedWarned {
                    udpShedWarned = true
                    logger.warning("[UDP] dropping new flows: kernel flow pressure [flows=\(FlowGauge.live) udp=\(FlowGauge.liveUDP)]")
                }
                return
            }
            // DNS rides through without resetting the shed latch.
        } else if udpShedWarned {
            udpShedWarned = false
            logger.info("[UDP] flow pressure recovered; admitting new flows")
        }

        requestLog.record(protocol: .udp, host: dstHost, port: datagram.dstPort, routeTarget: routeTarget, viaDefault: decision.viaDefault, ruleSetName: ruleSetName)

        let flow = UDPFlow(
            stack: self,
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
        udpFlows.withLock { $0[flowKey] = flow }
        Task { await flow.handleReceivedData(payload, payloadLength: payload.count) }
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

    /// Answers `datagram` with ICMP port-unreachable — sourced from the
    /// original destination — so the sender abandons the destination fast
    /// (QUIC fallback, stale fake IPs, blocked UDP). Callable from any queue.
    func sendICMPPortUnreachable(rejecting datagram: UDPPacket.Inbound) {
        guard let packet = ICMPPacket.portUnreachable(
            srcIP: datagram.srcIPData,
            srcPort: datagram.srcPort,
            dstIP: datagram.dstIPData,
            dstPort: datagram.dstPort,
            isIPv6: datagram.isIPv6,
            udpPayloadLength: datagram.payload.count
        ) else { return }
        enqueueOutbound(packet, isIPv6: datagram.isIPv6)
    }

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
