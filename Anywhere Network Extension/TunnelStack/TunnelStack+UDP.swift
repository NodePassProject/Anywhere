//
//  TunnelStack+UDP.swift
//  Anywhere
//
//  Created by NodePassProject on 5/23/26.
//

import Foundation

private let logger = AnywhereLogger(category: "TunnelStack")

extension TunnelStack {

    // MARK: - Flow Registry

    /// Removes `flow` from ``udpFlows`` only if it is still the flow registered
    /// for its key. Teardown callbacks (mux/Shadowsocks/proxy close handlers,
    /// receive and connect failures) fire asynchronously on ``udpQueue``, and
    /// during a network-path change the old transports error out just as resumed
    /// traffic recreates a flow for the same 5-tuple. A blind
    /// `removeValue(forKey:)` from a stale callback would then evict that *newer*
    /// flow and strand it — freed without `close()`, tripping the DEBUG leak
    /// tripwire in ``UDPFlow``'s `deinit`. Identity-guarding makes every removal
    /// self-only and idempotent.
    ///
    /// Must be called on ``udpQueue``.
    func removeUDPFlow(_ flow: UDPFlow) {
        if udpFlows[flow.flowKey] === flow {
            udpFlows.removeValue(forKey: flow.flowKey)
        }
    }

    /// Admission control for a new UDP flow, run on ``udpQueue`` immediately
    /// before the flow is inserted into ``udpFlows``. Bounds the data plane's
    /// memory footprint so a misbehaving client can't OOM the extension. Each
    /// live flow pins a socket (kernel buffers) plus a 64 KB in-process receive
    /// buffer.
    ///
    /// When the table is at ``TunnelConstants/udpMaxFlows`` the flow with the
    /// least time left before its own idle deadline is evicted to admit the new
    /// one. Because an unreplied flow's deadline is only
    /// ``TunnelConstants/udpIdleTimeoutUnreplied`` (30s) out versus
    /// ``TunnelConstants/udpIdleTimeoutStream`` (120s) for an established one,
    /// this preferentially sheds one-way NAT-traversal probes — the usual cause
    /// of a flow storm — before any flow an app is actively using, so no
    /// separate per-destination cap is needed.
    ///
    /// Eviction uses async ``UDPFlow/close`` (never `closeSync`): memory relief,
    /// unlike FD-pressure relief, needn't free the FD before returning, and
    /// async close avoids any cross-queue wait on a victim still inside
    /// `getaddrinfo`.
    func evictUDPFlowsToAdmit() {
        // Eviction precedes every insert and frees at most one slot — exactly
        // the one flow about to be added — so the table never exceeds the cap
        // and a single pass suffices (no drain loop). Below the cap nothing is
        // evicted, so the unloaded path is one comparison and no scan.
        let cap = TunnelConstants.udpMaxFlows
        guard udpFlows.count >= cap else { return }

        // Evict the flow with the least time left before it would idle out on
        // its own — the smallest idle deadline. `now` is constant across the
        // scan, so comparing deadlines directly ranks flows by time-left, and an
        // unreplied probe's 30s deadline sorts ahead of an established flow's
        // 120s one.
        var victim: UDPFlow?
        var victimDeadline = CFAbsoluteTime.greatestFiniteMagnitude
        for flow in udpFlows.values {
            let deadline = flow.idleDeadline
            if deadline < victimDeadline { victimDeadline = deadline; victim = flow }
        }

        if let victim {
            if !udpFlowCapWarned {
                udpFlowCapWarned = true
                logger.warning("[UDP] Flow table at capacity (\(cap)); evicting flow with least time left to bound memory")
            }
            victim.close()
            removeUDPFlow(victim)
        }
    }

    // MARK: - Inbound UDP
    //
    // UDP is handled entirely outside lwIP (built TCP-only). ``startReadingPackets``
    // routes UDP datagrams here after ``UDPPacket/parse`` extracts the 5-tuple
    // and payload; TCP/ICMP still flow through ``lwip_bridge_input``. The
    // routing logic below mirrors the TCP accept path in ``TunnelStack`` (`+Callbacks`):
    // resolve the fake IP, apply IP/domain rules, then create or feed a
    // per-flow ``UDPFlow``.

    /// Routes one parsed inbound UDP datagram. Must be called on ``udpQueue``
    /// (mutates ``udpFlows``).
    func handleInboundUDP(_ datagram: UDPPacket.Inbound) {
        let payload = datagram.payload
        let isIPv6 = datagram.isIPv6

        // Read the config the cold path needs once, from the snapshot
        // ``lwipQueue`` publishes — never the stored properties directly, which
        // that queue owns and mutates at start/restart.
        let cfg = udpConfig()

        // The DNS and Blocked-mode QUIC checks run before the flow lookup; the
        // Automatic-mode QUIC/MITM decision needs the routing result, so it
        // runs after resolution further down. The address string and `Data`
        // forms are computed lazily: an established flow (including an allowed
        // UDP/443 one) takes the fast path below and allocates nothing beyond
        // the payload copy made during parse.

        // DNS interception: fake-IP responses for queries targeting our own
        // resolver (the tunnel peer address). Queries to any other resolver
        // fall through and are proxied to the real server.
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

        // QUIC handling (Blocked mode): drop every UDP/443 datagram here,
        // before routing, with an ICMP port-unreachable so HTTP/3 clients fail
        // fast on the first datagram and fall back to HTTP/2. Automatic defers
        // to the post-resolution check below (it needs the routing decision);
        // Unblocked never drops. A QUIC-based proxy's own transport leaves the
        // extension on a kernel-excluded socket, so it never reaches here.
        if datagram.dstPort == 443 && cfg.quicPolicy.blocksAllQUIC {
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

        // Fast path: deliver to an existing flow. The byte-keyed lookup needs no
        // address string or `Data`, so a long-lived flow (e.g. a game on a
        // non-443 UDP port) costs only the parse-time payload copy per packet.
        // The flow already holds the resolved domain from when it was created,
        // so it survives fake-IP pool eviction by newer DNS allocations.
        let flowKey = UDPFlowKey(srcIP: datagram.srcIP, srcPort: datagram.srcPort,
                                 dstIP: datagram.dstIP, dstPort: datagram.dstPort, isIPv6: isIPv6)
        if let flow = udpFlows[flowKey] {
            flow.handleReceivedData(payload, payloadLength: payload.count)
            return
        }

        // New flow — now the string / Data forms are worth materialising.
        guard let defaultConfiguration = cfg.configuration else { return }
        let dstIPString = TunnelStack.ipAddrToString(datagram.dstIP, isIPv6: isIPv6)
        let srcHost = TunnelStack.ipAddrToString(datagram.srcIP, isIPv6: isIPv6)
        let srcIPData = datagram.srcIPData
        let dstIPData = datagram.dstIPData

        var dstHost = dstIPString
        var flowConfiguration = defaultConfiguration
        var forceBypass = false
        var dstIsDomain = false

        var requestAction: TunnelRequestAction = .default
        var requestConfigName: String? = defaultConfiguration.name

        switch resolveFakeIP(dstIPString, dstPort: datagram.dstPort, proto: "UDP") {
        case .passthrough:
            // Real IP — check IP CIDR rules
            if let action = domainRouter.matchIP(dstIPString) {
                switch action {
                case .direct:
                    forceBypass = true
                    requestAction = .direct
                    requestConfigName = nil
                case .reject:
                    requestLog.record(proto: "UDP", host: dstIPString, port: datagram.dstPort, action: .reject)
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
                case .proxy(_):
                    requestAction = .proxy
                    if let configuration = domainRouter.resolveConfiguration(action: action) {
                        flowConfiguration = configuration
                        requestConfigName = configuration.name
                    } else {
                        logger.warning("[UDP] Routing config not found for \(dstIPString)")
                        requestConfigName = nil
                    }
                }
            }
        case .resolved(let domain, let configurationOverride, let bypass):
            dstHost = domain
            dstIsDomain = true
            if let configuration = configurationOverride {
                flowConfiguration = configuration
                requestAction = .proxy
                requestConfigName = configuration.name
            } else if bypass {
                requestAction = .direct
                requestConfigName = nil
            }
            forceBypass = bypass
        case .drop(let domain):
            requestLog.record(proto: "UDP", host: domain, port: datagram.dstPort, action: .reject)
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

        // QUIC handling (Automatic mode): now that routing is resolved, drop
        // UDP/443 that would traverse a proxy, or whose domain is MITM-listed,
        // so it falls back to TCP — where a proxy relays it reliably and the
        // MITM path can intercept. Direct, non-MITM QUIC is left to flow.
        //
        // `mitmListed` is an autoclosure: the MITM trie is consulted only when
        // it can change the answer — Automatic mode with a direct flow (proxied
        // flows are already dropped) carrying a real resolved domain. Blocked
        // decided before routing; Unblocked never drops; neither touches the
        // trie here. When we do drop a bypassed flow it can only be MITM.
        if datagram.dstPort == 443,
           cfg.quicPolicy.blocksResolvedQUIC(
               isProxied: !forceBypass,
               mitmListed: dstIsDomain && cfg.mitmEnabled && mitmPolicy.matches(dstHost)
           ) {
            logger.debug("[UDP] QUIC blocked (automatic): \(dstHost):443 reason=\(forceBypass ? "mitm" : "proxied")")
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
            action: requestAction,
            configurationName: requestConfigName
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
            forceBypass: forceBypass,
            flowQueue: udpQueue
        )
        evictUDPFlowsToAdmit()
        udpFlows[flowKey] = flow
        flow.handleReceivedData(payload, payloadLength: payload.count)
    }

    // MARK: - Outbound UDP

    /// Builds a UDP packet in Swift and queues it to the TUN output, replacing
    /// the former lwIP `udp_sendto` path. `srcIP`/`dstIP` are the response
    /// packet's own source/destination (callers pass the original 5-tuple
    /// swapped). Callable from any queue — the build is pure and the enqueue is
    /// lock-guarded.
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
        // Tally downlink bytes here: the former lwIP udp_sendto path was counted
        // in the netif output callback, but enqueueOutbound bypasses it. (ICMP
        // unreachables call enqueueOutbound directly and stay uncounted, as they
        // were before.) ``addBytesIn`` is lock-guarded, so this is safe from
        // udpQueue concurrently with the TCP netif tally on lwipQueue.
        addBytesIn(Int64(packet.count))
        enqueueOutbound(packet, isIPv6: isIPv6)
    }
}
