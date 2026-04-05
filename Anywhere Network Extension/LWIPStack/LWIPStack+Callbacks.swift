//
//  LWIPStack+Callbacks.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
//

import Foundation

private let logger = TunnelLogger(category: "LWIPStack")

extension LWIPStack {

    // MARK: - Callback Registration

    /// Registers C callbacks that route lwIP events through ``shared``.
    func registerCallbacks() {
        // Output: lwIP → tunnel packet flow (batched)
        // Accumulates output packets during synchronous lwip_bridge_input processing,
        // then flushes them all in a single writePackets call. This reduces kernel
        // crossings from N per batch to 1, speeding up ACK delivery to the OS TCP
        // stack and improving upload throughput.
        lwip_bridge_set_output_fn { data, len, isIPv6 in
            guard let shared = LWIPStack.shared, let data else { return }
            let byteCount = Int(len)
            shared.totalBytesIn += Int64(byteCount)
            shared.outputPackets.append(Data(bytes: data, count: byteCount))
            shared.outputProtocols.append(isIPv6 != 0 ? LWIPStack.ipv6Proto : LWIPStack.ipv4Proto)
            if !shared.outputFlushScheduled {
                shared.outputFlushScheduled = true
                shared.lwipQueue.async {
                    shared.flushOutputPackets()
                }
            }
        }

        // TCP accept: create a new LWIPTCPConnection for each incoming connection
        lwip_bridge_set_tcp_accept_fn { srcIP, srcPort, dstIP, dstPort, isIPv6, pcb in
            guard let shared = LWIPStack.shared,
                  let pcb, let dstIP,
                  let defaultConfiguration = shared.configuration else {
                logger.debug("[LWIPStack] tcp_accept: guard failed")
                return nil
            }

            let dstIPString = LWIPStack.ipAddrToString(dstIP, isIPv6: isIPv6 != 0)

            var dstHost = dstIPString
            var connectionConfiguration = defaultConfiguration
            var forceBypass = false

            switch shared.resolveFakeIP(dstIPString, dstPort: dstPort, proto: "TCP") {
            case .passthrough:
                // Real IP — check IP CIDR rules, then GeoIP bypass
                let match = shared.domainRouter.matchIP(dstIPString)
                if let action = match.userAction {
                    switch action {
                    case .direct:
                        forceBypass = true
                    case .reject:
                        return nil
                    case .proxy(_):
                        if var configuration = shared.domainRouter.resolveConfiguration(action: action) {
                            if let chain = defaultConfiguration.chain, !chain.isEmpty, configuration.chain == nil {
                                configuration = configuration.withChain(chain)
                            }
                            connectionConfiguration = configuration
                        } else {
                            logger.warning("[TCP] Routing config not found for \(dstIPString)")
                        }
                    }
                } else if shared.proxyMode != .global, !shared.bypassCountryCode.isEmpty, match.isBypass {
                    forceBypass = true
                }
            case .resolved(let domain, let configurationOverride, let bypass):
                dstHost = domain
                if var configuration = configurationOverride {
                    if let chain = defaultConfiguration.chain, !chain.isEmpty, configuration.chain == nil {
                        configuration = configuration.withChain(chain)
                    }
                    connectionConfiguration = configuration
                }
                forceBypass = bypass
            case .drop, .unreachable:
                return nil
            }

            let connection = LWIPTCPConnection(
                pcb: pcb,
                dstHost: dstHost,
                dstPort: dstPort,
                configuration: connectionConfiguration,
                forceBypass: forceBypass,
                lwipQueue: shared.lwipQueue
            )
            return Unmanaged.passRetained(connection).toOpaque()
        }

        // TCP recv: deliver data to the connection
        lwip_bridge_set_tcp_recv_fn { connection, data, len in
            guard let connection else {
                logger.debug("[LWIPStack] tcp_recv: connection is nil")
                return
            }
            let tcpConnection = Unmanaged<LWIPTCPConnection>.fromOpaque(connection).takeUnretainedValue()
            if let data, len > 0 {
                tcpConnection.handleReceivedData(Data(bytes: data, count: Int(len)))
            } else {
                tcpConnection.handleRemoteClose()
            }
        }

        // TCP sent: notify the connection of acknowledged bytes
        lwip_bridge_set_tcp_sent_fn { connection, len in
            guard let connection else { return }
            let tcpConnection = Unmanaged<LWIPTCPConnection>.fromOpaque(connection).takeUnretainedValue()
            tcpConnection.handleSent(len: len)
        }

        // TCP error: PCB is already freed by lwIP — release our reference
        lwip_bridge_set_tcp_err_fn { connection, err in
            guard let connection else {
                logger.debug("[LWIPStack] tcp_err: connection is nil, err=\(err)")
                return
            }
            let tcpConnection = Unmanaged<LWIPTCPConnection>.fromOpaque(connection).takeRetainedValue()
            tcpConnection.handleError(err: err)
        }

        // UDP recv: route datagrams to per-flow handlers
        lwip_bridge_set_udp_recv_fn { srcIP, srcPort, dstIP, dstPort, isIPv6, data, len in
            guard let shared = LWIPStack.shared,
                  let srcIP, let dstIP, let data else { return }

            let payload = Data(bytes: data, count: Int(len))

            // DNS interception: intercept port-53 A/AAAA queries with fake-IP responses
            if dstPort == 53 {
                if shared.handleDNSQuery(
                    payload: payload,
                    srcIP: srcIP,
                    srcPort: srcPort,
                    dstIP: dstIP,
                    dstPort: dstPort,
                    isIPv6: isIPv6 != 0
                ) {
                    return  // Fake response sent, no flow needed
                }
                // Non-A/AAAA query — fall through, create normal UDP flow to proxy DNS
            }

            let srcHost = LWIPStack.ipAddrToString(srcIP, isIPv6: isIPv6 != 0)
            let dstIPString = LWIPStack.ipAddrToString(dstIP, isIPv6: isIPv6 != 0)

            // Fast path: deliver to an existing flow without re-resolving the fake IP.
            // The flow already has the resolved domain from when it was created.
            // This avoids dropping packets for long-lived flows (e.g. QUIC) whose
            // fake-IP pool entries may have been evicted by newer DNS allocations.
            let flowKey = UDPFlowKey(srcHost: srcHost, srcPort: srcPort, dstHost: dstIPString, dstPort: dstPort)
            if let flow = shared.udpFlows[flowKey] {
                flow.handleReceivedData(payload, payloadLength: Int(len))
                return
            }

            // New flow — resolve fake IP to domain and determine routing
            var dstHost = dstIPString
            guard let defaultConfiguration = shared.configuration else { return }
            var flowConfiguration = defaultConfiguration
            var forceBypass = false

            switch shared.resolveFakeIP(dstIPString, dstPort: dstPort, proto: "UDP") {
            case .passthrough:
                // Real IP — check IP CIDR rules, then GeoIP bypass
                let match = shared.domainRouter.matchIP(dstIPString)
                if let action = match.userAction {
                    switch action {
                    case .direct:
                        forceBypass = true
                    case .reject:
                        shared.sendICMPPortUnreachable(
                            srcIP: srcIP,
                            srcPort: srcPort,
                            dstIP: dstIP,
                            dstPort: dstPort,
                            isIPv6: isIPv6 != 0,
                            udpPayloadLength: Int(len)
                        )
                        return
                    case .proxy(_):
                        if var configuration = shared.domainRouter.resolveConfiguration(action: action) {
                            if let chain = defaultConfiguration.chain, !chain.isEmpty, configuration.chain == nil {
                                configuration = configuration.withChain(chain)
                            }
                            flowConfiguration = configuration
                        } else {
                            logger.warning("[UDP] Routing config not found for \(dstIPString)")
                        }
                    }
                } else if shared.proxyMode != .global, !shared.bypassCountryCode.isEmpty, match.isBypass {
                    forceBypass = true
                }
            case .resolved(let domain, let configurationOverride, let bypass):
                dstHost = domain
                if var configuration = configurationOverride {
                    if let chain = defaultConfiguration.chain, !chain.isEmpty, configuration.chain == nil {
                        configuration = configuration.withChain(chain)
                    }
                    flowConfiguration = configuration
                }
                forceBypass = bypass
            case .drop, .unreachable:
                shared.sendICMPPortUnreachable(
                    srcIP: srcIP,
                    srcPort: srcPort,
                    dstIP: dstIP,
                    dstPort: dstPort,
                    isIPv6: isIPv6 != 0,
                    udpPayloadLength: Int(len)
                )
                return
            }

            let addrSize = isIPv6 != 0 ? 16 : 4
            let srcIPData = Data(bytes: srcIP, count: addrSize)
            let dstIPData = Data(bytes: dstIP, count: addrSize)

            let flow = LWIPUDPFlow(
                flowKey: flowKey,
                srcHost: srcHost,
                srcPort: srcPort,
                dstHost: dstHost,
                dstPort: dstPort,
                srcIPData: srcIPData,
                dstIPData: dstIPData,
                isIPv6: isIPv6 != 0,
                configuration: flowConfiguration,
                forceBypass: forceBypass,
                lwipQueue: shared.lwipQueue
            )
            shared.udpFlows[flowKey] = flow
            flow.handleReceivedData(payload, payloadLength: Int(len))
        }
    }

    // MARK: - Fake-IP Resolution

    /// Result of resolving a fake IP to its domain and routing configuration.
    private enum FakeIPResolution {
        /// IP is not a fake IP — use original IP as host, default config, no bypass.
        case passthrough
        /// Resolved to a domain with optional config override and bypass flag.
        case resolved(domain: String, configurationOverride: ProxyConfiguration?, forceBypass: Bool)
        /// Connection should be dropped (rejected by rule).
        case drop
        /// Fake IP not in pool (stale from previous session) — drop and signal unreachable.
        case unreachable
    }

    /// Resolves a destination IP through the fake-IP pool and domain router.
    /// Shared by TCP accept and UDP recv callbacks.
    private func resolveFakeIP(_ ip: String, dstPort: UInt16, proto: String) -> FakeIPResolution {
        guard FakeIPPool.isFakeIP(ip) else { return .passthrough }

        guard let entry = fakeIPPool.lookup(ip: ip) else {
            return .unreachable
        }

        let match = domainRouter.matchDomain(entry.domain)

        if let action = match.userAction {
            switch action {
            case .direct:
                return .resolved(domain: entry.domain, configurationOverride: nil, forceBypass: true)
            case .reject:
                return .drop
            case .proxy(_):
                let configuration = domainRouter.resolveConfiguration(action: action)
                if configuration == nil {
                    logger.warning("[\(proto)] Routing config not found for \(entry.domain)")
                }
                return .resolved(domain: entry.domain, configurationOverride: configuration, forceBypass: false)
            }
        }

        // Country bypass: domain matched the bypass country's rule set.
        if proxyMode != .global, !bypassCountryCode.isEmpty, match.isBypass {
            return .resolved(domain: entry.domain, configurationOverride: nil, forceBypass: true)
        }

        return .resolved(domain: entry.domain, configurationOverride: nil, forceBypass: false)
    }
}
