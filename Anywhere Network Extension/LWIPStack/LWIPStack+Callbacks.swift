//
//  LWIPStack+Callbacks.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

private let logger = AnywhereLogger(category: "LWIPStack")

/// Tracks recent rejects per destination so a misbehaving app that
/// retries a blocked host in a tight loop downgrades from RST-on-SYN
/// to silent drop. RST every SYN burns CPU and packets on both sides
/// for no benefit; a timeout drives the app's retry back-off faster.
/// Mirrors sing-box's `RuleActionReject` flood guard (50 rejects in
/// 30 s → drop). Accessed from the SYN filter callback which runs on
/// `lwipQueue`, so no internal locking is needed.
private final class RejectFloodTracker {
    private let threshold: Int
    private let window: CFAbsoluteTime
    private var timestamps: [String: [CFAbsoluteTime]] = [:]

    init(threshold: Int = 50, window: CFAbsoluteTime = 30) {
        self.threshold = threshold
        self.window = window
    }

    /// Records a reject for `host` and returns `true` if the host has
    /// crossed the flood threshold within the window.
    func shouldDrop(host: String) -> Bool {
        let now = CFAbsoluteTimeGetCurrent()
        let cutoff = now - window
        var times = timestamps[host, default: []]
        times.removeAll { $0 < cutoff }
        times.append(now)
        timestamps[host] = times
        return times.count > threshold
    }
}

private let rejectFloodTracker = RejectFloodTracker()

extension LWIPStack {

    // MARK: - Callback Registration

    /// Registers C callbacks that route lwIP events through ``shared``.
    func registerCallbacks() {
        // Output: lwIP → tunnel packet flow (batched)
        // Accumulates output packets during synchronous lwip_bridge_input processing,
        // then flushes them all in a single writePackets call. This reduces kernel
        // crossings from N per batch to 1, speeding up ACK delivery to the OS TCP
        // stack and improving upload throughput.
        //
        // The bridge hands us either a pbuf payload (zero-copy single-pbuf path,
        // released via pbuf_free) or a heap buffer holding the flattened chain
        // (released via mem_free). We wrap the pointer with `Data(bytesNoCopy:...)`
        // so writePackets reads directly from lwIP's memory — saving one
        // payload-sized memcpy per packet vs. the previous `Data(bytes:count:)`.
        //
        // The `Data` deallocator is `.none`; ``pendingReleases`` (appended
        // under the same lock) is the actual owner of the pbuf/heap buffer
        // and is fired in a single ``lwipQueue.async`` per drain iteration.
        // Releases must stay on lwipQueue because `pbuf_free` / `mem_free`
        // mutate per-pool freelists with no locking under NO_SYS=1.
        lwip_bridge_set_output_fn { data, len, isIPv6, releaseCtx, release in
            guard let shared = LWIPStack.shared, let data, let release else { return }
            let byteCount = Int(len)
            shared.totalBytesIn += Int64(byteCount)

            let mutableData = UnsafeMutableRawPointer(mutating: data)
            let packet = Data(bytesNoCopy: mutableData, count: byteCount, deallocator: .none)
            let proto: NSNumber = isIPv6 != 0 ? LWIPStack.ipv6Proto : LWIPStack.ipv4Proto
            let pending = LWIPStack.PendingRelease(ctx: releaseCtx, fn: release)
            // Append under the buffer lock and decide whether to start a
            // drain on ``outputQueue``. The drain loop owns the writePackets
            // calls and pulls subsequent batches under the same lock — no
            // round-trip via ``lwipQueue`` between batches, so the drain
            // cadence is no longer gated by lwIP work on ``lwipQueue``.
            let needsKick: Bool = shared.outputBufferLock.withLock {
                shared.outputPackets.append(packet)
                shared.outputProtocols.append(proto)
                shared.pendingReleases.append(pending)
                if shared.outputDrainInFlight { return false }
                shared.outputDrainInFlight = true
                return true
            }
            if needsKick {
                shared.outputQueue.async { shared.drainOutputLoop() }
            }
        }

        // TCP SYN filter: reject `.reject`-classified destinations at SYN
        // time so we never complete the 3WHS for them. Saves the SYN-ACK +
        // final ACK + accept_cb path for every rejected connection and
        // gives the client a clean ECONNREFUSED instead of a closed
        // post-handshake connection. SNI-based rejects are not visible
        // here (no ClientHello yet) and still land in `LWIPTCPConnection`.
        lwip_bridge_set_tcp_syn_filter_fn { _, _, dstIP, dstPort, isIPv6 in
            guard let shared = LWIPStack.shared, let dstIP else {
                return Int32(LWIP_BRIDGE_SYN_PASS)
            }
            let dstIPString = LWIPStack.ipAddrToString(dstIP, isIPv6: isIPv6 != 0)

            // Helper: log + record + return DROP if the host is flooding,
            // RESET otherwise. The tracker keys on the human-readable host
            // (domain for fake-IP rejects, IP literal for IP-CIDR rejects),
            // matching what the user sees in the request log.
            func reject(host: String, reason: String) -> Int32 {
                shared.requestLog.record(proto: "TCP", host: host, port: dstPort, action: .reject)
                if rejectFloodTracker.shouldDrop(host: host) {
                    logger.debug("[TCP] SYN dropped (flood) by \(reason): \(host):\(dstPort)")
                    return Int32(LWIP_BRIDGE_SYN_DROP)
                }
                logger.debug("[TCP] SYN rejected by \(reason): \(host):\(dstPort)")
                return Int32(LWIP_BRIDGE_SYN_RESET)
            }

            switch shared.resolveFakeIP(dstIPString, dstPort: dstPort, proto: "TCP") {
            case .passthrough:
                if case .reject = shared.domainRouter.matchIP(dstIPString) {
                    return reject(host: dstIPString, reason: "IP rule")
                }
                return Int32(LWIP_BRIDGE_SYN_PASS)
            case .resolved:
                return Int32(LWIP_BRIDGE_SYN_PASS)
            case .drop(let domain):
                return reject(host: domain, reason: "fake-IP domain rule")
            case .unreachable:
                // Stale fake-IP pool entry — drop silently rather than RST.
                logger.debug("[TCP] SYN dropped (stale fake-IP): \(dstIPString):\(dstPort)")
                return Int32(LWIP_BRIDGE_SYN_DROP)
            }
        }

        // TCP accept: create a new LWIPTCPConnection for each incoming connection.
        // `.reject` cases were already handled at SYN by the filter above and
        // never reach this callback. SNI-based rejects are decided later.
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
            // Enable TLS ClientHello sniffing only on real-IP connections.
            // Fake-IP connections already know the domain via the fake-IP pool;
            // sniffing would add latency for no benefit (and could miscategorize
            // if the SNI disagrees with the DNS-resolved name).
            var sniffSNI = false

            // Tracks the action/configuration to surface in the request log.
            // Set on each routing branch below; recorded once after the switch.
            var requestAction: TunnelRequestAction = .default
            var requestConfigName: String? = defaultConfiguration.name

            switch shared.resolveFakeIP(dstIPString, dstPort: dstPort, proto: "TCP") {
            case .passthrough:
                // Real IP — check IP CIDR rules. `.reject` was filtered at SYN.
                if let action = shared.domainRouter.matchIP(dstIPString) {
                    switch action {
                    case .direct:
                        forceBypass = true
                        requestAction = .direct
                        requestConfigName = nil
                    case .reject:
                        // Should be unreachable — handled by the SYN filter.
                        return nil
                    case .proxy(_):
                        requestAction = .proxy
                        if let configuration = shared.domainRouter.resolveConfiguration(action: action) {
                            connectionConfiguration = configuration
                            requestConfigName = configuration.name
                        } else {
                            logger.warning("[TCP] Routing config not found for \(dstIPString)")
                            requestConfigName = nil
                        }
                    }
                }
                sniffSNI = true
            case .resolved(let domain, let configurationOverride, let bypass):
                dstHost = domain
                if let configuration = configurationOverride {
                    connectionConfiguration = configuration
                    requestAction = .proxy
                    requestConfigName = configuration.name
                } else if bypass {
                    requestAction = .direct
                    requestConfigName = nil
                }
                forceBypass = bypass
            case .drop, .unreachable:
                // Both were handled by the SYN filter; defensive return.
                return nil
            }

            shared.requestLog.record(
                proto: "TCP",
                host: dstHost,
                port: dstPort,
                action: requestAction,
                configurationName: requestConfigName
            )

            // Fake-IP MITM: domain is known at accept time, but we still
            // need the ClientHello bytes to drive ``TLSServer``. Force
            // sniffing on so the bytes land in ``LWIPTCPConnection.pendingData``;
            // the connection wakes ``mitmEnabled`` once ``applySNI`` runs.
            if shared.mitmEnabled && shared.mitmPolicy.matches(dstHost) {
                sniffSNI = true
            }

            let connection = LWIPTCPConnection(
                pcb: pcb,
                dstHost: dstHost,
                dstPort: dstPort,
                configuration: connectionConfiguration,
                forceBypass: forceBypass,
                sniffSNI: sniffSNI,
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
                tcpConnection.handleReceivedData(bytes: data, count: Int(len))
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

            // DNS interception: fake-IP responses for queries targeting our own
            // resolver (the tunnel peer address). Queries to any other resolver
            // fall through and are proxied to the real server,
            if dstPort == 53 {
                let dstIPString = LWIPStack.ipAddrToString(dstIP, isIPv6: isIPv6 != 0)
                if let destination = LWIPStack.dnsDestination(for: dstIPString) {
                    if shared.handleDNSQuery(
                        payload: payload,
                        srcIP: srcIP,
                        srcPort: srcPort,
                        dstIP: dstIP,
                        dstPort: dstPort,
                        isIPv6: isIPv6 != 0,
                        destination: destination
                    ) {
                        return  // Fake response sent, no flow needed
                    }
                    // `.publicResolver` non-A/AAAA — fall through, proxy MX/SRV/TXT to real server
                }
                // Non-intercepted DNS server — fall through to ordinary UDP flow
            }

            // QUIC blocking: drop UDP/443 with ICMP port-unreachable so HTTP/3
            // clients fail fast on the first datagram and fall back to HTTP/2.
            if shared.blockQUICEnabled && dstPort == 443 {
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

            // MITM HTTP/3 reject: clients that hit a MITM-listed hostname
            // over UDP/443 get the same ICMP unreachable so they fall back
            // to TCP/TLS, where the MITM TCP path can terminate the
            // connection. We can only do this for fake-IP UDP — without a
            // domain we don't know whether the destination is on the list.
            if shared.mitmEnabled && dstPort == 443 {
                let dstIPProbe = LWIPStack.ipAddrToString(dstIP, isIPv6: isIPv6 != 0)
                if FakeIPPool.isFakeIP(dstIPProbe),
                   let entry = shared.fakeIPPool.lookup(ip: dstIPProbe),
                   shared.mitmPolicy.matches(entry.domain) {
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

            var requestAction: TunnelRequestAction = .default
            var requestConfigName: String? = defaultConfiguration.name

            switch shared.resolveFakeIP(dstIPString, dstPort: dstPort, proto: "UDP") {
            case .passthrough:
                // Real IP — check IP CIDR rules
                if let action = shared.domainRouter.matchIP(dstIPString) {
                    switch action {
                    case .direct:
                        forceBypass = true
                        requestAction = .direct
                        requestConfigName = nil
                    case .reject:
                        shared.requestLog.record(proto: "UDP", host: dstIPString, port: dstPort, action: .reject)
                        logger.debug("[UDP] IP rejected by routing rule: \(dstIPString):\(dstPort)")
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
                        requestAction = .proxy
                        if let configuration = shared.domainRouter.resolveConfiguration(action: action) {
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
                shared.requestLog.record(proto: "UDP", host: domain, port: dstPort, action: .reject)
                shared.sendICMPPortUnreachable(
                    srcIP: srcIP,
                    srcPort: srcPort,
                    dstIP: dstIP,
                    dstPort: dstPort,
                    isIPv6: isIPv6 != 0,
                    udpPayloadLength: Int(len)
                )
                return
            case .unreachable:
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

            shared.requestLog.record(
                proto: "UDP",
                host: dstHost,
                port: dstPort,
                action: requestAction,
                configurationName: requestConfigName
            )

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
        /// Connection should be dropped (rejected by rule). Carries the
        /// resolved domain so the request log can record the rejected host.
        case drop(domain: String)
        /// Fake IP not in pool (stale from previous session) — drop and signal unreachable.
        case unreachable
    }

    /// Resolves a destination IP through the fake-IP pool and domain router.
    /// Shared by TCP accept and UDP recv callbacks.
    private func resolveFakeIP(_ ip: String, dstPort: UInt16, proto: String) -> FakeIPResolution {
        guard FakeIPPool.isFakeIP(ip) else { return .passthrough }

        guard let entry = fakeIPPool.lookup(ip: ip) else {
            logger.warning("[\(proto)] Fake IP not in pool (stale): \(ip):\(dstPort)")
            return .unreachable
        }

        if let action = domainRouter.matchDomain(entry.domain) {
            switch action {
            case .direct:
                return .resolved(domain: entry.domain, configurationOverride: nil, forceBypass: true)
            case .reject:
                logger.debug("[\(proto)] Domain rejected by routing rule: \(entry.domain) (\(ip):\(dstPort))")
                return .drop(domain: entry.domain)
            case .proxy(_):
                let configuration = domainRouter.resolveConfiguration(action: action)
                if configuration == nil {
                    logger.warning("[\(proto)] Routing config not found for \(entry.domain)")
                }
                return .resolved(domain: entry.domain, configurationOverride: configuration, forceBypass: false)
            }
        }

        return .resolved(domain: entry.domain, configurationOverride: nil, forceBypass: false)
    }
}
