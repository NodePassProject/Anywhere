//
//  TunnelStack+Callbacks.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "TunnelStack+Callbacks")

private final class RejectFloodTracker {
    private let threshold: Int
    private let window: CFAbsoluteTime
    private var timestamps: [String: [CFAbsoluteTime]] = [:]
    private var lastSweep: CFAbsoluteTime = 0

    init(threshold: Int = 50, window: CFAbsoluteTime = 30) {
        self.threshold = threshold
        self.window = window
    }

    /// Records a reject for `host` and returns `true` if the host has
    /// crossed the flood threshold within the window.
    func shouldDrop(host: String) -> Bool {
        let now = CFAbsoluteTimeGetCurrent()
        let cutoff = now - window
        // Reap stale hosts at most once per window so the key set stays bounded.
        if now - lastSweep > window {
            timestamps = timestamps.filter { _, ts in ts.contains { $0 >= cutoff } }
            lastSweep = now
        }
        var times = timestamps[host, default: []]
        times.removeAll { $0 < cutoff }
        times.append(now)
        timestamps[host] = times
        return times.count > threshold
    }
}

private let rejectFloodTracker = RejectFloodTracker()

extension TunnelStack {

    // MARK: - Callback Registration

    /// Registers C callbacks that route lwIP events through ``shared``.
    func registerCallbacks() {
        // Output: lwIP → tunnel packet flow, batched. `Data(bytesNoCopy:)` with
        // a `.none` deallocator lets writePackets read lwIP's memory directly;
        // ``pendingReleases`` is the actual owner, and releases must stay on
        // lwipQueue (pbuf_free/mem_free mutate freelists with no locking under
        // NO_SYS=1).
        lwip_bridge_set_output_fn { data, len, isIPv6, releaseCtx, release in
            guard let shared = TunnelStack.shared, let data, let release else { return }
            let byteCount = Int(len)
            let mutableData = UnsafeMutableRawPointer(mutating: data)
            let packet = Data(bytesNoCopy: mutableData, count: byteCount, deallocator: .none)
            let proto: NSNumber = isIPv6 != 0 ? TunnelStack.ipv6Proto : TunnelStack.ipv4Proto
            let pending = TunnelStack.PendingRelease(ctx: releaseCtx, fn: release)
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

        // TCP SYN filter: reject `.reject` destinations at SYN time — never
        // completes the 3WHS, giving the client a clean ECONNREFUSED. SNI-based
        // rejects (no ClientHello yet) still land in `TCPConnection`.
        lwip_bridge_set_tcp_syn_filter_fn { _, _, dstIP, dstPort, isIPv6 in
            guard let shared = TunnelStack.shared, let dstIP else {
                return Int32(LWIP_BRIDGE_SYN_PASS)
            }
            let dstIPString = TunnelStack.ipAddrToString(dstIP, isIPv6: isIPv6 != 0)

            // DROP if the host is flooding, RESET otherwise.
            func reject(host: String, reason: String) -> Int32 {
                shared.requestLog.record(protocolName: "TCP", host: host, port: dstPort, routeTarget: .reject)
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

        // TCP accept: create a TCPConnection per incoming connection. `.reject`
        // was already handled by the SYN filter.
        lwip_bridge_set_tcp_accept_fn { srcIP, srcPort, dstIP, dstPort, isIPv6, pcb in
            guard let shared = TunnelStack.shared,
                  let pcb, let dstIP,
                  let defaultConfiguration = shared.configuration else {
                logger.debug("[TunnelStack] tcp_accept: guard failed")
                return nil
            }

            let dstIPString = TunnelStack.ipAddrToString(dstIP, isIPv6: isIPv6 != 0)

            var dstHost = dstIPString
            // Plaintext MITM trusts a DNS-resolved (fake-IP) host over the spoofable `Host` header.
            var hostIsResolvedDomain = false
            var connectionConfiguration = defaultConfiguration
            // Committed routing identity; drives the dial path and accounting.
            var routeTarget = shared.defaultRouteTarget
            // Sniff TLS ClientHello only on real-IP connections — fake-IP ones
            // already know the domain, and an SNI disagreeing with the
            // DNS-resolved name could miscategorize.
            var sniffSNI = false

            // True until a routing rule matches — i.e. the default outbound is used.
            var viaDefault = true

            switch shared.resolveFakeIP(dstIPString, dstPort: dstPort, proto: "TCP") {
            case .passthrough:
                if let action = shared.domainRouter.matchIP(dstIPString) {
                    viaDefault = false
                    switch action {
                    case .direct:
                        routeTarget = .direct
                    case .reject:
                        // Should be unreachable — handled by the SYN filter.
                        return nil
                    case .proxy(let id):
                        routeTarget = .proxy(id)
                        if let configuration = shared.domainRouter.resolveConfiguration(action: action) {
                            connectionConfiguration = configuration
                        } else {
                            logger.warning("[TCP] Routing config not found for \(dstIPString)")
                        }
                    }
                }
                sniffSNI = true
            case .resolved(let domain, let target, let configuration):
                dstHost = domain
                hostIsResolvedDomain = true
                // `target == nil` → no domain rule matched; keep the default route.
                switch target {
                case .direct:
                    routeTarget = .direct
                    viaDefault = false
                case .proxy(let id):
                    routeTarget = .proxy(id)
                    viaDefault = false
                    if let configuration {
                        connectionConfiguration = configuration
                    }
                case .reject:
                    // `.reject` surfaces as `.drop`, handled below.
                    return nil
                case .none:
                    break
                }
            case .drop, .unreachable:
                // Both were handled by the SYN filter; defensive return.
                return nil
            }

            shared.requestLog.record(
                protocolName: "TCP",
                host: dstHost,
                port: dstPort,
                routeTarget: routeTarget,
                viaDefault: viaDefault
            )

            // MITM needs the buffered ClientHello, so force sniffing even for a known fake-IP domain.
            if shared.mitmEnabled && shared.mitmPolicy.matches(dstHost) {
                sniffSNI = true
            }

            let connection = TCPConnection(
                pcb: pcb,
                dstHost: dstHost,
                dstPort: dstPort,
                configuration: connectionConfiguration,
                routeTarget: routeTarget,
                viaDefault: viaDefault,
                sniffSNI: sniffSNI,
                hostIsResolvedDomain: hostIsResolvedDomain,
                lwipQueue: shared.lwipQueue
            )
            return Unmanaged.passRetained(connection).toOpaque()
        }

        lwip_bridge_set_tcp_recv_fn { connection, data, len in
            guard let connection else {
                logger.debug("[TunnelStack] tcp_recv: connection is nil")
                return
            }
            let tcpConnection = Unmanaged<TCPConnection>.fromOpaque(connection).takeUnretainedValue()
            if let data, len > 0 {
                tcpConnection.handleReceivedData(bytes: data, count: Int(len))
            } else {
                tcpConnection.handleRemoteClose()
            }
        }

        lwip_bridge_set_tcp_sent_fn { connection, len in
            guard let connection else { return }
            let tcpConnection = Unmanaged<TCPConnection>.fromOpaque(connection).takeUnretainedValue()
            tcpConnection.handleSent(len: len)
        }

        // PCB already freed by lwIP — release our reference (takeRetainedValue).
        lwip_bridge_set_tcp_err_fn { connection, err in
            guard let connection else {
                logger.debug("[TunnelStack] tcp_err: connection is nil, err=\(err)")
                return
            }
            let tcpConnection = Unmanaged<TCPConnection>.fromOpaque(connection).takeRetainedValue()
            tcpConnection.handleError(err: err)
        }
    }

    // MARK: - Fake-IP Resolution

    enum FakeIPResolution {
        /// IP is not a fake IP — use original IP as host and the default route.
        case passthrough
        /// Resolved to a domain. `target` is the matched route, or `nil` when no
        /// domain rule matched (caller uses the default). `configuration` is the
        /// dialing config for a `.proxy` target.
        case resolved(domain: String, target: RouteTarget?, configuration: ProxyConfiguration?)
        /// Rejected by rule; carries the resolved domain for the request log.
        case drop(domain: String)
        /// Fake IP not in pool (stale from previous session) — drop and signal unreachable.
        case unreachable
    }

    /// Resolves a destination IP through the fake-IP pool and domain router.
    func resolveFakeIP(_ ip: String, dstPort: UInt16, proto: String) -> FakeIPResolution {
        guard FakeIPPool.isFakeIP(ip) else { return .passthrough }

        guard let entry = fakeIPPool.lookup(ip: ip) else {
            logger.warning("[\(proto)] Fake IP not in pool (stale): \(ip):\(dstPort)")
            return .unreachable
        }

        if let action = domainRouter.matchDomain(entry.domain) {
            switch action {
            case .direct:
                return .resolved(domain: entry.domain, target: .direct, configuration: nil)
            case .reject:
                logger.debug("[\(proto)] Domain rejected by routing rule: \(entry.domain) (\(ip):\(dstPort))")
                return .drop(domain: entry.domain)
            case .proxy(let id):
                let configuration = domainRouter.resolveConfiguration(action: action)
                if configuration == nil {
                    logger.warning("[\(proto)] Routing config not found for \(entry.domain)")
                }
                return .resolved(domain: entry.domain, target: .proxy(id), configuration: configuration)
            }
        }

        return .resolved(domain: entry.domain, target: nil, configuration: nil)
    }
}
