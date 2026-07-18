//
//  TunnelStack+Callbacks.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TunnelStack+Callbacks")

/// Per-host SYN-reject flood tracker. Not `Sendable`: it is owned by ``TunnelStack`` as isolated
/// state and touched only by the isolated SYN-filter callback (on the lwIP queue).
final class RejectFloodTracker {
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

extension TunnelStack: LWIPBridgeHost {

    /// lwIP has an IP packet to write back to the TUN. Batches it onto ``outputBuffer`` and
    /// kicks a drain if idle; the release stays index-aligned and fires on ``lwipQueue``.
    func lwipDidOutput(_ packet: Data, isIPv6: Bool,
                       releaseCtx: UnsafeMutableRawPointer?,
                       release: @escaping @convention(c) (UnsafeMutableRawPointer?) -> Void) {
        let proto: NSNumber = isIPv6 ? Self.ipv6Proto : Self.ipv4Proto
        let pending = PendingRelease(ctx: releaseCtx, fn: release)
        let needsKick: Bool = outputBuffer.withLock { buffer in
            buffer.packets.append(packet)
            buffer.protocols.append(proto)
            buffer.releases.append(pending)
            if buffer.drainInFlight { return false }
            buffer.drainInFlight = true
            return true
        }
        if needsKick {
            kickOutputDrain()
        }
    }

    /// Verdict for an incoming SYN: reject `.reject` destinations at SYN time — never
    /// completing the 3WHS gives the client a clean ECONNREFUSED. SNI-based rejects (no
    /// ClientHello yet) still land in ``TCPConnection``.
    func lwipSynVerdict(dstIP: UnsafeRawPointer, dstPort: UInt16, isIPv6: Bool) -> Int32 {
        let dstIPString = TunnelStack.ipAddrToString(dstIP, isIPv6: isIPv6)

        // DROP if the host is flooding, RESET otherwise.
        func reject(host: String, reason: String, ruleSetName: String?) -> Int32 {
            requestLog.record(protocol: .tcp, host: host, port: dstPort, routeTarget: .reject, ruleSetName: ruleSetName)
            if rejectFloodTracker.shouldDrop(host: host) {
                logger.debug("[TCP] SYN dropped (flood) by \(reason): \(host):\(dstPort)")
                return Int32(LWIP_BRIDGE_SYN_DROP)
            }
            logger.debug("[TCP] SYN rejected by \(reason): \(host):\(dstPort)")
            return Int32(LWIP_BRIDGE_SYN_RESET)
        }

        let decision = connectionRouter.decision(forIP: dstIPString, port: dstPort, proto: "TCP")
        switch decision.action {
        case .reject(let ruleSetName):
            let reason = decision.hostIsResolvedDomain ? "fake-IP domain rule" : "IP rule"
            return reject(host: decision.host, reason: reason, ruleSetName: ruleSetName)
        case .unreachable:
            // Stale fake-IP pool entry — drop silently rather than RST.
            logger.debug("[TCP] SYN dropped (stale fake-IP): \(dstIPString):\(dstPort)")
            return Int32(LWIP_BRIDGE_SYN_DROP)
        case .route, .routeViaDefault:
            // Raw-IP destinations admit against the lower watermark.
            return admitSYN(rawIP: !decision.hostIsResolvedDomain)
        }
    }

    /// Builds the ``TCPConnection`` for a just-accepted pcb, or `nil` to abort it (RST).
    /// `.reject` was already handled by the SYN filter.
    func lwipAccept(pcb: UnsafeMutableRawPointer, dstIP: UnsafeRawPointer,
                    dstPort: UInt16, isIPv6: Bool) -> TCPConnection? {
        guard let defaultConfiguration = configuration else {
            logger.debug("[TunnelStack] tcp_accept: guard failed")
            return nil
        }

        let activeTCP = lwipBridge.activeTCPCount()
        if activeTCP > TunnelLimits.tcpMaxConnections {
            if !tcpConnectionCapWarned {
                tcpConnectionCapWarned = true
                logger.warning("[TCP] Connection table at capacity (\(TunnelLimits.tcpMaxConnections)); refusing new connections to bound memory")
            }
            return nil  // bridge aborts newpcb (tcp_abort)
        } else if tcpConnectionCapWarned && activeTCP < TunnelLimits.tcpMaxConnections * 3 / 4 {
            tcpConnectionCapWarned = false
        }

        let dstIPString = TunnelStack.ipAddrToString(dstIP, isIPv6: isIPv6)
        let decision = connectionRouter.decision(forIP: dstIPString, port: dstPort, proto: "TCP")

        var connectionConfiguration = defaultConfiguration
        // Committed routing identity; drives the dial path and accounting.
        var routeTarget = defaultRouteTarget
        // Rule set behind the committed route; nil while on the default.
        var ruleSetName: String? = nil

        switch decision.action {
        case .route(let target, let configuration, let matchedRuleSet):
            routeTarget = target
            ruleSetName = matchedRuleSet
            if let configuration {
                connectionConfiguration = configuration
            }
        case .routeViaDefault:
            break
        case .reject, .unreachable:
            // Both were handled by the SYN filter; defensive return.
            return nil
        }

        // `decision.host` is the dial destination; plaintext MITM trusts a
        // DNS-resolved (fake-IP) host over the spoofable `Host` header.
        let dstHost = decision.host

        requestLog.record(
            protocol: .tcp,
            host: dstHost,
            port: dstPort,
            routeTarget: routeTarget,
            viaDefault: decision.viaDefault,
            ruleSetName: ruleSetName
        )

        // Sniff TLS ClientHello only on real-IP connections — fake-IP ones
        // already know the domain, and an SNI disagreeing with the
        // DNS-resolved name could miscategorize. MITM is the exception: it
        // needs the buffered ClientHello, so force sniffing even for a
        // known fake-IP domain.
        var sniffSNI = !decision.hostIsResolvedDomain
        if mitmEnabled && mitmPolicy.matches(dstHost) {
            sniffSNI = true
        }

        return TCPConnection(
            stack: self,
            pcb: pcb,
            dstHost: dstHost,
            dstPort: dstPort,
            configuration: connectionConfiguration,
            routeTarget: routeTarget,
            viaDefault: decision.viaDefault,
            ruleSetName: ruleSetName,
            sniffSNI: sniffSNI,
            hostIsResolvedDomain: decision.hostIsResolvedDomain,
            bridge: lwipBridge
        )
    }

    // MARK: - Flow Admission

    /// Admits a TCP SYN against the kernel flow budget. Over budget the SYN
    /// is dropped, not RST — the client backs off on kernel SYN
    /// retransmission, where an RST invites an instant retry.
    /// Raw-IP destinations are swarm-shaped (P2P/PCDN peers) and yield at the
    /// lower pressure watermark so they can't starve domain-routed traffic.
    /// Runs on ``lwipQueue``.
    func admitSYN(rawIP: Bool) -> Int32 {
        let load = FlowGauge.admissionLoad
        let watermark = rawIP ? TunnelLimits.flowPressureWatermark : TunnelLimits.flowBudget
        if load < watermark {
            // Clear the shed latch only once even raw-IP SYNs are admitted
            // again, so alternating domain/raw-IP SYNs can't flap it.
            if flowShedWarned, load < TunnelLimits.flowPressureWatermark {
                flowShedWarned = false
                logger.info("[TCP] flow budget recovered; admitting SYNs [\(DialDiagnostics.snapshot(bridge: lwipBridge))]")
            }
            return Int32(LWIP_BRIDGE_SYN_PASS)
        }
        if !flowShedWarned {
            flowShedWarned = true
            logger.warning("[TCP] dropping new SYNs: flow budget exhausted [\(DialDiagnostics.snapshot(bridge: lwipBridge))]")
        }
        return Int32(LWIP_BRIDGE_SYN_DROP)
    }

}
