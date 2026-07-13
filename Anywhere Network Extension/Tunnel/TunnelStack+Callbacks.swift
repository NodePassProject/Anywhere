//
//  TunnelStack+Callbacks.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import Synchronization

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

    /// Fetches the stack behind the bridge's host context. All bridge
    /// callbacks run on ``lwipQueue``, where the context is set/cleared, so
    /// the read is queue-confined.
    private static func stack() -> TunnelStack? {
        guard let ctx = lwip_bridge_host_ctx() else { return nil }
        return Unmanaged<TunnelStack>.fromOpaque(ctx).takeUnretainedValue()
    }

    /// Publishes `self` as the bridge's host context and registers the C
    /// callbacks that route lwIP events back to it. Must be called on
    /// ``lwipQueue`` before `lwip_bridge_init`.
    func registerCallbacks() {
        lwip_bridge_set_host_ctx(Unmanaged.passUnretained(self).toOpaque())

        // Output: lwIP → tunnel packet flow, batched. `Data(bytesNoCopy:)` with
        // a `.none` deallocator lets writePackets read lwIP's memory directly;
        // ``OutputBufferState/releases`` is the actual owner, and releases must
        // stay on lwipQueue (pbuf_free/mem_free mutate freelists with no locking
        // under NO_SYS=1).
        lwip_bridge_set_output_fn { data, len, isIPv6, releaseCtx, release in
            guard let stack = TunnelStack.stack(), let data, let release else { return }
            let byteCount = Int(len)
            let mutableData = UnsafeMutableRawPointer(mutating: data)
            let packet = Data(bytesNoCopy: mutableData, count: byteCount, deallocator: .none)
            let proto: NSNumber = isIPv6 != 0 ? TunnelStack.ipv6Proto : TunnelStack.ipv4Proto
            let pending = TunnelStack.PendingRelease(ctx: releaseCtx, fn: release)
            let needsKick: Bool = stack.outputBuffer.withLock { buffer in
                buffer.packets.append(packet)
                buffer.protocols.append(proto)
                buffer.releases.append(pending)
                if buffer.drainInFlight { return false }
                buffer.drainInFlight = true
                return true
            }
            if needsKick {
                stack.outputQueue.async { stack.drainOutputLoop() }
            }
        }

        // TCP SYN filter: reject `.reject` destinations at SYN time — never
        // completes the 3WHS, giving the client a clean ECONNREFUSED. SNI-based
        // rejects (no ClientHello yet) still land in `TCPConnection`.
        lwip_bridge_set_tcp_syn_filter_fn { _, _, dstIP, dstPort, isIPv6 in
            guard let stack = TunnelStack.stack(), let dstIP else {
                return Int32(LWIP_BRIDGE_SYN_PASS)
            }
            let dstIPString = TunnelStack.ipAddrToString(dstIP, isIPv6: isIPv6 != 0)

            // DROP if the host is flooding, RESET otherwise.
            func reject(host: String, reason: String, ruleSetName: String?) -> Int32 {
                stack.requestLog.record(protocol: .tcp, host: host, port: dstPort, routeTarget: .reject, ruleSetName: ruleSetName)
                if rejectFloodTracker.shouldDrop(host: host) {
                    logger.debug("[TCP] SYN dropped (flood) by \(reason): \(host):\(dstPort)")
                    return Int32(LWIP_BRIDGE_SYN_DROP)
                }
                logger.debug("[TCP] SYN rejected by \(reason): \(host):\(dstPort)")
                return Int32(LWIP_BRIDGE_SYN_RESET)
            }

            let decision = stack.connectionRouter.decision(forIP: dstIPString, port: dstPort, proto: "TCP")
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
                return stack.admitSYN(rawIP: !decision.hostIsResolvedDomain)
            }
        }

        // TCP accept: create a TCPConnection per incoming connection. `.reject`
        // was already handled by the SYN filter.
        lwip_bridge_set_tcp_accept_fn { srcIP, srcPort, dstIP, dstPort, isIPv6, pcb in
            guard let stack = TunnelStack.stack(),
                  let pcb, let dstIP,
                  let defaultConfiguration = stack.configuration else {
                logger.debug("[TunnelStack] tcp_accept: guard failed")
                return nil
            }

            let activeTCP = Int(lwip_bridge_active_tcp_count())
            if activeTCP > TunnelLimits.tcpMaxConnections {
                if !stack.tcpConnectionCapWarned {
                    stack.tcpConnectionCapWarned = true
                    logger.warning("[TCP] Connection table at capacity (\(TunnelLimits.tcpMaxConnections)); refusing new connections to bound memory")
                }
                return nil  // bridge aborts newpcb (tcp_abort)
            } else if stack.tcpConnectionCapWarned && activeTCP < TunnelLimits.tcpMaxConnections * 3 / 4 {
                stack.tcpConnectionCapWarned = false
            }

            let dstIPString = TunnelStack.ipAddrToString(dstIP, isIPv6: isIPv6 != 0)
            let decision = stack.connectionRouter.decision(forIP: dstIPString, port: dstPort, proto: "TCP")

            var connectionConfiguration = defaultConfiguration
            // Committed routing identity; drives the dial path and accounting.
            var routeTarget = stack.defaultRouteTarget
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

            stack.requestLog.record(
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
            if stack.mitmEnabled && stack.mitmPolicy.matches(dstHost) {
                sniffSNI = true
            }

            let connection = TCPConnection(
                stack: stack,
                pcb: pcb,
                dstHost: dstHost,
                dstPort: dstPort,
                configuration: connectionConfiguration,
                routeTarget: routeTarget,
                viaDefault: decision.viaDefault,
                ruleSetName: ruleSetName,
                sniffSNI: sniffSNI,
                hostIsResolvedDomain: decision.hostIsResolvedDomain,
                lwipQueue: stack.lwipQueue
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
                logger.info("[TCP] flow budget recovered; admitting SYNs [\(DialDiagnostics.snapshot())]")
            }
            return Int32(LWIP_BRIDGE_SYN_PASS)
        }
        if !flowShedWarned {
            flowShedWarned = true
            logger.warning("[TCP] dropping new SYNs: flow budget exhausted [\(DialDiagnostics.snapshot())]")
        }
        return Int32(LWIP_BRIDGE_SYN_DROP)
    }

}
