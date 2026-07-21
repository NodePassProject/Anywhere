//
//  TunnelStack+Callbacks.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "TunnelStack+Callbacks")

// MARK: - C-Callback Crossing Types

struct LWIPRawPointer: @unchecked Sendable { let raw: UnsafeRawPointer }

struct LWIPPCBHandle: @unchecked Sendable { let raw: UnsafeMutableRawPointer }

struct LWIPReleaseAction: @unchecked Sendable {
    let ctx: UnsafeMutableRawPointer?
    let fn: @convention(c) (UnsafeMutableRawPointer?) -> Void
    
    static let noop = LWIPReleaseAction(ctx: nil, fn: { _ in })
    
    func run() { fn(ctx) }
}

final class RejectFloodTracker {
    private let threshold: Int
    private let window: CFAbsoluteTime
    private var timestamps: [String: [CFAbsoluteTime]] = [:]
    private var lastSweep: CFAbsoluteTime = 0

    init(threshold: Int = 50, window: CFAbsoluteTime = 30) {
        self.threshold = threshold
        self.window = window
    }
    
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

extension TunnelStack {

    // MARK: - Callback Installation
    
    func installLwipCallbacks() {
        lwip_bridge_set_host_ctx(BridgeContext.passUnretained(self))
        
        lwip_bridge_set_output_fn { data, len, isIPv6, releaseCtx, release in
            guard let stack = TunnelStack.lwipHost(), let data, let release else { return }
            let packet = Data(
                bytesNoCopy: UnsafeMutableRawPointer(mutating: data),
                count: Int(len),
                deallocator: .none
            )
            let releaseAction = LWIPReleaseAction(ctx: releaseCtx, fn: release)
            stack.assumeIsolated {
                $0.lwipDidOutput(packet, isIPv6: isIPv6 != 0, release: releaseAction)
            }
        }
        
        lwip_bridge_set_tcp_syn_filter_fn { _, _, dstIP, dstPort, isIPv6 in
            guard let stack = TunnelStack.lwipHost(), let dstIP else {
                return Int32(LWIP_BRIDGE_SYN_PASS)
            }
            let dstIPBox = LWIPRawPointer(raw: dstIP)
            return stack.assumeIsolated { $0.lwipSynVerdict(dstIP: dstIPBox.raw, dstPort: dstPort, isIPv6: isIPv6 != 0) }
        }
        
        lwip_bridge_set_tcp_accept_fn { _, _, dstIP, dstPort, isIPv6, pcb in
            guard let stack = TunnelStack.lwipHost(), let pcb, let dstIP else { return nil }
            let pcbHandle = LWIPPCBHandle(raw: pcb)
            let dstIPBox = LWIPRawPointer(raw: dstIP)
            guard let connection = stack.assumeIsolated({
                $0.lwipAccept(pcb: pcbHandle.raw, dstIP: dstIPBox.raw, dstPort: dstPort, isIPv6: isIPv6 != 0)
            }) else {
                return nil
            }
            return connection.adopt()
        }
        
        lwip_bridge_set_tcp_recv_fn { connection, data, len in
            guard let connection else {
                logger.debug("[LWIPBridge] tcp_recv: connection is nil")
                return
            }
            let dataBox = data.map { LWIPRawPointer(raw: $0) }
            BridgeContext.unretained(connection, as: TCPConnection.self).assumeIsolated { conn in
                if let dataBox, len > 0 {
                    conn.handleReceivedData(bytes: dataBox.raw, count: Int(len))
                } else {
                    conn.handleRemoteClose()
                }
            }
        }
        
        lwip_bridge_set_tcp_sent_fn { connection, len in
            guard let connection else { return }
            BridgeContext.unretained(connection, as: TCPConnection.self).assumeIsolated { $0.handleSent(len: len) }
        }
        
        lwip_bridge_set_tcp_err_fn { connection, err in
            guard let connection else {
                logger.debug("[LWIPBridge] tcp_err: connection is nil, err=\(err)")
                return
            }
            BridgeContext.consume(connection, as: TCPConnection.self).assumeIsolated { $0.handleError(err: err) }
        }
    }
    
    private static func lwipHost() -> TunnelStack? {
        guard let ctx = lwip_bridge_host_ctx() else { return nil }
        return BridgeContext.unretained(ctx, as: TunnelStack.self)
    }

    // MARK: - Callbacks
    
    func lwipDidOutput(_ packet: Data, isIPv6: Bool, release: LWIPReleaseAction) {
        let proto: NSNumber = isIPv6 ? Self.ipv6Proto : Self.ipv4Proto
        let needsKick: Bool = outputBuffer.withLock { buffer in
            buffer.packets.append(packet)
            buffer.protocols.append(proto)
            buffer.releases.append(release)
            if buffer.drainInFlight { return false }
            buffer.drainInFlight = true
            return true
        }
        if needsKick {
            kickOutputDrain()
        }
    }
    
    func lwipSynVerdict(dstIP: UnsafeRawPointer, dstPort: UInt16, isIPv6: Bool) -> Int32 {
        let dstIPString = TunnelStack.ipAddrToString(dstIP, isIPv6: isIPv6)
        
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
            logger.debug("[TCP] SYN dropped (stale fake-IP): \(dstIPString):\(dstPort)")
            return Int32(LWIP_BRIDGE_SYN_DROP)
        case .route, .routeViaDefault:
            return admitSYN(rawIP: !decision.hostIsResolvedDomain)
        }
    }
    
    func lwipAccept(
        pcb: UnsafeMutableRawPointer,
        dstIP: UnsafeRawPointer,
        dstPort: UInt16,
        isIPv6: Bool
    ) -> TCPConnection? {
        guard let defaultConfiguration = configuration else {
            logger.debug("[TunnelStack] tcp_accept: guard failed")
            return nil
        }
        
        let activeTCP = Int(lwip_bridge_active_tcp_count())
        if activeTCP > TunnelLimits.tcpMaxConnections {
            if !tcpConnectionCapWarned {
                tcpConnectionCapWarned = true
                logger.warning("[TCP] Connection table at capacity (\(TunnelLimits.tcpMaxConnections)); refusing new connections to bound memory")
            }
            return nil
        } else if tcpConnectionCapWarned && activeTCP < TunnelLimits.tcpMaxConnections * 3 / 4 {
            tcpConnectionCapWarned = false
        }

        let dstIPString = TunnelStack.ipAddrToString(dstIP, isIPv6: isIPv6)
        let decision = connectionRouter.decision(forIP: dstIPString, port: dstPort, proto: "TCP")

        var connectionConfiguration = defaultConfiguration
        var routeTarget = defaultRouteTarget
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
            return nil
        }
        
        let dstHost = decision.host

        requestLog.record(
            protocol: .tcp,
            host: dstHost,
            port: dstPort,
            routeTarget: routeTarget,
            viaDefault: decision.viaDefault,
            ruleSetName: ruleSetName
        )
        
        var sniffSNI = !decision.hostIsResolvedDomain
        if mitmEnabled && mitmPolicy.matches(dstHost) {
            sniffSNI = true
        }

        return TCPConnection(
            stack: self,
            pcb: LWIPPCBHandle(raw: pcb),
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
    
    func admitSYN(rawIP: Bool) -> Int32 {
        let load = FlowGauge.admissionLoad
        let watermark = rawIP ? TunnelLimits.flowPressureWatermark : TunnelLimits.flowBudget
        if load < watermark {
            if flowShedWarned, load < TunnelLimits.flowPressureWatermark {
                flowShedWarned = false
                logger.info("[TCP] flow budget recovered; admitting SYNs")
            }
            return Int32(LWIP_BRIDGE_SYN_PASS)
        }
        if !flowShedWarned {
            flowShedWarned = true
            logger.warning("[TCP] flow budget exhausted; dropping new SYNs")
        }
        return Int32(LWIP_BRIDGE_SYN_DROP)
    }
}
